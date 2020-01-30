import idc
import ida_bytes
import ida_segment
import ida_search
import ida_offset
import ida_ua
import ida_auto

from idautils import XrefsTo

from .utils import set_entry_name
from .slicer import find_args

# This is the main function
# It finds scatterload related information, and performs scatterloading
def run_scatterload(debug=False):
    # Newly identified region may have additional scatter load procedure. Thus,
    # we continuously proceed until no changes left.
    is_changed = True
    while is_changed:
        is_changed = False
        tables = find_scatter_table()
        scatter_funcs = find_scatter_funcs()

        for start, end in tables.items():
            print("Processing table: 0x%x to 0x%x" % (start, end))
            while start < end:
                ida_bytes.create_dword(start, 16)
                ida_offset.op_offset(start, 0, idc.REF_OFF32)
                src = ida_bytes.get_dword(start)
                dst = ida_bytes.get_dword(start + 4)
                size = ida_bytes.get_dword(start + 8)
                how = ida_bytes.get_dword(start + 12)

                if how not in scatter_funcs:
                    print("%x: no addr 0x%x in scatter_funcs" % (start, how))
                    start += 16
                    continue

                func_name = scatter_funcs[how]
                start += 16
                print("%s: 0x%x -> 0x%x (0x%x bytes)" % (func_name, src, dst, size))

                if func_name != "__scatterload_zeroinit":
                    if not idc.is_loaded(src) or size == 0:
                        print("0x%x is not loaded." % (src))
                        continue

                if debug:
                    # only show information above
                    continue

                if func_name == "__scatterload_copy":
                    if add_segment(dst, size, "CODE"):
                        memcpy(src, dst, size)
                        is_changed = True
                elif func_name == "__scatterload_decompress":
                    if add_segment(dst, size, "DATA"):
                        decomp(src, dst, size)
                        is_changed = True
                # some old firmware images have this.
                elif func_name == "__scatterload_decompress2":
                    if add_segment(dst, size, "DATA"):
                        decomp2(src, dst, size)
                        is_changed = True
                elif func_name == "__scatterload_zeroinit":
                    # No need to further proceed for zero init.
                    if add_segment(dst, size, "DATA"):
                        memclr(dst, size)

                ida_auto.auto_wait()


def add_segment(ea, size, seg_class, debug=False):
    # align page size
    ea = ea & 0xFFFFF000
    end_ea = ea + size
    is_changed = False
    if ea == 0:
        return False
    while ea < end_ea:
        cur_seg = ida_segment.getseg(ea)
        next_seg = ida_segment.get_next_seg(ea)

        if debug:
            print("=" * 30)
            if cur_seg:
                print("cur_seg: %x - %x" % (cur_seg.start_ea, cur_seg.end_ea))
            if next_seg:
                print("next_seg: %x - %x" % (next_seg.start_ea, next_seg.end_ea))
            print("new_seg: %x - %x" % (ea, end_ea))

        # if there is no segment, so create new segment
        if not cur_seg:
            if not next_seg:
                ida_segment.add_segm(0, ea, end_ea, "", seg_class)
                is_changed = True
                break

            # if next_seg exists
            if end_ea <= next_seg.start_ea:
                ida_segment.add_segm(0, ea, end_ea, "", seg_class)
                is_changed = True
                break

            # end_ea > next_seg.start_ea, need to create more segments
            ida_segment.add_segm(0, ea, next_seg.start_ea, "", seg_class)

        # if segment already exists, we extend current segment
        else:
            if end_ea <= cur_seg.end_ea:
                break

            if not next_seg:
                ida_segment.set_segm_end(ea, end_ea, 0)
                ida_segment.set_segm_class(cur_seg, seg_class)
                is_changed = True
                break

            # if next_seg exists
            if end_ea <= next_seg.start_ea:
                ida_segment.set_segm_end(ea, end_ea, 0)
                ida_segment.set_segm_class(cur_seg, seg_class)
                is_changed = True
                break

            # end_ea > next_seg.start_ea, need to create more segments
            if cur_seg.end_ea < next_seg.start_ea:
                ida_segment.set_segm_end(ea, next_seg.start_ea, 0)
                ida_segment.set_segm_class(cur_seg, seg_class)
                is_changed = True

        ea = next_seg.start_ea

    return is_changed


# TODO: search only newly created segments.
def create_func_by_prefix(func_name, prefix, force=False):
    addrs = []
    start_addr = 0
    func_addr = 0
    while func_addr != idc.BADADDR:
        func_addr = ida_search.find_binary(
            start_addr, idc.BADADDR, prefix, 16, idc.SEARCH_DOWN
        )
        if func_addr == idc.BADADDR:
            break

        # already existing function but it is not the right prefix
        addr = idc.get_func_attr(func_addr, idc.FUNCATTR_START)
        if addr != idc.BADADDR and func_addr != addr:
            if not force:
                start_addr = func_addr + 4
                continue

            idc.del_func(addr)
            idc.del_items(func_addr)

        # add_func is not applied to the existing function
        idc.add_func(func_addr)

        func_name = set_entry_name(func_addr, func_name)
        print("%s: 0x%x" % (func_name, func_addr))

        addrs.append(func_addr)
        start_addr = func_addr + 4

    return addrs


def find_scatter_funcs():
    scatter_func_bytes = {
        "__scatterload": [
            "2C 00 8F E2 00 0C 90 E8 00 A0 8A E0 00 B0 8B E0",  # For 5G
            "0A A0 90 E8 00 0C 82 44",
        ],
        "__scatterload_copy": [
            "10 20 52 E2 78 00 B0 28",  # For 5G
            "10 3A 24 BF 78 C8 78 C1 FA D8 52 07",
        ],
        "__scatterload_decompress": [
            "02 20 81 E0 00 C0 A0 E3 01 30 D0 E4",  # For 5G
            "0A 44 10 F8 01 4B 14 F0 0F 05 08 BF 10 F8 01 5B",
            "0A 44 4F F0 00 0C 10 F8 01 3B 13 F0 07 04 08 BF",
        ],
        "__scatterload_decompress2": [
            "10 F8 01 3B 0A 44 13 F0 03 04 08 BF 10 F8 01 4B",
        ],
        "__scatterload_zeroinit": [
            "00 30 B0 E3 00 40 B0 E3 00 50 B0 E3 00 60 B0 E3",  # For 5G
            "00 23 00 24 00 25 00 26 10 3A 28 BF 78 C1 FB D8",
        ],
    }

    funcs = {}
    for name, prefixes in scatter_func_bytes.items():
        for prefix in prefixes:
            addrs = create_func_by_prefix(name, prefix, force=True)
            for addr in addrs:
                if addr != idc.BADADDR:
                    funcs[addr] = name

    return funcs


def find_scatter_table():
    scatter_load_bytes = {
        "__scatterload": [
            "0A A0 90 E8 00 0C 82 44",
            "2C 00 8F E2 00 0C 90 E8 00 A0 8A E0 00 B0 8B E0",  # For 5G
        ],
    }

    tables = {}
    for name, prefixes in scatter_load_bytes.items():
        for prefix in prefixes:
            addrs = create_func_by_prefix(name, prefix, force=True)
            for addr in addrs:
                if addr == idc.BADADDR:
                    continue

                offset_addr = idc.get_operand_value(addr, 1)
                if offset_addr == -1:
                    old_flag = idc.get_sreg(addr, "T")
                    idc.split_sreg_range(addr, "T", not old_flag, idc.SR_user)
                    offset_addr = idc.get_operand_value(addr, 1)

                offset = ida_bytes.get_dword(offset_addr)
                offset2 = ida_bytes.get_dword(offset_addr + 4)
                start = (offset + offset_addr) & 0xFFFFFFFF
                end = (offset2 + offset_addr) & 0xFFFFFFFF
                if not idc.is_loaded(start):
                    continue

                tables[start] = end
                print("__scatter_table: 0x%x -> 0x%x" % (start, end))
                func_name = set_entry_name(start, "__scatter_table")

    return tables


def memcpy(src, dst, length):
    if length == 0:
        return
    data = ida_bytes.get_bytes(src, length)
    ida_bytes.put_bytes(dst, data)


def memclr(dst, length):
    if length == 0:
        return
    data = b"\x00" * length
    ida_bytes.put_bytes(dst, data)


def decomp(src, dst, length):
    # print("decomp 0x%X 0x%X (0x%x)"%(src, dst, length))
    end = dst + length
    while True:
        meta = ida_bytes.get_byte(src)
        src += 1
        l = meta & 7
        if l == 0:
            l = ida_bytes.get_byte(src)
            src += 1
        l2 = meta >> 4
        if l2 == 0:
            l2 = ida_bytes.get_byte(src)
            src += 1
        # print("meta: 0x%x l: 0x%X l2: 0x%x"%(meta,l,l2))
        # copy l byte
        memcpy(src, dst, l - 1)
        src += l - 1
        dst += l - 1
        if meta & 8:
            off = ida_bytes.get_byte(src)
            src += 1
            for i in range(l2 + 2):
                memcpy(dst - off, dst, 1)
                dst += 1
        else:
            memclr(dst, l2)
            dst += l2
        if dst >= end:
            assert dst == end, "Decompress failed"
            # print('decomp end %0x %0x'%(dst, end))
            break


def decomp2(src, dst, length):
    # print("decomp 0x%X 0x%X (0x%x)"%(src, dst, length))
    meta = ida_bytes.get_byte(src)
    src += 1
    end = dst + length
    while True:
        l = meta & 3
        if l == 0:
            l = ida_bytes.get_byte(src)
            src += 1

        l2 = meta >> 4
        if l2 == 0:
            l2 = ida_bytes.get_byte(src)
            src += 1
        # print("meta: 0x%x l: 0x%X l2: 0x%x"%(meta,l,l2))
        # copy l byte
        memcpy(src, dst, l - 1)
        src += l - 1
        dst += l - 1

        if l2:
            off = ida_bytes.get_byte(src)
            src += 1
            meta_val = meta & 0xC
            src_ptr = dst - off
            if meta_val == 12:
                meta_val = ida_bytes.get_byte(src)
                src += 1
                src_ptr -= 256 * meta_val

            else:
                src_ptr -= 64 * meta_val

            l2 += 2
            memcpy(src_ptr, dst, l2)
            dst += l2

        meta = ida_bytes.get_byte(src)
        src += 1

        if dst >= end:
            assert dst == end, "Decompress failed"
            # print('decomp end %0x %0x'%(dst, end))
            break
