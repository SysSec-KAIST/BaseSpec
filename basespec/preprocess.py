import time
import pickle

import idc
import idaapi
import idautils

import ida_funcs
import ida_auto
import ida_bytes
import ida_offset
import ida_segment

from idautils import XrefsTo

from .utils import get_string, check_string, create_string
from .utils import check_funcname, set_funcname


def next_addr_aligned(ea, align=2, end_ea=idc.BADADDR):
    ea = ida_bytes.next_inited(ea, end_ea)
    while ea % align != 0:
        ea = ida_bytes.next_inited(ea, end_ea)

    return ea


def prev_addr_aligned(ea, align=2, end_ea=0):
    ea = ida_bytes.prev_inited(ea, 0)
    while ea % align != 0:
        ea = ida_bytes.prev_inited(ea, 0)

    return ea


def is_assigned(ea):
    func_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
    # check if function is already assigned
    if func_end != idc.BADADDR:
        # sometimes, ida returns wrong addr
        if func_end > ea:
            ea = func_end
        else:
            ea = next_addr_aligned(ea, 4)

        return True, ea

    # check if string is already assigned
    if idc.get_str_type(ea) is not None:
        item_end = idc.get_item_end(ea)
        # sometimes, ida returns wrong addr
        if item_end > ea:
            ea = item_end
        else:
            ea = next_addr_aligned(ea, 4)

        return True, ea

    return False, ea


string_initialized = False


def init_strings(force=False, target_seg_name=None):
    global string_initialized
    if not force and string_initialized:
        return

    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        seg_name = ida_segment.get_segm_name(seg)

        # We only check target segment since it may take too much time.
        if target_seg_name and seg_name == target_seg_name:
            continue

        print("Initializing %x -> %x (%s)" % (seg.start_ea, seg.end_ea, seg_name))

        # TODO: we may use other strategy to find string pointers
        analyze_str_ptr(seg.start_ea, seg.end_ea)

    analyze_ida_str()
    string_initialized = True


def analyze_str_ptr(start_ea, end_ea):
    str_cnt = 0
    start_time = time.time()

    # First, find string references. strings referenced by pointers are highly
    # likely string.
    ea = start_ea
    while ea != idc.BADADDR and ea < end_ea:
        status, ea = is_assigned(ea)
        if status:
            continue

        str_ptr = ida_bytes.get_dword(ea)
        if idc.get_str_type(str_ptr) is not None or check_string(str_ptr, 8):
            # even already assigned strings may not have reference.
            ida_offset.op_offset(ea, 0, idc.REF_OFF32)

            if idc.get_str_type(str_ptr) is None:
                create_string(str_ptr)

            str_cnt += 1
            if str_cnt % 10000 == 0:
                print(
                    "%x: %d strings has been found. (%0.3f secs)"
                    % (ea, str_cnt, time.time() - start_time)
                )

        ea = next_addr_aligned(ea, 4)

    print("Created %d strings. (%0.3f secs)" % (str_cnt, time.time() - start_time))


def analyze_ida_str():
    global all_str
    if "all_str" not in globals():
        all_str = idautils.Strings()

    str_cnt = 0
    start_time = time.time()

    for s in all_str:
        # check if there exists already assigned function or string
        if any(
            ida_funcs.get_fchunk(ea) or (idc.get_str_type(ea) is not None)
            for ea in (s.ea, s.ea + s.length)
        ):
            continue

        if check_string(30) and create_string(s.ea):
            str_cnt += 1
            if str_cnt % 1000 == 0:
                print(
                    "%x: %d strings has been found. (%0.3f secs)"
                    % (s.ea, str_cnt, time.time() - start_time)
                )

    print("Created %d strings. (%0.3f secs)" % (str_cnt, time.time() - start_time))


NONE = 0
ARM = 1
THUMB = 2


def is_valid_reglist(word, is_16bit=False):
    if is_16bit:
        word = word & 0x1FF
        # should contain LR
        lr = word >> 8 & 1
        if lr != 1:
            return False

        regs = word

    else:
        # should contain LR
        # should not contain SP, PC
        sp = word >> 13 & 1
        lr = word >> 14 & 1
        pc = word >> 15 & 1
        if sp != 0 or lr != 1 or pc != 0:
            return False

        regs = word & 0x1FFF

    # At least one reg should exist
    if regs == 0:
        return False

    # We compute maximum consequtive 1s to find continuous reg-list like
    # '0001111100000'.
    if is_16bit:
        threshold = 0
    else:
        threshold = 1

    cnt = 0
    while regs != 0:
        regs = regs & (regs << 1)
        cnt += 1

    if cnt > threshold:
        return True
    else:
        return False


# This function only checks PUSH instruction.
# TODO: properly find function prolog (e.g, using ML?)
def is_func_prolog(ea, reg_check=True):
    if ea % 2 != 0:
        return NONE

    # function prolog requires at least four bytes
    if any(not ida_bytes.is_mapped(ea + i) for i in range(4)):
        return NONE

    word = ida_bytes.get_word(ea)
    next_word = ida_bytes.get_word(ea + 2)

    # check thumb PUSH.W
    if word == 0xE92D:
        # PUSH LR
        if not reg_check or is_valid_reglist(next_word, False):
            return THUMB

    # check thumb PUSH
    elif (word >> 8) == 0xB5:
        if not reg_check or is_valid_reglist(word, True):
            return THUMB

    # check arm PUSH
    elif next_word == 0xE92D:
        if ea % 4 == 0:
            # PUSH LR
            if not reg_check or is_valid_reglist(word, False):
                return ARM

    return NONE


# This function finds function candidates.  Currently, we only find the
# candidates by prolog.
def find_prev_func_cand(ea, end_ea=idc.BADADDR):
    while ea < end_ea and ea != idc.BADADDR:
        mode = is_func_prolog(ea, reg_check=False)
        if mode != NONE:
            # check if the function is already assigned. If current function
            # has found, we cannot just set ea to the function end since IDA
            # may fail to find the function end corrently.
            if idc.get_func_attr(ea, idc.FUNCATTR_START) == idc.BADADDR:
                return ea, mode

        ea = prev_addr_aligned(ea)

    return idc.BADADDR, NONE


# This function finds function candidates.  Currently, we only find the
# candidates by prolog.
def find_next_func_cand(ea, end_ea=idc.BADADDR):
    while ea < end_ea and ea != idc.BADADDR:
        mode = is_func_prolog(ea)
        if mode != NONE:
            # check if the function is already assigned. If current function
            # has found, we cannot just set ea to the function end since IDA
            # may fail to find the function end corrently.
            if idc.get_func_attr(ea, idc.FUNCATTR_START) == idc.BADADDR:
                return ea, mode

        ea = next_addr_aligned(ea)

    return idc.BADADDR, NONE


def fix_func_prolog(ea, end_ea=idc.BADADDR):
    global FUNC_BY_LS

    func_cnt = 0
    func = ida_funcs.get_fchunk(ea)
    if func is None:
        func = ida_funcs.get_next_func(ea)
    ea = func.start_ea

    while func is not None and ea < end_ea:
        # if current function is small enough and there exists a function right
        # next to current function
        if (
            func.size() <= 8
            and idc.get_func_attr(func.end_ea, idc.FUNCATTR_START) != idc.BADADDR
        ):
            # If the next function can be connected, there must be a basic block reference.
            # xref.type == 21 means 'fl_F', which is an ordinary flow.
            if all(
                (func.start_ea <= xref.frm < func.end_ea) and xref.type == 21
                for xref in XrefsTo(func.end_ea)
            ):
                if func_cnt > 0 and func_cnt % 1000 == 0:
                    print(
                        "%x <- %x: prolog merging (%d)."
                        % (func.start_ea, func.end_ea, func_cnt)
                    )
                ida_bytes.del_items(func.end_ea, ida_bytes.DELIT_EXPAND)
                ida_bytes.del_items(func.start_ea, ida_bytes.DELIT_EXPAND)
                ida_auto.auto_wait()

                status = idc.add_func(func.start_ea)
                if not status:
                    print("Error merging 0x%x <- 0x%x" % (func.start_ea, func.end_ea))
                else:
                    func_cnt += 1
                    FUNC_BY_LS.discard(func.end_ea)
                ida_auto.auto_wait()

        func = ida_funcs.get_next_func(ea)
        if func:
            ea = func.start_ea

    print("Fixed %d functions" % func_cnt)


FUNC_BY_LS = set()
FUNC_BY_LS_TIME = None


def analyze_linear_sweep(start_ea, end_ea=idc.BADADDR):
    global FUNC_BY_LS, FUNC_BY_LS_TIME
    if "FUNC_BY_LS" not in globals() or len(FUNC_BY_LS) == 0:
        FUNC_BY_LS = set()

    cand_cnt = 0
    func_cnt = 0
    ea = start_ea
    start_time = time.time()
    while ea < end_ea and ea != idc.BADADDR:
        ea, mode = find_next_func_cand(ea, end_ea)
        if ea == idc.BADADDR:
            break

        cand_cnt += 1
        if cand_cnt % 10000 == 0:
            print(
                "%x: %d/%d function has been found (%d secs)"
                % (ea, func_cnt, cand_cnt, time.time() - start_time)
            )

        # set IDA segment register to specify ARM mode
        old_flag = idc.get_sreg(ea, "T")
        if mode == THUMB:
            idc.split_sreg_range(ea, "T", 1, idc.SR_user)
        elif mode == ARM:
            idc.split_sreg_range(ea, "T", 0, idc.SR_user)
        else:
            print("Unknown mode")
            raise NotImplemented

        # add_func ignores the existing function, but existing function is
        # already filtered when finding the candidate
        status = idc.add_func(ea)
        if status:
            func_cnt += 1
            FUNC_BY_LS.add(ea)

            # Wait IDA's auto analysis
            ida_auto.auto_wait()

            # even though add_func succeed, it may not be correct.
            # TODO: how to check the correctness? we may check the function end?
            func_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
            if func_end > ea:
                ea = func_end
            else:
                # sometimes, ida returns wrong addr
                ea = next_addr_aligned(ea)

        else:
            if idc.get_func_attr(ea, idc.FUNCATTR_START) == idc.BADADDR:
                # IDA automatically make code, and this remains even though
                # add_func fails.
                ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND)

                # reset IDA segment register to previous ARM mode
                idc.split_sreg_range(ea, "T", old_flag, idc.SR_user)

                # Wait IDA's auto analysis
                ida_auto.auto_wait()

            ea = next_addr_aligned(ea)

    # linear sweep may choose wrong prologs. We merge the prologs of two
    # adjacent functions.
    if func_cnt > 0:
        fix_func_prolog(start_ea, end_ea)

    FUNC_BY_LS_TIME = time.time() - start_time
    print(
        "Found %d/%d functions. (%d sec)" % (len(FUNC_BY_LS), cand_cnt, FUNC_BY_LS_TIME)
    )


# TODO: find other functions by other pointer analysis
# Please check analyze_func_ptrs function at the below
FUNC_BY_PTR = set()
FUNC_BY_PTR_TIME = None


def analyze_func_ptr(start_ea, end_ea):
    global FUNC_BY_PTR, FUNC_BY_PTR_TIME
    if "FUNC_BY_PTR" not in globals() or len(FUNC_BY_PTR) == 0:
        FUNC_BY_PTR = set()

    ea = start_ea
    func_cnt = 0
    name_cnt = 0
    start_time = time.time()

    while ea != idc.BADADDR and ea <= end_ea:
        status, ea = is_assigned(ea)
        if status:
            continue

        # now check function pointer
        func_ptr = ida_bytes.get_dword(ea)

        # TODO: skip other segments that are not code.

        # for those already assigned functions, we need to check the segment range.
        if not (start_ea <= func_ptr < end_ea):
            ea = next_addr_aligned(ea, 4)
            continue

        # we only target thumb function to reduce false positives
        if func_ptr & 1 == 0:
            ea = next_addr_aligned(ea, 4)
            continue

        func_ptr = func_ptr - 1
        func_start = idc.get_func_attr(func_ptr, idc.FUNCATTR_START)
        if func_start != idc.BADADDR and func_start != func_ptr:
            # this is not a proper function pointer
            ea = next_addr_aligned(ea, 4)
            continue

        # new thumb function has been found!
        if func_start == idc.BADADDR:
            old_flag = idc.get_sreg(func_ptr, "T")
            idc.split_sreg_range(func_ptr, "T", 1, idc.SR_user)
            status = idc.add_func(func_ptr)
            if not status:
                # IDA automatically make code, and this remains even
                # though add_func fails.
                ida_bytes.del_items(func_ptr, ida_bytes.DELIT_EXPAND)
                idc.split_sreg_range(func_ptr, "T", old_flag, idc.SR_user)

                ea = next_addr_aligned(ea, 4)
                continue

            func_cnt += 1
            FUNC_BY_PTR.add(ea)
            if func_cnt % 10000 == 0:
                print(
                    "%x: %d functions has been found. (%0.3f secs)"
                    % (ea, func_cnt, time.time() - start_time)
                )

        # If we find a function, we try to assign a name. The name may be
        # derived by C++ structure.
        if analyze_funcname(ea, func_ptr):
            name_cnt += 1
            func_name = idc.get_func_name(func_ptr)
            if name_cnt % 10000 == 0:
                print(
                    "%x: %d names has been found. (%0.3f secs)"
                    % (ea, name_cnt, time.time() - start_time)
                )
            # print("%x: %x => %s" % (ea, func_ptr, func_name))

        ea = next_addr_aligned(ea, 4)

    FUNC_BY_PTR_TIME = time.time() - start_time
    print(
        "Found %d functions, renamed %d functions (%0.3f secs)"
        % (len(FUNC_BY_PTR), name_cnt, FUNC_BY_PTR_TIME)
    )


# TODO: find the cause of the remaining function names.
def analyze_funcname(ea, func_ptr):
    # check at least 10 items.
    name_pptr = find_funcname_ptr(ea, 10)
    if not name_pptr:
        return False

    ida_offset.op_offset(ea, 0, idc.REF_OFF32)
    ida_offset.op_offset(name_pptr, 0, idc.REF_OFF32)

    func_name = idc.get_func_name(func_ptr)
    if not func_name.startswith("sub_"):
        # already function name has been assigned
        return False

    name_ptr = ida_bytes.get_dword(name_pptr)
    func_name = get_string(name_ptr)
    if isinstance(func_name, bytes):
        func_name = func_name.decode()

    set_funcname(func_ptr, func_name)

    return True


# this function returns first name pointer
def find_funcname_ptr(ea, n):
    for i in range(4, n * 4, 4):
        name_ptr = ida_bytes.get_dword(ea + i)
        # this might be a function, so break and proceed next check
        if name_ptr & 1 == 1:
            return
        elif check_funcname(name_ptr):
            return ea + i
    return


func_initialized = False


def init_functions(force=False, target_seg_name=None):
    global func_initialized
    if not force and func_initialized:
        return

    # Linear sweep to find functions
    for ea in idautils.Segments():
        # TODO: skip other segments that are not code.
        seg = ida_segment.getseg(ea)
        seg_name = ida_segment.get_segm_name(seg)

        # We only check target segment since it may take too much time.
        if target_seg_name and seg_name == target_seg_name:
            continue

        # TODO: we may use other strategy not just sweep linearly.
        print(
            "Linear sweep analysis: %x -> %x (%s)"
            % (seg.start_ea, seg.end_ea, seg_name)
        )
        analyze_linear_sweep(seg.start_ea, seg.end_ea)

    # Find function pointer candidates
    for ea in idautils.Segments():
        # TODO: skip other segments that are not code.
        seg = ida_segment.getseg(ea)
        seg_name = ida_segment.get_segm_name(seg)

        # We only check target segment since it may take too much time.
        if target_seg_name and seg_name == target_seg_name:
            continue

        # Analyze functions by pointers
        print(
            "Function pointer analysis: %x -> %x (%s)"
            % (seg.start_ea, seg.end_ea, seg_name)
        )
        analyze_func_ptr(seg.start_ea, seg.end_ea)

    func_initialized = True
