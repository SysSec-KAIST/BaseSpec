import os
import string
import re
import pickle

import idc
import ida_ua
import ida_segment
import ida_bytes

STR_CHARS = string.ascii_letters + string.digits + "_ "
STR_CHARS = STR_CHARS.encode()
STR_COMMENT_CHARS = string.ascii_letters + string.punctuation + string.digits + " \t\n"
STR_COMMENT_CHARS = STR_COMMENT_CHARS.encode()
FUNCNAME_CHARS = string.ascii_letters + "_" + string.digits
FUNCNAME_CHARS = FUNCNAME_CHARS.encode()

def create_string(ea, length=idc.BADADDR):
    s = get_string(ea, length)
    if s:
        idc.create_strlit(ea, ea + len(s))

    return s

# ida's get_strlit_contents filters 0x1d, 0x9, 0x6, etc.
def get_string(ea, length=idc.BADADDR):
    end_ea = ea + length
    ret = []

    while ea < end_ea:
        # break if current ea is already assigned
        if not idc.is_loaded(ea):
            break

        byte = ida_bytes.get_byte(ea)
        if byte == 0:  # NULL terminate
            break

        ret.append(byte)
        ea += 1

    return bytes(ret)

def check_string(ea, length=idc.BADADDR):
    global STR_CHARS, STR_COMMENT_CHARS

    if isinstance(ea, int):
        s = get_string(ea, length)
    elif isinstance(ea, str):
        s = ea.encode()
    elif isinstance(ea, bytes):
        s = ea

    if not s:
        return False

    # strict limit
    if len(s) < 4:
        return False

    #    # possible strings
    #    if len(s) < 10:
    #        if any(ch not in STR_CHARS for ch in s):
    #            return False

    # highly likely comments

    if any(ch not in STR_COMMENT_CHARS for ch in s):
        return False

    return True


def check_funcname(data_ptr, length=idc.BADADDR):
    global FUNCNAME_CHARS

    if isinstance(data_ptr, int):
        s = get_string(data_ptr, length)
    elif isinstance(data_ptr, str):
        s = data_ptr.encode()
    elif isinstance(data_ptr, bytes):
        s = data_ptr
    else:
        raise Exception

    if not s:
        return False

    if len(s) < 8:
        return False

    # function name would be less than 30 characters.
    if len(s) > 30:
        return False

    if s.upper() == s:
        return False

    if any(ch not in FUNCNAME_CHARS for ch in s):
        return False

    # TODO: add other func name checks
    return True


# deprecated.
def set_funcname(ea, name):
    func_addr = idc.get_func_attr(ea, idc.FUNCATTR_START)
    if func_addr == idc.BADADDR:
        return
    return set_entry_name(func_addr, name)


def set_entry_name(ea, name):
    cur_name = idc.get_name(ea)
    if cur_name.startswith(name):
        return cur_name

    name = check_name(name)
    status = idc.set_name(ea, name)
    if status:
        return name
    else:
        return


def is_name_exist(name):
    addr = idc.get_name_ea_simple(name)
    # if name already exists, we need to assign new name with suffix
    if addr != idc.BADADDR:
        return True
    else:
        return False


def check_name(orig_name):
    name = orig_name
    idx = 1
    while is_name_exist(name):
        name = "%s_%d" % (orig_name, idx)
        idx += 1

    return name

def is_func(ea):
    if ea == idc.BADADDR:
        return False

    start_ea = idc.get_func_attr(ea, idc.FUNCATTR_START)
    end_ea = idc.get_func_attr(ea, idc.FUNCATTR_END)

    return start_ea <= ea < end_ea


def is_thumb(ea):
    return idc.get_sreg(ea, "T") == 1

