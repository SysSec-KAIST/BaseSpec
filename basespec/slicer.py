import idc
import idautils
import idaapi

import ida_bytes
import ida_ua
import ida_funcs
import ida_idp
import ida_xref
import ida_segment

import re

from .utils import is_thumb


def get_reg(op):
    return ida_idp.get_reg_name(op.reg, 0)


def get_regs(ea):
    if is_thumb(ea):
        # 1  --- 1 (LSB)
        # R7 --- R0
        reg_bits = ida_bytes.get_word(ea) & 0x1FF
        reg_list = ["R{0}".format(idx) for idx in range(8)]
        reg_list.append("LR")
        # reg_list.extend(['SP', 'LR'])
        # TODO: add 32 bit Thumb handling
    else:
        # 1   --- 1 (LSB)
        # R12 --- R0
        reg_bits = ida_bytes.get_word(ea) & 0xFFFF
        reg_list = ["R{0}".format(idx) for idx in range(13)]
        reg_list.extend(["SP", "LR", "PC"])

    regs = []
    idx = 0
    while reg_bits:
        if reg_bits & 0x1:
            regs.append(reg_list[idx])
        reg_bits = reg_bits >> 1
        idx += 1

    return regs


def merge_op_vals(val1, val2, operator):
    values = set()
    for x in val1:
        for y in val2:
            values.add(operator(x, y))

    return values


class SimpleForwardSlicer(object):
    def __init__(self):
        self.visited = set()
        self.values = dict()
        self.inter = False
        self.init()

    def init(self):
        self.memory = dict()
        self.regs = dict()
        self.func_start = None

        # initialize stack
        self.regs["SP"] = 0x100000000

    def run(self, start_ea, end_ea=idc.BADADDR, end_cnt=100):
        self.init()

        # not in code segment
        ea = start_ea

        func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        if func_start == idc.BADADDR:
            return

        self.func_start = func_start

        cnt = 0
        while True:
            if ea in self.visited:
                break

            self.visited.add(ea)
            # break if ea is out of the original function
            # TODO: Add inter-procedural
            if idc.get_func_attr(ea, idc.FUNCATTR_START) != func_start:
                break

            if ea == end_ea:
                break

            if end_ea == idc.BADADDR and cnt >= end_cnt:
                break

            # there may exist data section
            mnem = ida_ua.ua_mnem(ea)
            if not ida_ua.can_decode(ea) or not mnem:
                break

            if mnem.startswith("B"):
                ea = idc.get_operand_value(ea, 0)

            elif mnem.startswith("POP"):
                break

            else:
                if not self.run_helper(ea):
                    # print("%x: something wrong: %s" % (ea, idc.GetDisasm(ea)))
                    break

                ea = ida_xref.get_first_cref_from(ea)

            cnt += 1

    def fetch_value(self, op1, op2, op3, op4, operator=None):
        value = None
        value2 = None
        value3 = None
        value4 = None

        # fetch register value
        if op2.type == ida_ua.o_reg:
            if get_reg(op2) not in self.regs:
                return

            value = self.regs[get_reg(op2)]

            # More than two arguments
            if op3 and op3.type != ida_ua.o_void:
                # ADD R0, R1, R2
                if op3.type == ida_ua.o_reg:
                    if get_reg(op3) not in self.regs:
                        return

                    value3 = self.regs[get_reg(op3)]

                # immediate value, we get the value right away
                # ADD R0, R1, #123
                elif op3.type == ida_ua.o_imm:
                    value3 = op3.value

                # o_idaspec0-5
                # ADD R0, R1, R2,LSL#2
                # processor specific type 'LSL'
                elif op3.type == ida_ua.o_idpspec0:
                    if get_reg(op3) not in self.regs:
                        return

                    value3 = self.regs[get_reg(op3)] << op3.value

                else:
                    # TODO: currently not implemented
                    # print("unknown operand type: %d" % (op3.type))
                    # raise NotImplemented
                    return

                # Handle arithmetic operator
                assert operator is not None
                assert value3 is not None
                value = operator(value, value3) & 0xFFFFFFFF

            # MLA R0, R1, R2, R3
            if op4 and op4.type != ida_ua.o_void:
                if op4.type == ida_ua.o_reg:
                    if get_reg(op4) not in self.regs:
                        return

                    value4 = self.regs[get_reg(op4)]

                # Handle arithmetic operator
                assert operator is not None
                assert value3 is not None
                value = operator(value, value4) & 0xFFFFFFFF

        # in the stack.
        # o_displ = [Base Reg + Displacement]
        elif op2.type == ida_ua.o_displ:
            if get_reg(op2) not in self.regs:
                return

            value = self.regs[get_reg(op2)] + op2.addr

        # reference the memory and get the value written in the memory
        elif op2.type == ida_ua.o_mem:
            value = op2.addr

        # immediate value, we get the value right away
        elif op2.type == ida_ua.o_imm:
            value = op2.value

        # o_phrase = [Base Reg + Index Reg + Displacement]
        elif op2.type == ida_ua.o_phrase:
            assert op3 is not None

            if get_reg(op3) not in self.regs:
                return

            if get_reg(op2) not in self.regs:
                return

            value2 = self.regs[get_reg(op2)]
            value3 = self.regs[get_reg(op3)]
            value = value2 + value3 + op2.phrase

        return value

    def run_helper(self, ea):
        # there may exist data section
        mnem = ida_ua.ua_mnem(ea)
        if not ida_ua.can_decode(ea) or not mnem:
            return

        # we need to check at most 4 operands
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, ea)
        op1 = insn.ops[0]
        op2 = insn.ops[1]
        op3 = insn.ops[2]
        op4 = insn.ops[3]

        if any(mnem.startswith(word) for word in ["PUSH", "POP"]):
            # TODO: implement this properly
            return True

        elif any(
            mnem.startswith(word)
            for word in ["MOV", "LDR", "ADR", "STR", "ADD", "SUB", "MUL"]
        ):
            assert op2 is not None

            if mnem.startswith("ADD"):
                operator = lambda x1, x2: x1 + x2
            elif mnem.startswith("SUB"):
                operator = lambda x1, x2: x1 - x2
            elif mnem.startswith("MUL"):
                operator = lambda x1, x2: x1 * x2
            else:
                operator = None

            value = self.fetch_value(op1, op2, op3, op4, operator)
            if value is None:
                return

            value = value & 0xFFFFFFFF

            if mnem.startswith("MOV"):
                self.regs[get_reg(op1)] = value

            elif mnem.startswith("LDR") or mnem.startswith("ADR"):
                if mnem.startswith("LDR"):
                    assert op2.type in [ida_ua.o_displ, ida_ua.o_mem, ida_ua.o_phrase]

                    if value in self.memory:
                        value = self.memory[value]

                    else:
                        seg = ida_segment.getseg(value)
                        if seg == idc.BADADDR:
                            return

                        value = ida_bytes.get_dword(value)

                elif mnem.startswith("ADR"):
                    assert op2.type == ida_ua.o_imm

                self.regs[get_reg(op1)] = value

            elif mnem.startswith("STR"):
                assert op2.type in [ida_ua.o_displ, ida_ua.o_mem, ida_ua.o_phrase]
                if get_reg(op1) not in self.regs:
                    return

                self.memory[value] = self.regs[get_reg(op1)]

            elif any(mnem.startswith(word) for word in ["ADD", "SUB", "MUL"]):
                if op2.type == ida_ua.o_imm:
                    if get_reg(op1) not in self.regs:
                        return

                    value = operator(self.regs[get_reg(op1)], value)

                self.regs[get_reg(op1)] = value

            return True

        else:
            # Skip unknown instructions
            return True

        # This should not be reached.
        print(hex(ea), idc.GetDisasm(ea))
        assert False


class SimpleBackwardSlicer(object):
    def __init__(self):
        self.visited = set()
        self.values = dict()
        self.memory = dict()
        self.stack = dict()
        self.func_start = None
        self.inter = False

    def find_reg_value(
        self, ea, reg_name, end_ea=idc.BADADDR, inter=False, end_cnt=100
    ):
        # not in code segment
        func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
        if func_start == idc.BADADDR:
            return

        self.func_start = func_start
        self.inter = inter

        return self.find_reg_value_helper(ea, reg_name, end_ea, end_cnt)

    def find_reg_value_helper(self, ea, reg_name, end_ea, end_cnt, offset=None):
        if (ea, reg_name) in self.values:
            return self.values[(ea, reg_name)]

        if end_ea != idc.BADADDR and ea < end_ea:
            return

        if end_cnt == 0:
            return

        # not in code segment
        func_addr = idc.get_func_attr(ea, idc.FUNCATTR_START)
        if func_addr == idc.BADADDR:
            return

        # out of current function
        if not self.inter and func_addr != self.func_start:
            return

        # there may exist data section
        mnem = ida_ua.ua_mnem(ea)
        if not ida_ua.can_decode(ea) or not mnem:
            return

        # we need to check at most 4 operands
        insn = ida_ua.insn_t()
        inslen = ida_ua.decode_insn(insn, ea)
        op1 = insn.ops[0]
        op2 = insn.ops[1]
        op3 = insn.ops[2]
        op4 = insn.ops[3]

        if any(mnem.startswith(word) for word in ["MOV", "LDR"]):
            assert op2 is not None

            # first argument should be reg_name
            if get_reg(op1) != reg_name:
                return self.proceed_backward(ea, reg_name, end_ea, end_cnt - 1, offset)

            # follow new register
            if op2.type == ida_ua.o_reg:
                if get_reg(op2) == "SP":
                    offset = 0
                return self.proceed_backward(
                    ea, get_reg(op2), end_ea, end_cnt - 1, offset
                )

            # in the stack. need to check when the value is stored
            # o_displ = [Base Reg + Index Reg + Displacement]
            elif op2.type == ida_ua.o_displ:
                values = self.proceed_backward(
                    ea, get_reg(op2), end_ea, end_cnt - 1, op2.addr
                )
                values = set(filter(lambda x: x, values))
                if mnem.startswith("LDR"):
                    return set(map(lambda x: ida_bytes.get_dword(x), values))
                else:
                    return values

            # reference the memory and get the value written in the memory
            elif op2.type == ida_ua.o_mem:
                # TODO: implement memory access

                # we assume that this memory is not initialized.
                if mnem.startswith("LDR"):
                    return set([ida_bytes.get_dword(op2.addr)])
                else:
                    return set([op2.addr])

            # immediate value, we get the value right away
            elif op2.type == ida_ua.o_imm:
                return set([op2.value])

            elif op2.type == ida_ua.o_phrase:
                assert mnem.startswith("LDR")

                phrase_val = self.proceed_backward(
                    ea, get_reg(op3), end_ea, end_cnt - 1, offset
                )
                if not phrase_val:
                    return

                op2_val = self.proceed_backward(
                    ea, get_reg(op2), end_ea, end_cnt - 1, offset
                )
                if not op2_val:
                    return

                operator = lambda x1, x2: x1 + x2
                values = merge_op_vals(op2_val, phrase_val, operator)

                return set(map(lambda x: ida_bytes.get_dword(x + op2.phrase), values))

            return

        # only checks stored stacks
        elif any(mnem.startswith(word) for word in ["STR"]):
            assert op2 is not None

            if op3 and op3.type != ida_ua.o_void:
                target_op = op3
            else:
                target_op = op2

            # arguments should include reg_name
            if get_reg(target_op) != reg_name:
                return self.proceed_backward(ea, reg_name, end_ea, end_cnt - 1, offset)

            # in the stack. need to check when the value is stored
            # o_displ = [Base Reg + Index Reg + Displacement]
            if target_op.type == ida_ua.o_displ:
                target_memory = self.stack

            # we assume that memory is not initialized.
            # reference the memory and get the value written in the memory
            elif target_op.type == ida_ua.o_mem:
                assert get_reg(target_op) != "SP"
                target_memory = self.memory

            else:
                return

            if target_op == op2:
                if target_op.addr == offset:
                    self.stack[target_op.addr] = self.proceed_backward(
                        ea, get_reg(op1), end_ea, end_cnt - 1
                    )
                    return self.stack[target_op.addr]
            else:
                if target_op.addr == offset:
                    self.stack[target_op.addr] = self.proceed_backward(
                        ea, get_reg(op1), end_ea, end_cnt - 1
                    )
                    return self.stack[target_op.addr]
                elif target_op.addr + 4 == offset:
                    self.stack[target_op.addr + 4] = self.proceed_backward(
                        ea, get_reg(op2), end_ea, end_cnt - 1
                    )
                    return self.stack[target_op.addr + 4]

            return self.proceed_backward(ea, reg_name, end_ea, end_cnt - 1, offset)

        elif any(mnem.startswith(word) for word in ["ADD", "SUB", "MUL"]):
            assert op2 is not None

            if mnem.startswith("ADD"):
                operator = lambda x1, x2: x1 + x2
            elif mnem.startswith("SUB"):
                operator = lambda x1, x2: x1 - x2
            elif mnem.startswith("MUL"):
                operator = lambda x1, x2: x1 * x2

            # TODO: Handle stack variable
            # Check how to follow below.
            # STR R5, [SP #8]
            # STR R4, [SP #4]
            # ADD R3, SP, #4
            # ADD R2, R3, #4
            if get_reg(op1) != reg_name:
                return self.proceed_backward(ea, reg_name, end_ea, end_cnt - 1, offset)

            # Two arguments
            if not op3 or op3.type == ida_ua.o_void:
                if op2.type == ida_ua.o_reg:
                    op1_val = self.proceed_backward(
                        ea, reg_name, end_ea, end_cnt - 1, offset
                    )
                    if not op1_val:
                        return

                    op2_val = self.proceed_backward(
                        ea, get_reg(op2), end_ea, end_cnt - 1
                    )
                    if not op2_val:
                        return

                    return merge_op_vals(op1_val, op2_val, operator)

                elif op2.type == ida_ua.o_imm:
                    op1_val = self.proceed_backward(
                        ea, reg_name, end_ea, end_cnt - 1, offset
                    )
                    return set(map(lambda x: operator(x, op2.value), op1_val))

                else:
                    return

            if op2.type != ida_ua.o_reg:
                # This should not be reached.
                print(hex(ea), idc.GetDisasm(ea), reg_name, op2.type)
                assert False

            # More than three arguments
            # follow new register
            # ADD R0, R1, R2
            if op3.type == ida_ua.o_reg:
                op2_val = self.proceed_backward(
                    ea, get_reg(op2), end_ea, end_cnt - 1, offset
                )
                # if we cannot fetch the value, stop the analysis
                if not op2_val:
                    return

                op3_val = self.proceed_backward(
                    ea, get_reg(op3), end_ea, end_cnt - 1, offset
                )
                # if we cannot fetch the value, stop the analysis
                if not op3_val:
                    return

                # MLA R0, R1, R2, R3
                if op4 and op4.type == ida_ua.o_reg:
                    op4_val = self.proceed_backward(
                        ea, get_reg(op4), end_ea, end_cnt - 1, offset
                    )
                    if not op4_val:
                        return

                    return merge_op_vals(
                        merge_op_vals(op2_val, op3_val, operator), op4_val, operator
                    )

                return merge_op_vals(op2_val, op3_val, operator)

            # immediate value, we get the value right away
            # ADD R0, R1, #123
            elif op3.type == ida_ua.o_imm:
                return self.proceed_backward(
                    ea, get_reg(op2), end_ea, end_cnt - 1, operator(0, op3.value)
                )

            # ADD R0, R1, R2,LSL#2
            # o_idaspec0~5
            elif op3.type == ida_ua.o_idpspec0:
                # processor specific type 'LSL'
                op3_val = self.proceed_backward(
                    ea, get_reg(op3), end_ea, end_cnt - 1, offset
                )
                # if we cannot fetch the value, stop the analysis
                if not op3_val:
                    return
                op3_val = set(map(lambda x: x << op3.value, op3_val))
                op2_val = self.proceed_backward(
                    ea, get_reg(op2), end_ea, end_cnt - 1, offset
                )

                return merge_op_vals(op2_val, op3_val, operator)

            else:
                return

        else:
            return self.proceed_backward(ea, reg_name, end_ea, end_cnt - 1, offset)

    def proceed_backward(self, ea, reg_name, end_ea, end_cnt, offset=None):
        # initialize prev code points
        values = set()
        xref = ida_xref.get_first_cref_to(ea)
        while xref and xref != idc.BADADDR:
            tmp_values = self.find_reg_value_helper(
                xref, reg_name, end_ea, end_cnt, offset
            )
            if tmp_values:
                tmp_values = list(map(lambda x: x & 0xFFFFFFFF, tmp_values))
                values.update(tmp_values)

            xref = ida_xref.get_next_cref_to(ea, xref)

        self.values[(ea, reg_name)] = values

        return values


def find_mnem(target_ea, target_mnem, backward=False, threshold=0x100):
    assert target_ea is not None
    ea = target_ea
    addr = None
    visited = set()
    while True:
        mnem = ida_ua.ua_mnem(ea)
        if not ida_ua.can_decode(ea) or not mnem:
            break
        if mnem == target_mnem:
            addr = ea
            break

        visited.add(ea)

        if backward:
            next_ea = ida_xref.get_first_cref_to(ea)
            if next_ea < target_ea - 0x100:
                break

            while next_ea != idc.BADADDR and next_ea in visited:
                next_ea = ida_xref.get_next_cref_to(ea, next_ea)

        else:
            next_ea = ida_xref.get_first_cref_from(ea)
            if next_ea > target_ea + 0x100:
                break

            while next_ea != idc.BADADDR and next_ea in visited:
                next_ea = ida_xref.get_next_cref_from(ea, next_ea)

        ea = next_ea

    return addr


def fetch_arg_one(ea, reg_name, end_ea=idc.BADADDR, end_cnt=100):
    slicer = SimpleBackwardSlicer()
    values = slicer.find_reg_value(ea, reg_name, end_ea=end_ea, end_cnt=end_cnt)
    if not values:
        return idc.BADADDR

    return values.pop()


def find_args(ea, num_regs, limit=10):
    registers = ["R%d" % (i) for i in range(num_regs)]
    return [fetch_arg_one(ea, reg, end_cnt=limit) for reg in registers]
