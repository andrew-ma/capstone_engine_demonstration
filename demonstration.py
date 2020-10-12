import capstone
from capstone import *
from capstone.x86 import *
import os
import sys
import argparse
from colorama import init
from termcolor import colored
from tabulate import tabulate
from typing import *


def get_eflag_name(eflag) -> Optional[str]:
    if eflag == X86_EFLAGS_UNDEFINED_OF:
        return "UNDEF_OF"
    elif eflag == X86_EFLAGS_UNDEFINED_SF:
        return "UNDEF_SF"
    elif eflag == X86_EFLAGS_UNDEFINED_ZF:
        return "UNDEF_ZF"
    elif eflag == X86_EFLAGS_MODIFY_AF:
        return "MOD_AF"
    elif eflag == X86_EFLAGS_UNDEFINED_PF:
        return "UNDEF_PF"
    elif eflag == X86_EFLAGS_MODIFY_CF:
        return "MOD_CF"
    elif eflag == X86_EFLAGS_MODIFY_SF:
        return "MOD_SF"
    elif eflag == X86_EFLAGS_MODIFY_ZF:
        return "MOD_ZF"
    elif eflag == X86_EFLAGS_UNDEFINED_AF:
        return "UNDEF_AF"
    elif eflag == X86_EFLAGS_MODIFY_PF:
        return "MOD_PF"
    elif eflag == X86_EFLAGS_UNDEFINED_CF:
        return "UNDEF_CF"
    elif eflag == X86_EFLAGS_MODIFY_OF:
        return "MOD_OF"
    elif eflag == X86_EFLAGS_RESET_OF:
        return "RESET_OF"
    elif eflag == X86_EFLAGS_RESET_CF:
        return "RESET_CF"
    elif eflag == X86_EFLAGS_RESET_DF:
        return "RESET_DF"
    elif eflag == X86_EFLAGS_RESET_IF:
        return "RESET_IF"
    elif eflag == X86_EFLAGS_TEST_OF:
        return "TEST_OF"
    elif eflag == X86_EFLAGS_TEST_SF:
        return "TEST_SF"
    elif eflag == X86_EFLAGS_TEST_ZF:
        return "TEST_ZF"
    elif eflag == X86_EFLAGS_TEST_PF:
        return "TEST_PF"
    elif eflag == X86_EFLAGS_TEST_CF:
        return "TEST_CF"
    elif eflag == X86_EFLAGS_RESET_SF:
        return "RESET_SF"
    elif eflag == X86_EFLAGS_RESET_AF:
        return "RESET_AF"
    elif eflag == X86_EFLAGS_RESET_TF:
        return "RESET_TF"
    elif eflag == X86_EFLAGS_RESET_NT:
        return "RESET_NT"
    elif eflag == X86_EFLAGS_PRIOR_OF:
        return "PRIOR_OF"
    elif eflag == X86_EFLAGS_PRIOR_SF:
        return "PRIOR_SF"
    elif eflag == X86_EFLAGS_PRIOR_ZF:
        return "PRIOR_ZF"
    elif eflag == X86_EFLAGS_PRIOR_AF:
        return "PRIOR_AF"
    elif eflag == X86_EFLAGS_PRIOR_PF:
        return "PRIOR_PF"
    elif eflag == X86_EFLAGS_PRIOR_CF:
        return "PRIOR_CF"
    elif eflag == X86_EFLAGS_PRIOR_TF:
        return "PRIOR_TF"
    elif eflag == X86_EFLAGS_PRIOR_IF:
        return "PRIOR_IF"
    elif eflag == X86_EFLAGS_PRIOR_DF:
        return "PRIOR_DF"
    elif eflag == X86_EFLAGS_TEST_NT:
        return "TEST_NT"
    elif eflag == X86_EFLAGS_TEST_DF:
        return "TEST_DF"
    elif eflag == X86_EFLAGS_RESET_PF:
        return "RESET_PF"
    elif eflag == X86_EFLAGS_PRIOR_NT:
        return "PRIOR_NT"
    elif eflag == X86_EFLAGS_MODIFY_TF:
        return "MOD_TF"
    elif eflag == X86_EFLAGS_MODIFY_IF:
        return "MOD_IF"
    elif eflag == X86_EFLAGS_MODIFY_DF:
        return "MOD_DF"
    elif eflag == X86_EFLAGS_MODIFY_NT:
        return "MOD_NT"
    elif eflag == X86_EFLAGS_MODIFY_RF:
        return "MOD_RF"
    elif eflag == X86_EFLAGS_SET_CF:
        return "SET_CF"
    elif eflag == X86_EFLAGS_SET_DF:
        return "SET_DF"
    elif eflag == X86_EFLAGS_SET_IF:
        return "SET_IF"
    else: 
        return None


def hex_str_or_int(value: str) -> int:
    if value.startswith("0x"):
        return int(value, 16)
    else:
        return int(value)

def table_lite_mode(md, code: bytes, offset: int, skipto: int) -> Iterator[List]:
    for i in md.disasm_lite(CODE, offset=args.offset):
        (address, size, mnemonic, op_str) = i
        
        if address < skipto:
            continue

        
        yield [f"0x{address:x}", mnemonic, op_str, size]

def lite_mode(md, code: bytes, offset: int, skipto: int) -> Iterator[str]:
    for i in md.disasm_lite(CODE, offset=args.offset):
        (address, size, mnemonic, op_str) = i
        
        if address < skipto:
            continue

        yield f"0x{address:x}:\t{mnemonic}\t{op_str}\tSize={size}"
        
        
        
def table_full_mode(md, code: bytes, offset: int, skipto: int) -> Iterator[List]:
    for i in md.disasm(CODE, offset=args.offset):
        if i.address < skipto:
            continue

        text = [
            f"0x{i.address:x}",
            i.mnemonic,
            i.op_str,
            i.id,
            i.size,
            str(i.bytes)[11:-1]
        ]
            

        try:
            regs_read, regs_write = i.regs_access()
            
            text.append('\n'.join(i.reg_name(x) for x in regs_read))

            text.append('\n'.join(i.reg_name(x) for x in regs_write))
        except capstone.CsError:
            text.append(None)
            text.append(None)
            

        try:
            text.append('\n'.join(i.group_name(x) for x in i.groups))
        except capstone.CsError:
            text.append(None)
            
        try:
            text.append(len(i.operands))
        except capstone.CsError:
            text.append(None)
            
        for op_num in range(2):
            try:
                op = i.operands[op_num]

                op_details = []
                if op.type == X86_OP_INVALID:
                    op_details.append(f"INVALID")
                elif op.type == X86_OP_REG:
                    op_details.append(f"REG={i.reg_name(op.value.reg)}")
                elif op.type == X86_OP_IMM:
                    op_details.append(f"IMMEDIATE={hex( op.value.imm )}")
                elif op.type == X86_OP_MEM:
                    mem = op.value.mem
                    op_details.append(f"MEM base={mem.base}, index={mem.index}, disp={mem.disp}")
                    
                
                # access
                if op.access == CS_AC_INVALID:
                    op_details.append(f"access=Immediate")
                elif op.access == CS_AC_READ:
                    op_details.append(f"access=READ")
                elif op.access == CS_AC_WRITE:
                    op_details.append(f"access=WRITE")
                elif op.access == CS_AC_READ + CS_AC_WRITE:
                    op_details.append(f"access=READ & WRITE")
                    
                text.append("\n".join(op_details))

            except capstone.CsError:
                text.append(None)
            except Exception:
                text.append(None)
        
        
        try:
            if i.eflags:
                updated_flags = []
                for j in range(0,46):
                    if i.eflags & (1 << j):
                        updated_flags.append(get_eflag_name(1<<j))
                text.append('\n'.join(updated_flags))
        except capstone.CsError:
            text.append(None)
            
        yield text
        
        
def full_mode(md, code: bytes, offset: int, skipto: int) -> Iterator[str]:
    # disassemble binary code with disasm(binary_code, offset) # offset is address of first instruction
    
    for i in md.disasm(CODE, offset=args.offset):
        if i.address < skipto:
            continue
        
        text = []
        
        text.append(colored(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}\tID={i.id}\tSize={i.size}\tBytes={str(i.bytes)[11:-1]}", "green"))
        
        regs_read, regs_write = None, None

        try:
            regs_read, regs_write = i.regs_access()
            if regs_read:
                text.append(f"\tRegisters Read:\t\t{', '.join(i.reg_name(x) for x in regs_read)}")

            if regs_write:
                text.append(f"\tRegisters Written:\t{', '.join(i.reg_name(x) for x in regs_write)}")
        except capstone.CsError:
            pass

        try:
            if i.groups:
                text.append(f"\tGroups:\t\t{', '.join(i.group_name(x) for x in i.groups)}")
        except capstone.CsError:
            pass
            
        try:
            if i.operands:
                text.append(f"\t{len(i.operands)} Operands")
                c=0
                for op in i.operands:
                    if op.type == X86_OP_INVALID:
                        text.append(f"\toperand[{c}]:\tINVALID")
                    elif op.type == X86_OP_REG:
                        text.append(f"\toperand[{c}]:\tREG={i.reg_name(op.value.reg)}")
                    elif op.type == X86_OP_IMM:
                        text.append(f"\t[{c}]:\tIMMEDIATE={hex( op.value.imm )}")
                    elif op.type == X86_OP_MEM:
                        mem = op.value.mem
                        text.append(f"\toperand[{c}]:\tMEM base={mem.base}, index={mem.index}, disp={mem.disp}")
                        
                    
                    if op.access == CS_AC_INVALID:
                        text.append(f"\t\t\taccess=Immediate")
                    elif op.access == CS_AC_READ:
                        text.append(f"\t\t\taccess=READ")
                    elif op.access == CS_AC_WRITE:
                        text.append(f"\t\t\taccess=WRITE")
                    elif op.access == CS_AC_READ + CS_AC_WRITE:
                        text.append(f"\t\t\taccess=READ & WRITE")

                    c += 1
        except capstone.CsError:
            pass
                
        try:
            if i.eflags:
                updated_flags = []
                for j in range(0,46):
                    if i.eflags & (1 << j):
                        updated_flags.append(get_eflag_name(1<<j))
                text.append(f"\tFLAGS:\t\t{','.join(updated_flags)}")
        except capstone.CsError:
            pass
            
        yield "\n".join(text)
                
    


if __name__ == "__main__":
    init()  # colorama init code

    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('filename',type=str, help='filename to process')
    parser.add_argument('--offset', type=hex_str_or_int, default='0', help='offset to first instruction')
    parser.add_argument('--pagesize', type=int, default=4, help='how many instructions to display per page')
    parser.add_argument('-lite', action='store_true', help='show less information')
    parser.add_argument('-table', action='store_true', help='show in table format')
    parser.add_argument('--skipto', type=hex_str_or_int, default=0, help='skip to this address')

    args = parser.parse_args()

    
    with open(args.filename, 'rb') as f:
        CODE = f.read()
        
    
    # Capstone class(hardware architecture, hardware mode)
    md = Cs(CS_ARCH_X86, CS_MODE_64) # x86, 64-bit mode

    # to get details like implicit registers read/written, or groups
    md.detail = True

    # skipdata to not stop on broken instruction
    md.skipdata = True

    if args.lite:
        # if we don't want full instruction info in CsInsn, we can use disasm_lite() which is faster
        # and it returns Tuple[address, size, mnemonic, op_str]
        if args.table:
            headers = ["Address", "Mnemonic", "Op String", "Size"]
            text_it = table_lite_mode(md, CODE, args.offset, args.skipto)
        else:
            text_it = lite_mode(md, CODE, args.offset, args.skipto)
    else:
        
        if args.table:
            headers = ["Address", "Mnemonic", "Op String", "ID", "Size", "Bytes", "Reg Read", "Reg Write", "Groups", "# Op", "Op 1", "Op 2", "Flags"]
            text_it = table_full_mode(md, CODE, args.offset, args.skipto)
        else:
            text_it = full_mode(md, CODE, args.offset, args.skipto)
    
    
    # page through the text items until we reach StopIteration
    quit = False
    while not quit:
        cur_page = []
        for p in range(args.pagesize):
            try:
                item = next(text_it)

                cur_page.append(item)
            except StopIteration:
                quit = True
                break
            
        if args.table:
            print(tabulate(cur_page, headers=headers, tablefmt="fancy_grid"))
        else:
            print("\n".join(cur_page))

        if quit:
            break
        
        x = input('-- More --')
        while True:
            x = x.strip()
            if x == 'q':
                quit = True
                break
            elif not x:
                # new line or space
                break
            else:
                try:
                    goto_address = hex_str_or_int(x)
                    
                    # Restart generation
                    if args.lite:
                        # if we don't want full instruction info in CsInsn, we can use disasm_lite() which is faster
                        # and it returns Tuple[address, size, mnemonic, op_str]
                        if args.table:
                            headers = ["Address", "Mnemonic", "Op String", "Size"]
                            text_it = table_lite_mode(md, CODE, args.offset, goto_address)
                        else:
                            text_it = lite_mode(md, CODE, args.offset, goto_address)
                    else:
                        
                        if args.table:
                            headers = ["Address", "Mnemonic", "Op String", "ID", "Size", "Bytes", "Reg Read", "Reg Write", "Groups", "# Op", "Op 1", "Op 2", "Flags"]
                            text_it = table_full_mode(md, CODE, args.offset, goto_address)
                        else:
                            text_it = full_mode(md, CODE, args.offset, goto_address)
                            
                    break
                except Exception:
                    pass
                
            # until we get valid input, don't display next page
            x = input('')
