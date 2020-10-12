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
    if value.startswith("0x") or value.startswith("0X"):
        return int(value, 16)
    else:
        return int(value)

def table_lite_mode(md, code: bytes, offset: int, skipto: int) -> Iterator[List]:
    for i in md.disasm_lite(CODE, offset=args.offset):
        (address, size, mnemonic, op_str) = i
        
        if address < skipto:
            continue

        
        address_str = f"0x{address:x}"
        yield [colored(address_str, "green"), colored( mnemonic, 'white', 'on_blue' ), colored(op_str, 'cyan'), size]

def lite_mode(md, code: bytes, offset: int, skipto: int) -> Iterator[str]:
    for i in md.disasm_lite(CODE, offset=args.offset):
        (address, size, mnemonic, op_str) = i
        
        if address < skipto:
            continue

        address_str = f"0x{address:x}"
        yield f"{colored(address_str, 'green')}:\t{colored( mnemonic , 'white', 'on_blue')}\t{colored( op_str , 'cyan')}\t\tSize={size}"
        
        
        
def table_full_mode(md, code: bytes, offset: int, skipto: int) -> Iterator[List]:
    for i in md.disasm(CODE, offset=args.offset):
        if i.address < skipto:
            continue

        address_str = f"0x{i.address:x}"

        text = [
            colored(address_str, "green"),
            colored(i.mnemonic, "white", "on_blue"),
            colored(i.op_str, "cyan"),
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
            
        for op_num in range(2):
            try:
                op = i.operands[op_num]


                if op.type == X86_OP_INVALID:
                    text.append(f"INVALID")
                elif op.type == X86_OP_REG:
                    register = i.reg_name(op.value.reg)
                    text.append(colored(register, 'green', attrs=['bold']))
                elif op.type == X86_OP_IMM:
                    immediate_value = hex( op.value.imm )
                    text.append(colored(immediate_value, 'magenta', attrs=['bold']))
                elif op.type == X86_OP_MEM:
                    mem = op.value.mem
                    mem_str = f"MEM[ {mem.base} + {mem.index}*{mem.scale} + {mem.disp} ] = MEM[ {mem.base + mem.index*mem.scale + mem.disp} ]"
                    text.append(colored(mem_str, 'yellow', attrs=['bold']))
                        
                # access
                if op.access == CS_AC_INVALID:
                    text[-1] += colored("  ( IMMEDIATE )", "magenta")
                elif op.access == CS_AC_READ:
                    text[-1] += colored("  ( READ )", "yellow")
                elif op.access == CS_AC_WRITE:
                    text[-1] += colored("  ( WRITE )", "red")
                elif op.access == CS_AC_READ + CS_AC_WRITE:
                    text[-1] += colored("  ( READ & WRITE )", 'red', attrs=['bold'])

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
        
        address_str = f"0x{i.address:x}"
        text.append(f"{colored(address_str, 'green')}:\t{colored( i.mnemonic , 'white',  'on_blue' )}\t{colored(i.op_str, 'cyan')}\tID={i.id}\tSize={i.size}\tBytes={str(i.bytes)[11:-1]}")
        
        regs_read, regs_write = None, None

        try:
            regs_read, regs_write = i.regs_access()
            if regs_read:
                text.append(f"\tReg Read:\t{', '.join(i.reg_name(x) for x in regs_read)}")

            if regs_write:
                text.append(f"\tReg Write:\t{', '.join(i.reg_name(x) for x in regs_write)}")
        except capstone.CsError:
            pass

        try:
            if i.groups:
                text.append(f"\tGroups:\t\t{', '.join(i.group_name(x) for x in i.groups)}")
        except capstone.CsError:
            pass
            
        try:
            if i.operands:

                c=1
                for op in i.operands:
                    op_number = colored(str(c), "white", attrs=['bold'])

                    if op.type == X86_OP_INVALID:
                        text.append(f"\t[{op_number}]:\tINVALID")
                    elif op.type == X86_OP_REG:
                        register = i.reg_name(op.value.reg)
                        text.append(f"\t[{op_number}]:\t{colored(register, 'green', attrs=['bold'])}")
                    elif op.type == X86_OP_IMM:
                        immediate_value = hex( op.value.imm )
                        text.append(f"\t[{op_number}]:\t{colored(immediate_value, 'magenta', attrs=['bold'])}")
                    elif op.type == X86_OP_MEM:
                        mem = op.value.mem
                        mem_str = f"MEM[ {mem.base} + {mem.index}*{mem.scale} + {mem.disp} ] = MEM[ {mem.base + mem.index*mem.scale + mem.disp} ]"
                        text.append(f"\t[{op_number}]:\t{colored(mem_str, 'yellow', attrs=['bold'])}")
                        
                    # access
                    if op.access == CS_AC_INVALID:
                        text[-1] += colored("\t( IMMEDIATE )", "magenta")
                    elif op.access == CS_AC_READ:
                        text[-1] += colored("\t( READ )", "yellow")
                    elif op.access == CS_AC_WRITE:
                        text[-1] += colored("\t( WRITE )", "red")
                    elif op.access == CS_AC_READ + CS_AC_WRITE:
                        text[-1] += colored("\t( READ & WRITE )", 'red', attrs=['bold'])

                    c += 1
        except capstone.CsError:
            pass
                
        try:
            if i.eflags:
                updated_flags = []
                for j in range(0,46):
                    if i.eflags & (1 << j):
                        updated_flags.append(get_eflag_name(1<<j))
                text.append(f"\tFLAGS:\t\t{', '.join(updated_flags)}")
        except capstone.CsError:
            pass
            
        yield "\n".join(text)
                
    


if __name__ == "__main__":
    init()  # colorama init code

    parser = argparse.ArgumentParser()
    parser.add_argument('filename',type=str, help='file to disassemble')
    parser.add_argument('--offset', type=hex_str_or_int, default='0', help='offset for first instruction (for if address 0 in file corresponds to different address)')
    parser.add_argument('--pagesize', type=int, default=4, help='how many instructions to display per page')
    parser.add_argument('-lite', action='store_true', help='lite mode to show only address, mnemonic, operands, and size of instruction')
    parser.add_argument('-table', action='store_true', help='show in table format')
    parser.add_argument('--skipto', type=hex_str_or_int, default=0, help='skip to this address (usually should be address of .text section)')

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
            headers = ["Address", "Mnemonic", "Op String", "ID", "Size", "Bytes", "Reg Read", "Reg Write", "Groups", "Op 1", "Op 2", "Flags"]
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
