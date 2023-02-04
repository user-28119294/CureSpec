from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import sys
import re

import angr
from angrutils import *

""" Sample 1
push   %rbp
mov    %rsp,%rbp
mov    %edi,-0x4(%rbp) -> prolog

if (idx < array1_size) {                  
  mov    -0x4(%rbp),%edx
  mov    0x2edb(%rip),%eax        # 4040 <array1_size>
  cmp    %eax,%edx ; important!!!
  jae    119b <victim_fun+0x46> ; important
; temp &= array2[array1[idx] * 512];
  mov    -0x4(%rbp),%eax
  cltq   ; ignore
  lea    0x2f0b(%rip),%rdx        # 4080 <array1>
  movzbl (%rax,%rdx,1),%eax
  movzbl %al,%eax
  shl    $0x9,%eax
  cltq   
  lea    0x2f38(%rip),%rdx        # 40c0 <array2>
  movzbl (%rax,%rdx,1),%edx
  movzbl 0x2ece(%rip),%eax        # 4061 <temp>
  and    %edx,%eax
  mov    %al,0x2ec6(%rip)        # 4061 <temp>
"""

#ASLR gadget
"""
uint8_t victim_fun(int idx) {
    1155:       55                      push   %rbp
    1156:       48 89 e5                mov    %rsp,%rbp
    1159:       89 7d fc                mov    %edi,-0x4(%rbp)
    if (idx < array1_size) {                  
    115c:       8b 55 fc                mov    -0x4(%rbp),%edx
    115f:       8b 05 db 2e 00 00       mov    0x2edb(%rip),%eax        # 4040 <array1_size>
    1165:       39 c2                   cmp    %eax,%edx
    1167:       73 12                   jae    117b <victim_fun+0x26>
        return array1[idx];
    1169:       8b 45 fc                mov    -0x4(%rbp),%eax
    116c:       48 98                   cltq   
    116e:       48 8d 15 0b 2f 00 00    lea    0x2f0b(%rip),%rdx        # 4080 <array1>
    1175:       0f b6 04 10             movzbl (%rax,%rdx,1),%eax
    1179:       eb 00                   jmp    117b <victim_fun+0x26>
    }
}
    117b:       5d                      pop    %rbp
    117c:       c3                      retq
"""

#optimized ASLR gadget
"""

"""

X64_CALLING_REGS = ["di","si","dx","cx","8","9"]
CMP_INSTRUCTIONS = ["test","cmp"]
DEREF_INSTRUCTIONS = ["lea"]

MOV = "mov"


def process_file(filename):
    with open(filename, 'rb') as f:
      elffile = ELFFile(f)
      code = elffile.get_section_by_name('.text')
      opcodes = code.data()
      addr = code['sh_addr']
      md = Cs(CS_ARCH_X86, CS_MODE_64)
      vf = code.get_symbol_by_name['victim_fun']
      for i in md.disasm(opcodes, addr):
          print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


def section_info_highlevel(elffile):
    print('High level API...')

    # Just use the public methods of ELFFile to get what we need
    # Note that section names are strings.
    print('  %s sections' % elffile.num_sections())
    section = elffile.get_section_by_name('.symtab')

    if not section:
        print('  No symbol table found. Perhaps this ELF has been stripped?')
        return

    # A section type is in its header, but the name was decoded and placed in
    # a public attribute.
    print('  Section name: %s, type: %s' %(
        section.name, section['sh_type']))

    # But there's more... If this section is a symbol table section (which is
    # the case in the sample ELF file that comes with the examples), we can
    # get some more information about it.
    if isinstance(section, SymbolTableSection):
        num_symbols = section.num_symbols()
        for i in range(0,num_symbols):
          print("  The name of the last symbol in the section is: %s" % (
              section.get_symbol(i).name))

def generate_call_graph_for_function(binary,function_name,filename):
  proj = angr.Project(binary, load_options={'auto_load_libs':False})
  main = proj.loader.main_object.get_symbol(function_name)
  analyze_and_plot(proj, main.rebased_addr,filename)


def analyze_and_plot(b, addr, name=None):
  start_state = b.factory.blank_state(addr=addr)
  start_state.stack_push(0x0)
  with hook0(b):
    cfg = b.analyses.CFGEmulated(fail_fast=False, starts=[addr], call_depth=30, context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=True,normalize=True)

  plot_cg(b.kb, "%s_cg" % name, format="png")

#think about basic blocks
if __name__ == '__main__':
    if len(sys.argv) == 2:
      #process_file(sys.argv[1])
      filename = sys.argv[1]
      with open(filename, 'rb') as f:
        generate_call_graph_for_function(filename,"main","ćg")
        """
        elffile = ELFFile(f)
        code = elffile.get_section_by_name('.text')
        opcodes = code.data()
        base_addr = code['sh_addr']
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        symtab = elffile.get_section_by_name('.symtab')
        #['st_info'].type == STT_FUNC
        victim_fun = symtab.get_symbol_by_name('victim_fun')

        func = victim_fun[0]
        offset = func['st_value'] - base_addr
        subset_oc = opcodes[offset:offset+func['st_size']]

        print("Function: %s" % func.name)

        oc_list = []
        #TODO: look for smart way to find compares, jumps
        for line_num, i in enumerate(md.disasm(subset_oc,func['st_value'])):
          oc_list.append((line_num,i.address,i.mnemonic,i.op_str))
          #print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        current_jump_tar = -1
        for i in range(0,len(oc_list)):
          line_num,addr,mnemonic,op_str = oc_list[i]
          if(mnemonic in CMP_INSTRUCTIONS):
            cmp_reg_a = op_str.split(',')[0][1:]
            cmp_reg_b = op_str.split(',')[1][1:]

            param_register = ""
            if(cmp_reg_b in X64_CALLING_REGS):
              param_register = cmp_reg_b
            elif(cmp_reg_a in X64_CALLING_REGS):
              param_register = cmp_reg_a

            i +=1
            #this should be now a jmp
            line_num,addr,mnemonic,op_str = oc_list[i]
            #print("\t%s\t%s" %(mnemonic,op_str))
            current_jump_tar = int(op_str,16)
            #look at first branch
            i += 1
            line_num,addr,mnemonic,op_str = oc_list[i]
            while current_jump_tar != addr:
              line_num,addr,mnemonic,op_str = oc_list[i]
              #TODO: think of more sophisticated approach
              if(MOV in mnemonic and param_register in op_str):
                print("Potential gadget found...")
              i+=1
            """

            #look for lea + mov instructions



    else:
      print("Usage ./parse_bin.py <binary-file>")

"""
Use angr to jump to the potential dangerous functions
"""