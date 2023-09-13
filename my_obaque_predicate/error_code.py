import angr
import claripy

def main():
    proj = angr.Project('/root/a.out',auto_load_libs=False)
    init_state = proj.factory.blank_state(addr=0x40088A)
    simgr = proj.factory.simgr(init_state)
    
    reach_bb=[]
    # 因为angr的basicblock的定义和ida这类工具的定义不太一样
    noisy=[]
    
    while len(simgr.active):
        for active in simgr.active:
            
            # hook all call
            block = proj.factory.block(active.addr)
            for inst in block.capstone.insns:
                if inst.mnemonic == 'call':
                    next_func_addr = int(inst.op_str, 16)
                    proj.hook(next_func_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)
                    print('Hook [%s\t%s] at %#x %d' % (inst.mnemonic, inst.op_str, inst.address,inst.size))
# 000008b6  e865feffff         call    std::istream::operator>>
# 000008bb  8b45f4             mov     eax, dword [rbp-0xc {var_14}]
                    noisy.append(next_func_addr)
                    noisy.append(inst.address+inst.size)
            reach_bb.append(active.addr)    
            
        simgr.step()
    
    #reach_bb=list(set(reach_bb)-set(noisy))
    for addr in reach_bb:
        print(hex(addr))
    
    
if __name__ == '__main__':
    main()
    

