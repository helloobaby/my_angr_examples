import angr
import claripy

def main():
    proj = angr.Project('/root/a.out',auto_load_libs=False)
    
    start_addr=0x004008bb
    init_state = proj.factory.blank_state(addr=start_addr)
    simgr = proj.factory.simgr(init_state)
    
    cfg = proj.analyses.CFGFast()
    
    # 要加入约束
    rbp=init_state.regs.rbp
    sym=claripy.BVS('',64)
    init_state.memory.store(rbp-0xc,sym,endness='Iend_LE')
    
    reach_bb=[]
    noisy=[start_addr]
    
    while len(simgr.active):
        for active in simgr.active:
            
            # hook all call
            block:angr.block.Block = proj.factory.block(active.addr)
            for inst in block.capstone.insns:
                if inst.mnemonic == 'call':
                    next_func_addr = int(inst.op_str, 16)
                    proj.hook(next_func_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)
                    print('Hook [%s\t%s] at %#x %d' % (inst.mnemonic, inst.op_str, inst.address,inst.size))
                    noisy.append(next_func_addr)
            reach_bb.append(active.addr)    
            
        simgr.step()
        reach_bb=list(set(reach_bb)-set(noisy))
    for addr in reach_bb:
        print(hex(addr))
    
    
if __name__ == '__main__':
    main()
    