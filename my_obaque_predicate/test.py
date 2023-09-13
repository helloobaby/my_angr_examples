import angr
import claripy

def main():
    proj = angr.Project('/root/a.out',auto_load_libs=False)
    
    start_addr=0x04008bb
    init_state:angr.sim_state.SimState = proj.factory.blank_state(addr=start_addr)
    simgr = proj.factory.simgr(init_state)
    
    rbp=init_state.regs.rbp
    sym=claripy.BVS('',64)
    init_state.memory.store(rbp-0xc,sym,endness='Iend_LE')
    
    # if ((var_14 > 2 && var_14 <= 0))
    # 这个分支是走不到的,代码写的不对就可能出现有found的情况
    simgr.explore(find=0x004008ca)
    
    print(simgr)
    if(simgr.found):
        solution=simgr.found[0]
        print(solution)
        print(hex(solution.solver.eval(sym)))    
    
    
if __name__ == '__main__':
    main()
    

