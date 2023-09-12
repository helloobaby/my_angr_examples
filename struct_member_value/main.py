import angr
import claripy

def main():
    # create project
    proj = angr.Project('../problems/a.out',auto_load_libs=False)
    print(hex(proj.entry))
    # entry point
    init_state:angr.sim_state.SimState = proj.factory.blank_state(addr=0x400802)
    # create simulation
    simulation = proj.factory.simgr(init_state)
    
    address = 0x0A1BA1C0
    
    _1stparam=claripy.BVS('_1stparam',32)
    _11stparam=claripy.BVS('_11stparam',32)
    # mov     eax, [rax+4]   通过+4偏移访问Test结构体
    init_state.memory.store(address,_11stparam,endness='Iend_LE')
    # 不设置endness,打印出来的值全是大端的,但是一般x86架构下的字节序都是小端的
    init_state.memory.store(address+4,_1stparam,endness='Iend_LE')
    
    # rdi指向Test结构体
    init_state.regs.rdi=address
    
    
    
    simulation.explore(find=0x400821)
    print(simulation)
    
    
    
    
    if(simulation.found):
        #print(simulation.found)
        solution_state = simulation.found[0]
        print(hex(solution_state.solver.eval(_11stparam)))
        print(hex(solution_state.solver.eval(_1stparam)))
        
    
if __name__ == '__main__':
    main()
    

