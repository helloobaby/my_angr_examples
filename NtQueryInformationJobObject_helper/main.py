# model name      : Intel(R) Xeon(R) CPU E5-2690 v2 @ 3.00GHz
# 跑五分钟
# 吃两三G内存
# 结果是31

import angr
import claripy

def main():
    # create project
    proj = angr.Project('/root/Angr_Tutorial_For_CTF/problems/ntoskrnl_17763_107.exe',auto_load_libs=False)
    print(proj)
    print(hex(proj.entry))
    
    init_state=proj.factory.blank_state(addr=0x14056E7E0)
    simgr=proj.factory.simgr(init_state)
    
# <SimulationManager with 2 active>
# >>> simgr.active
# [<SimState @ 0x14056e842>, <SimState @ 0x140702ec0>]

#14056e83c分支14056e842，0x140702ec0

# 模拟执行如果走0x140702ec0遇到无条件分支0x14056ea59
#        如果走0x14056e842遇到0x14056e84e，0x14056ebcd
# >>> simgr.step()
# <SimulationManager with 3 active>
# >>> simgr.active
# [<SimState @ 0x14056ebcd>, <SimState @ 0x14056e84e>, <SimState @ 0x14056ea59>]

# 如果走0x14056e84e，会碰到2个分支，0x14056e857,0x14056f2a4
# 如果走0x14056ebcd，0x14056ebd7，0x0x14056eb83
# 如果走0x14056ea59，call    __security_check_cookie(0x14018dbc0)

# >>> simgr.step()
# <SimulationManager with 5 active>
# >>> simgr.active
# [<SimState @ 0x14056eb83>, <SimState @ 0x14056ebd7>, <SimState @ 0x14056f2a4>, <SimState @ 0x14056e857>, <SimState @ 0x14018dbc0>]
# >>> simgr.step()
# <SimulationManager with 8 active>
# >>> simgr.active
# [<SimState @ 0x14056e8a1>, <SimState @ 0x14056eb83>, <SimState @ 0x14056ebdc>, <SimState @ 0x14056eb83>, <SimState @ 0x14056f2ae>, <SimState @ 0x14056f291>, <SimState @ 0x14056e860>, <SimState @ 0x14018dbc9>]
# <SimulationManager with 11 active>
# >>> simgr.active
# [<SimState @ 0x14056e92f>, <SimState @ 0x14056e8c8>, <SimState @ 0x14056e8a1>, <SimState @ 0x1407024b4>, <SimState @ 0x14056e8a1>, <SimState @ 0x14056eb7d>, <SimState @ 0x14056eb83>, <SimState @ 0x14056f29b>, <SimState @ 0x14056eb73>, <SimState @ 0x14056e869>, <SimState @ 0x14018dbd4>]  
    
    
    # 目的分支
    good_addr=0x140702BB2
    
    # 
    jclass=claripy.BVS('JobInformationClass',32)
    init_state.regs.rdx=jclass
    
    while len(simgr.active):
        for active in simgr.active:
            print(hex(active.addr))
            block = proj.factory.block(active.addr)
            
            if(active.addr == good_addr):
                print('能够达到指定分支')
                active:angr.sim_state.SimState = active     
                print(active.solver.eval(jclass))         
                exit(0)
            
            # 首先要尝试hook掉所有中间的call
            # 内核函数都大的一B,不hook这辈子也跑不出来
            for inst in block.capstone.insns:
                if inst.mnemonic == 'call':
                    next_func_addr = int(inst.op_str, 16)
                    proj.hook(next_func_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](), replace=True)
                    print('Hook [%s\t%s] at %#x' % (inst.mnemonic, inst.op_str, inst.address))
        simgr.step()
    
    
        
    
if __name__ == '__main__':
    main()
    

