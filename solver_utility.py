import claripy
from angr import PointerWrapper, sim_options, SIM_PROCEDURES
from angr.sim_type import SimTypeFunction, SimTypePointer
from angr.errors import SimUnsatError
from math import ceil

class SolverUtility:
    def __init__(self, project):
        self.project = project
    
    def _symbolic_par(self,x,cc,par,state,par_val=None):
        symb_par=claripy.BVS(x, par.size)
        print(state.solver.constraints)
        if par_val is None:
            sim_reg=cc.return_val(par)
            par_val=sim_reg.reg_name
            
        # symb_val = getattr(state.regs,par_val)
        # print(type(symb_val))
        # t=state.project.concrete_target
        #print(state.__getstate__())
        #print(state.read_register(par_val))
        #state.solver.add(symb_par == symb_val)
        setattr(state.regs,str(par_val),symb_par)

        return symb_par

    def _rules_symbolic_par(self,cc,api,par_list,state):
        symb_input=dict()
        # Symbolic return variable
        if par_list[0] is not None:
            symb_input[par_list[0]]=self._symbolic_par(par_list[0],cc,api.type.returnty,state)
            
        # Symbolic input variables
        input_arg=api.type.args
        for i,x in enumerate(par_list[1:]):
            if x!='?':
                symb_input[x]=self._symbolic_par(x,cc,input_arg[i],state,api.reg[i]) 
        print(symb_input)
        return symb_input    

    def _create_call_state(self,args, input_type, source,extras):
        y = [PointerWrapper(x, buffer=True) for x in args]

        #Change inputs into pointer
        p = [SimTypePointer(r) for r in input_type.args]
        c = SimTypeFunction(p, input_type.returnty)

        return self.project.factory.call_state(source, *y, prototype=c,add_options=extras)
    
    def _get_solutions(self,solver,n,args):
        solutions=[]
        try:
            temp=[solver.eval_upto(args[i],n, cast_to=bytes) for i in range(len(args))] 
        except SimUnsatError:
            return None
        min_length=min(len(sublist) for sublist in temp)
        for i in range(min_length):
            solutions.append([repr(x[i]) for x in temp])
        
        return solutions

    def _explore(self, sm, args, n):
        
        num_paths=len(sm.found)
        paths = sm.found[:n] if num_paths > n else sm.found

        solutions = []
        for i, path in enumerate(paths):
            s=path.solver
            solutions.extend(self._get_solutions(s,ceil((n-i)/num_paths),args))
        
        solutions=[x for x in solutions if x is not None]
        if not solutions:
            return False

        return solutions

    def _explore_paths(self, find, n, input_type,source, binary,num_steps=None,api_list=[],visitor=None):
        claripy_contstraints=None
        symbolic_par=None
        input_arg = input_type.args
        extras = {sim_options.REVERSE_MEMORY_NAME_MAP, sim_options.TRACK_ACTION_HISTORY}

        # Symbolic input variables
        args = [claripy.BVS("arg"+ str(i), size.size) for i,size in enumerate(input_arg)]
        if source is None:
            state=self.project.factory.entry_state(args=[binary]+args, add_options=extras)
        else:
            state = self._create_call_state(args,input_type, source,extras)

        # Explore the program with symbolic execution
        sm = self.project.factory.simgr(state, save_unconstrained=True)
        sm.explore(find=find)

        if num_steps is not None:
            #Calling convention
            cc=self.project.factory.cc()
            symbolic_par=dict()
            for i,a in enumerate(api_list[:-1]):
                if sm.found:
                    symbolic_par.update(self._rules_symbolic_par(cc,a,visitor.par_list[i],sm.found[0]))
                    sm= self.project.factory.simgr(sm.found[0], save_unconstrained=True)
                    sm.explore(find=api_list[i+1].address,n=num_steps)
                else:
                    return None,None
            if sm.found:
                symbolic_par.update(self._rules_symbolic_par(cc,api_list[-1],visitor.par_list[-1],sm.found[0]))
                print(symbolic_par)
                claripy_contstraints=visitor.predicate(symbolic_par)
                solver=sm.found[0].solver
                solver.add(claripy_contstraints)
                print(solver.constraints)
            else:
                return None,None
            
            # Get solutions leading to reaching the api_address
            solutions=self._get_solutions(solver,n,args)
        else:
            solutions = self._explore(sm,args, n)
    
        return solutions, symbolic_par
    

    def get_solver(self, target, n, input_type,source=None, binary=None,num_steps=None, visitor=None):
        if num_steps is not None:
            return self._explore_paths(target[0].address, n, input_type,source,binary,num_steps,api_list=target,visitor=visitor)
        else:
            return self._explore_paths(target, n, input_type,source,binary)
