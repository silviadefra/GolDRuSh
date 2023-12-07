import claripy
from angr import PointerWrapper
from angr.sim_type import SimTypeFunction, SimTypePointer
from math import ceil

class SolverUtility:
    def __init__(self, project):
        self.project = project


    def _create_call_state(self,args, input_type, source):
        y = [PointerWrapper(x, buffer=True) for x in args]

        #Change inputs into pointer
        p = [SimTypePointer(r) for r in input_type.args]
        c = SimTypeFunction(p, input_type.returnty)

        return self.project.factory.call_state(source, *y, prototype=c)
    
    def _get_solutions(self,path,n,args):
        solutions=[]
        temp=[path.solver.eval_upto(args[i],n, cast_to=bytes) for i in range(len(args))]   

        min_length=min(len(sublist) for sublist in temp)
        for i in range(min_length):
            solutions.append([repr(x[i]) for x in temp])
        return solutions

    def _explore(self, sm, args, n):
        
        num_paths=len(sm.found)
        paths = sm.found[:n] if num_paths > n else sm.found

        constraints = []
        solutions = []
        for i, path in enumerate(paths):
            constraints.extend(path.solver.constraints)
            solutions.extend(self._get_solutions(path,ceil((n-i)/num_paths),args))

        # Create a solver with all the constraints combined using the logical OR operator
        if constraints:
            solver = self._combine_constraints(constraints)
        else:
            solver = True

        return solver, solutions

    def _combine_constraints(self, constraints):
        combined_constraints = claripy.Or(*constraints)
        solver = claripy.Solver()
        solver.add(combined_constraints)
        return solver


    def _explore_paths(self, find, n, input_type,source=None, num_steps=None, binary=None,api_list=[]):
        
        input_arg = input_type.args

        # Symbolic input variables
        args = [claripy.BVS("arg"+ str(i), size.size) for i,size in enumerate(input_arg)]

        if source is None:
            state=self.project.factory.entry_state(args=[binary]+args)
        else:
            state = self._create_call_state(args,input_arg, source)

        # Explore the program with symbolic execution
        sm = self.project.factory.simgr(state, save_unconstrained=True)
        sm.explore(find=find)

        if num_steps is not None:
            for a in find[1:]:
                if sm.found:
                    sm= self.project.factory.simgr(sm.found[0], save_unconstrained=True)
                    sm.explore(find=a,n=num_steps)
                else:
                    return None,None
        
            solver=sm.found[0].solver

            # Get solutions leading to reaching the api_address
            solutions=self._get_solutions(sm.found[0],n,args)
        else:
            solver, solutions = self._explore(sm,args, n)

        return solver, solutions
    

    def get_solver(self, target, n, input_type,source=None, num_steps=None, binary=None):
        
        if len(target)>1:
            return self._explore_paths(target[0], n, input_type,source,num_steps,binary,target[1:])
        else:
            return self._explore_paths(target, n, input_type,source,num_steps,binary)
