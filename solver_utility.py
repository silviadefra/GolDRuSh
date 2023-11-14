import claripy
from angr import PointerWrapper, SimTypePointer, SimTypeFunction
from math import ceil

class SolverUtility:
    def __init__(self, project):
        self.project = project

    def _explore_paths(self, find, n, input_type,source=None, num_steps=None, binary=None,api_list=None):
        input_arg = input_type.args
        args = [claripy.BVS("arg"+ str(i), input_arg[i].size) for i in range(len(input_arg))]

        if source is None:
            state=self.project.factory.entry_state(args=[binary]+args)
        else:
            y = [PointerWrapper(x, buffer=True) for x in args]

            p = [SimTypePointer(r) for r in input_arg]
            c = SimTypeFunction(p, input_type.returnty)
            state = self.project.factory.call_state(source, *y, prototype=c)
        
        sm = self.project.factory.simgr(state, save_unconstrained=True)
        sm.explore(find=find)

        constraints = []
        solutions = []
        num_paths = len(sm.found)

        if num_paths > n:
            paths = sm.found[:n]
        else:
            paths = sm.found

        for i, path in enumerate(paths):
            m = ceil((n-i)/num_paths)
            constraints.extend(path.solver.constraints)
            temp = [path.solver.eval_upto(args[i], m, cast_to=bytes) for i in range(len(args))]
            min_length = min(len(sublist) for sublist in temp)
            for i in range(min_length):
                solutions.append([x[i].decode() for x in temp])

        if num_steps is not None:
            sm.move(from_stash="found", to_stash="active")
            for a in api_list:
                sm.run(n=num_steps)

                if not any(a in state.history.bbl_addrs for state in sm.active):
                    return None, None

        if constraints:
            combined_constraints = claripy.Or(*constraints)
            solver = claripy.Solver()
            solver.add(combined_constraints)
        else:
            solver = True

        return solver, solutions
    

    def get_solver(self, target, n, input_type,source=None, num_steps=None, binary=None):
        
        if len(target)>1:
            target=target[0]
            api_list=target[1:]
        else:
            api_list=None
       
        return self._explore_paths(target, n, input_type,source,num_steps,binary,api_list)
