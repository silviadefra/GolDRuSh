#!/usr/bin python3

from angr.errors import SimUnsatError
from angr import sim_options
import claripy
import sys
from tree_visitor import FuncVisitor
from call_graph import file_data
from graph_distance import first_distance
from solver_utility import SolverUtility
from angr import PointerWrapper
from angr.sim_type import SimTypeFunction, SimTypePointer


def value_api(addr,types,p):

    block = p.factory.block(addr)
    block.capstone.pp() # Capstone object has pretty print and other data about the dissassembly
    block.vex.pp()

    input_arg = types.args

    # Symbolic input variables
    args = [claripy.BVS("arg"+ str(i), size.size) for i,size in enumerate(input_arg)]
    y = [PointerWrapper(x, buffer=True) for x in args]

        #Change inputs into pointer
    d = [SimTypePointer(r) for r in types.args]
    c = SimTypeFunction(d, types.returnty)
    initial_state = p.factory.call_state(addr,*y,prototype=c)
    #initial_state.regs.ip = addr
    print(initial_state.callstack)

    simulation = p.factory.simulation_manager(initial_state)
    simulation.run()
    
    final_state = simulation.deadended[0]

    print(final_state.addr)

    # Retrieve the return value
    #return_value = final_state.solver.eval(final_state.regs.ret)

    # Retrieve the values of function arguments
    #arg1_value = final_state.solver.eval(final_state.mem[final_state.regs.esp + 4].int.resolved)
    #arg2_value = final_state.solver.eval(final_state.mem[final_state.regs.esp + 8].int.resolved)
    #print(return_value)



def get_main_solver_distance1(api_address,project,n,binary_path,input,num_steps,api_type):

    # Input arguments
    input_arg=input.args

    # Symbolic input variables
    args=[claripy.BVS("arg"+ str(i),input_arg[i].size) for i in range(len(input_arg))]
    lenght=len(input_arg)+1

    #Calling convention
    cc=project.factory.cc()

    #for a,t in zip(api_address,api_type):
        #value_api(a,t,project)

    ret=api_type[0].returnty
    return_value = claripy.BVS("return_value", ret.size)

    #__getattr__(
    a=cc.return_val(ret)
    print(type(a.reg_name))
    print(a)

    # Set up symbolic variables and constraints
    state= project.factory.entry_state(args=[binary_path]+args, cc=cc)
    state.options |= {sim_options.CONSTRAINT_TRACKING_IN_SOLVER}
    state.options -= {sim_options.COMPOSITE_SOLVER}
    setattr(state.regs,a.reg_name,return_value) #settattr(obj,attr_name,val)=(obj.attr_name=val)
    #state.regs.rax= return_value

    # Explore the program with symbolic execution
    sm = project.factory.simgr(state)
    sm.explore(find=api_address[0])
    
    # Check if the functions in 'api_address' can be reached in a max of 'num_steps' steps
    for a in api_address[1:]:
        if sm.found:
            sm= project.factory.simgr(sm.found[0], save_unconstrained=True)
            sm.explore(find=a,n=num_steps)
        else:
            return None,None
        
    solver=sm.found[0].solver

    # Get solutions leading to reaching the api_address
    solutions=[]
    temp=[sm.found[0].solver.eval_upto(args[i],n, cast_to=bytes) for i in range(len(args))]   

    min_length=min(len(sublist) for sublist in temp)
    for i in range(min_length):
        solutions.append([lenght]+[repr(x[i]) for x in temp])

    return solver, solutions


# Find the successors with smaller distance
def find_succ(source,graph,addr,distance):
    
    elems_in_both_lists = set(addr) & set(list(graph.successors(source)))
    target_addr=[x for x in elems_in_both_lists if distance[source] > distance[x]]
    
    return target_addr


def entry_node(nodes,data,graph):
    
    start_nodes = [n for n, d in graph.in_degree() if d == 0]
    main_f=list(set(start_nodes) & set(nodes))[0]
    i=data.index[data['address']==main_f].item() # main function index
    input_type=data.loc[i,'type'] 

    return main_f,input_type,i


# Dataframe of functions, for each function: solver, values  
def functions_dataframe(binary_path, project, call_graph, function_data, n, steps,nodes,distance,api_address,api_type):
    
    # function 'main' of the binary
    main_f,input_type,i=entry_node(nodes,function_data,call_graph)

    main_solver=SolverUtility(project)
    # If 'api_address' are reachable from the main
    if distance[main_f]==1:
        s,v=get_main_solver_distance1(api_address,project,n,binary_path,input_type,steps,api_type)
        if s is None:
            return
        
    else:
        # Find successors with smaller distance
        target_func=find_succ(main_f,call_graph,nodes,distance)
        # Get the solver with constraints leading to reaching the target_func, and values to solve them
        s,v=main_solver.get_solver(target_func,n,input_type,binary=binary_path)
    
    function_data.loc[i,'solver']=s
    function_data.at[i,'values']=v

    nodes.remove(main_f)
    #TODO in parallel
    for starting_address in nodes:
        func_solver=SolverUtility(project)
        i=function_data.index[function_data['address']==starting_address].item()
        input_type=function_data.loc[i,'type']
        if distance[starting_address]==0:
            continue
        elif distance[starting_address]==1:
            s,v=func_solver.get_solver(api_address,n,input_type,source=starting_address,binary=binary_path,num_steps=steps)
            if s is None:
                return
        else:
            # Find for each node successors with smaller distance
            target_func=find_succ(starting_address,call_graph,nodes,distance) #forse conviene non definire la funzione e mettere tutto nel main
            # Get the solver with constraints leading to reaching the target_func, and values to solve them
            s,v=func_solver.get_solver(target_func,n,input_type,source=starting_address)
        
        function_data.loc[i,'solver']=s
        function_data.at[i,'values']=v

    return function_data


# Main function
def main(binary_path,rules):

    #TODO
    num_values=2
    steps=5

    project,call_graph,function_data,func_addr=file_data(binary_path)

    for tree in rules:
        visitor = FuncVisitor()
        visitor.visit(tree)

        nodes,distance,api_address,api_type,functions_data=first_distance(func_addr,visitor.api_list,function_data,call_graph)

        functions_data=functions_dataframe(binary_path,project,call_graph,function_data,num_values,steps,nodes,distance,api_address,api_type)

    return functions_data


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python graph_distance.py <file target_executable> <file binary>")
        #sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    # Specify the function name
    filename= sys.argv[2]

    with open(filename, "r") as file:
        rules = file.read()

    functions_data=main(binary_path,rules)