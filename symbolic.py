#!/usr/bin python3

from angr import PointerWrapper
from angr.errors import SimUnsatError
from angr.sim_type import SimTypeFunction, SimTypePointer
import networkx as nx
import claripy
import math
import sys
from tree_visitor import FuncVisitor
from call_graph import file_data
from graph_distance import first_distance
from solver_utility import SolverUtility



def get_main_solver_distance1(api_address,project,n,binary_path,input,num_steps,api_type):

     # Input arguments
    input_arg=input.args

    # Symbolic input variables
    args=[claripy.BVS("arg"+ str(i),input_arg[i].size) for i in range(len(input_arg))]
    lenght=len(input_arg)+1

    #Calling convention
    cc=project.factory.cc()
    print(cc)

    # Set up symbolic variables and constraints
    state= project.factory.entry_state(args=[binary_path]+args,cc=cc)

    # Explore the program with symbolic execution
    sm = project.factory.simgr(state)
    sm.explore(find=api_address[0])
    
    # Get constraints and solutions leading to reaching the api_address
    constraints = []
    solutions=[]
    num_paths=len(sm.found)

    if num_paths>n:
        paths=sm.found[:n]
    else:
        paths=sm.found

    for i,path in enumerate(paths):
        ret=api_type[0].returnty
        return_value = claripy.BVS("return_value", ret.size)
        a=cc.return_val(ret)

        # Read the return value from the memory at api_address[0]
        #api_return_value = path.memory.load(api_address[0], ret.size, endness=path.arch.memory_endness)
    
        # Add a constraint that relates the symbolic variable to the return value of the API function
        path.solver.add(return_value == a)

        m=math.ceil((n-i)/num_paths) #number of solution for each path
        constraints.extend(path.solver.constraints)
        try:
            temp=[path.solver.eval_upto(args[i],m, cast_to=bytes) for i in range(len(args))]
        except SimUnsatError:
            print(path.solver.unsat_core)

        min_length=min(len(sublist) for sublist in temp)
        for i in range(min_length):
            solutions.append([lenght]+[repr(x[i]) for x in temp])
    

    # Check if the functions in 'api_address' can be reached in a max of 'num_steps' steps
    sm.move(from_stash="found", to_stash="active")
    for a in api_address[1:]:
        # Explore for a maximum of 'num_steps' steps
        sm.run(n=num_steps)
    
        # Check if the address 'a' is not found
        if not any(a in state.history.bbl_addrs for state in sm.active):
            return None, None      

    # Create a solver with all the constraints combined using the logical OR operator
    if constraints:
        combined_constraints = claripy.Or(*constraints)
        solver = claripy.Solver()
        solver.add(combined_constraints)
    else:
        solver=True

    return solver, solutions


# Find the successors with smaller distance
def find_succ(source,graph,addr,distance):
    
    elems_in_both_lists = set(addr) & set(list(graph.successors(source)))
    target_addr=[x for x in elems_in_both_lists if distance[source] > distance[x]]
    
    
    return target_addr

# Get solver and values to reach the target_func of the main
def get_main_solver(target,project,n,binary_path,input):

    # Input arguments
    input_arg=input.args

    # Symbolic input variables
    args=[claripy.BVS("arg"+ str(i),input_arg[i].size) for i in range(len(input_arg))]
    lenght=len(input_arg)+1

    # Set up symbolic variables and constraints
    state= project.factory.entry_state(args=[binary_path]+args)

    # Explore the program with symbolic execution
    sm = project.factory.simgr(state)
    sm.explore(find=target)

    # Get constraints and solutions leading to reaching the api_address
    constraints = []
    solutions=[]
    num_paths=len(sm.found)

    if num_paths>n:
        paths=sm.found[:n]
    else:
        paths=sm.found

    for i,path in enumerate(paths):
        m=math.ceil((n-i)/num_paths) #number of solution for each path
        constraints.extend(path.solver.constraints)
        temp=[path.solver.eval_upto(args[i],m, cast_to=bytes) for i in range(len(args))]
        min_length=min(len(sublist) for sublist in temp)
        for i in range(min_length):
            solutions.append([lenght]+[repr(x[i]) for x in temp])
        

    # Create a solver with all the constraints combined using the logical OR operator
    if constraints:
        combined_constraints = claripy.Or(*constraints)
        solver = claripy.Solver()
        solver.add(combined_constraints)
    else:
        solver=True

    return solver, solutions

# Get the solver with constraints leading to reaching the target_func
def get_solver_distance1(source,api_address,project,n,input_type,num_steps,flag):

    # Input arguments
    input_arg=input_type.args

    # Symbolic input variables
    args=[claripy.BVS("arg"+ str(i),input_arg[i].size) for i in range(len(input_arg))]
    y=[PointerWrapper(x,buffer=True) for x in args]

    #Change inputs into pointer
    p=[SimTypePointer(r) for r in input_arg]
    c=SimTypeFunction(p,input_type.returnty)
    
    # Set up symbolic variables and constraints
    state = project.factory.call_state(source, *y, prototype=c) 

    
    # Explore the program with symbolic execution
    sm = project.factory.simgr(state, save_unconstrained=True)
    sm.explore(find=api_address[0])


    # Get constraints and solutions leading to reaching the api_address
    constraints = []
    solutions=[]
    num_paths=len(sm.found)

    if num_paths>n:
        paths=sm.found[:n]
    else:
        paths=sm.found

    for i,path in enumerate(paths):
        m=math.ceil((n-i)/num_paths) #number of solution for each path
        constraints.extend(path.solver.constraints)
        temp=[path.solver.eval_upto(args[i],m, cast_to=bytes) for i in range(len(args))]
        min_length=min(len(sublist) for sublist in temp)
        for i in range(min_length):
            solutions.append([x[i].decode() for x in temp])

    # Check if the functions in 'api_address' can be reached in a max of 'num_steps' steps
    sm.move(from_stash="found", to_stash="active")
    for a in api_address[1:]:
        # Explore for a maximum of 'num_steps' steps
        sm.run(n=num_steps)
    
        # Check if the address 'a' is not found
        if not any(a in state.history.bbl_addrs for state in sm.active):
            return None, None      

    # Create a solver with all the constraints combined using the logical OR operator
    if constraints:
        combined_constraints = claripy.Or(*constraints)
        solver = claripy.Solver()
        solver.add(combined_constraints)
    else:
        solver=True

    return solver, solutions


# Get the solver with constraints leading to reaching the target_func
def get_solver(source,target,project,n,input_type):

    # Input arguments
    input_arg=input_type.args

    # Symbolic input variables
    args=[claripy.BVS("arg"+ str(i),input_arg[i].size) for i in range(len(input_arg))]
    y=[PointerWrapper(x,buffer=True) for x in args]

    #Change inputs into pointer
    p=[SimTypePointer(r) for r in input_arg]
    c=SimTypeFunction(p,input_type.returnty)
    
    # Set up symbolic variables and constraints
    state = project.factory.call_state(source, *y, prototype=c) 

    
    # Explore the program with symbolic execution
    sm = project.factory.simgr(state, save_unconstrained=True)
    sm.explore(find=target)


    # Get constraints and solutions leading to reaching the api_address
    constraints = []
    solutions=[]
    num_paths=len(sm.found)

    if num_paths>n:
        paths=sm.found[:n]
    else:
        paths=sm.found

    for i,path in enumerate(paths):
        m=math.ceil((n-i)/num_paths) #number of solution for each path
        constraints.extend(path.solver.constraints)
        temp=[path.solver.eval_upto(args[i],m, cast_to=bytes) for i in range(len(args))]
        min_length=min(len(sublist) for sublist in temp)
        for i in range(min_length):
            solutions.append([x[i].decode() for x in temp])

    # Create a solver with all the constraints combined using the logical OR operator
    if constraints:
        combined_constraints = claripy.Or(*constraints)
        solver = claripy.Solver()
        solver.add(combined_constraints)
    else:
        solver=True

    return solver, solutions


def entry_node(nodes,data,graph):
    
    start_nodes = [n for n, d in graph.in_degree() if d == 0]
    main_f=list(set(start_nodes) & set(nodes))[0]
    i=data.index[data['address']==main_f].item() # main function index
    input_type=data.loc[i,'type'] 

    return main_f,input_type


# Dataframe of functions, for each function: solver, values  
def functions_dataframe(binary_path, project, call_graph, function_data, n, steps,nodes,distance,api_address,api_type):
    
    # function 'main' of the binary
    main_f,input_type=entry_node(nodes,function_data,call_graph)

    main_solver=SolverUtility(project)
    # If 'api_address' are reachable from the main
    if distance[main_f]==1:
        s,v=main_solver.get_solver(api_address,n,input_type,binary=binary_path,num_steps=steps)
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
            s,v=get_solver(target_func,n,input_type,source=starting_address)
        
        function_data.loc[i,'solver']=s
        function_data.at[i,'values']=v
    #if function_data.loc[function_data['distance'] == 1]['solver']:
        #return 

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