#!/usr/bin python3

from angr import Project, PointerWrapper
from angr.sim_type import SimTypeFunction, SimTypePointer
import networkx as nx
import matplotlib.pyplot as plt
import claripy
from pandas import DataFrame
import math


# Generate call graph
def generate_call_graph(project):

    # Set up the call graph analysis
    cfg = project.analyses.CFGEmulated(keep_state=True)

    # Retrieve the call graph
    call_graph = cfg.functions.callgraph
    
    # Filter out internal functions and keep only the explicitly defined functions
    defined_functions = project.kb.functions.values()
    program_functions = []
    program_functions_addr=[]
    program_functions_name=[]
    
    for function in defined_functions:
        if not function.is_simprocedure:
            program_functions_addr.append(function.addr)
            program_functions.append(function)
            program_functions_name.append(function.name)

    d={'name': program_functions_name,'address': program_functions_addr,'distance':[math.inf]*len(program_functions_addr), 'solver': [[None]]*len(program_functions_addr),  'values': [[None]]*len(program_functions_addr)}
    function_data=DataFrame(data=d)

    # Create a subgraph for the program functions
    sub_graph = call_graph.subgraph(program_functions_addr)

    return (sub_graph, program_functions,function_data,cfg)


# Find the address of the target
def find_func_address(target,func_addr):
    target_address = None

    #TODO without for loop
    for function in func_addr:
        if function.name == target:
                target_address = function.addr

    return target_address


# Label the nodes with the minimum path length to the target node
def nodes_distance(graph, trg):

    shortest_paths = nx.shortest_path_length(graph, target=trg)
    addresses=list(shortest_paths)
    addresses.reverse()

    return (addresses,shortest_paths)


# Get functions' type inputs
def get_type(project, functions,cfg):

    types=[]
    # Set up the calling convention analysis for each function
    for f in functions:
        # Vriable recovery
        project.analyses.VariableRecoveryFast(f)
        
        cca = project.analyses.CallingConvention(f,cfg=cfg,analyze_callsites=True)
        types.append(cca.prototype)
        
    return types
  

# Find the successors with smaller distance
def find_succ(source,graph,addr,distance):
    
    elems_in_both_lists = set(addr) & set(list(graph.successors(source)))
    target_addr=[x for x in elems_in_both_lists if distance[source] > distance[x]]
    
    
    return target_addr

# Get solver and values to reach the target_func of the main
def get_main_solver(target,project,n,binary_path,input):    #da sistemare

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

# Visualize the call graph
def visualize(cfg,graph):
    pos = nx.spring_layout(graph)
    node_labels = {function: cfg.kb.functions.function(function).name for function in graph.nodes}
    nx.draw_networkx(graph, pos, with_labels=True, labels=node_labels, node_size=500, node_color='lightblue', font_size=8, font_weight='bold', width=0.2, arrows=True)
    plt.title('Call Graph')
    plt.axis('off')
    plt.show()



# Main function
def functions_dataframe(binary_path, api_call,n):

    # Create an angr project
    project = Project(binary_path, auto_load_libs=False)

    # Generate the call graph
    (call_graph, func_addr,function_data, cfg)=generate_call_graph(project)

    # Find the address of the function
    api_address=find_func_address(api_call,func_addr) 
    # Check if the function is found in the call graph
    if api_address is None:
        return
    
    # Find minimum distance between nodes and target
    (nodes,distance)=nodes_distance(call_graph,api_address)

    # Get functions' type inputs
    type_inputs=get_type(project, func_addr,cfg)
    function_data['type']=type_inputs

    
    main_f=nodes[0]# Main function
    i=function_data.index[function_data['address']==main_f].item() # main function index
    function_data.loc[i,'distance']=distance[main_f] # main function distance
    input_type=function_data.loc[i,'type']
    
    # Find successors with smaller distance
    target_func=find_succ(main_f,call_graph,nodes,distance)

    # Get the solver with constraints leading to reaching the target_func, and values to solve them
    s,v=get_main_solver(target_func,project,n,binary_path,input_type)
    function_data.loc[i,'solver']=s
    function_data.at[i,'values']=v

    addr=nodes[1:].copy() 
    #TODO in parallel
    for starting_address in addr:
        i=function_data.index[function_data['address']==starting_address].item()
        function_data.loc[i,'distance']=distance[starting_address]
        input_type=function_data.loc[i,'type']
        if distance[starting_address]==0:
            continue
        
        # Find for each node successors with smaller distance
        target_func=find_succ(starting_address,call_graph,addr,distance) #forse conviene non definire la funzione e mettere tutto nel main
        
        # Get the solver with constraints leading to reaching the target_func, and values to solve them
        s,v=get_solver(starting_address,target_func,project,n,input_type)
        function_data.loc[i,'solver']=s
        function_data.at[i,'values']=v

    # Visualize the call graph
    #visualize(cfg,call_graph) 

    return function_data

#if __name__ == "__main__":

    #if len(sys.argv) < 2:
        #print("Usage: python call_graph.py <target_executable> <api_call>")
        #sys.exit(1)

    # Path to the binary program
    #binary_path = sys.argv[1]

    # Specify the function name
    #api_call = sys.argv[2]

    #num_values=2

    #main(binary_path,api_call,num_values)

