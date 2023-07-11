#!/usr/bin python3

import angr
import networkx as nx
import matplotlib.pyplot as plt
import os
import claripy
import pandas as pd
import math
import sys


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
    function_data=pd.DataFrame(data=d)

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

    # Check if the function is found in the call graph
    if target_address is None:
        print(f"Error: '{target}' not found in the call graph.")
        return None

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
        vr = project.analyses.VariableRecoveryFast(f)
        
        cca = project.analyses.CallingConvention(f,cfg=cfg,analyze_callsites=True)
        types.append(cca.prototype)
        
    return types
  

# Find the successors with smaller distance
def find_succ(source,graph,addr,distance):
    
    elems_in_both_lists = set(addr) & set(list(graph.successors(source)))
    target_addr=[x for x in elems_in_both_lists if distance[source] > distance[x]]
    
    
    return target_addr


# Get the solver with constraints leading to reaching the target_func
def get_solver(source,target,project,n,binary_path):

    # Symbolic input variables
    x= claripy.BVS("x", 16)
    y = claripy.BVS("y", 7*8) # 100 bytes
    
    # Set up symbolic variables and constraints
    state= project.factory.blank_state(addr=source)   #,args=[binary_path,y]
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    # Assign the symbolic input to the RDI register for the main function
    state.regs.rdi = x 
    state.memory.store(source + 4, y)
    
    # Explore the program with symbolic execution
    sm = project.factory.simgr(state)
    sm.explore(find=target)

    # Get constraints and solutions leading to reaching the api_address
    constraints = []
    sol=[]
    for path in sm.found:
        constraints.extend(path.solver.constraints)
        sol.append([path.solver.eval(y)])
        s=path.solver.eval(y, cast_to=bytes)
        print(s)
        print(s.decode())

    


    # Create a solver with all the constraints combined using the logical OR operator
    if constraints:
        combined_constraints = claripy.Or(*constraints)
        solver = claripy.Solver()
        solver.add(combined_constraints)
        solutions=solver.eval(y,n)
        solutions=[[s] for s in solutions]
        #print(solutions)
    else:
        solver=True
        solutions=[]

    # Convert solutions from bytes to strings
    #solutions_as_strings = [sol.decode('utf-8') for sol in solutions]
    #print(solutions_as_strings)
    return solver, sol #solutions

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

    # Check if the binary file exists
    if not os.path.isfile(binary_path):
        print(f"Error: File '{binary_path}' does not exist.")
        return 

    # Create an angr project
    project = angr.Project(binary_path, auto_load_libs=False)

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

    addr=nodes.copy() #non necessario
    #TODO in parallel
    for starting_address in nodes:
        i=function_data.index[function_data['address']==starting_address].item()
        function_data.loc[i,'distance']=distance[starting_address]
        if distance[starting_address]==0:
            continue
        addr.remove(starting_address)
        
        # Find for each node successors with smaller distance
        target_func=find_succ(starting_address,call_graph,addr,distance) #forse conviene non definire la funzione e mettere tutto nel main
        
        # Get the solver with constraints leading to reaching the target_func, and values to solve them
        s,v=get_solver(starting_address,target_func,project,n,binary_path)
        function_data.loc[i,'solver']=s
        function_data.at[i,'values']=v
    print(function_data.values.tolist())

    # Visualize the call graph
    #visualize(cfg,call_graph) #se eliminamo questa funzione possiamo togliere cfg da funzione generate_call-graph

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

