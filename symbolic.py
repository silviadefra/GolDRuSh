#!/usr/bin python3

import sys
from tree_visitor import FuncVisitor
from call_graph import file_data
from graph_distance import first_distance
from solver_utility import SolverUtility


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
def functions_dataframe(binary_path, project, call_graph, function_data, n, steps,nodes,distance,api_address,api_type,par_list):
    
    # function 'main' of the binary
    main_f,input_type,i=entry_node(nodes,function_data,call_graph)

    main_solver=SolverUtility(project)
    # If 'api_address' are reachable from the main
    if distance[main_f]==1:
        s,v=main_solver.get_solver(api_address,n,input_type,binary=binary_path,num_steps=steps,api_type=api_type,par_list=par_list)
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
            s,v=func_solver.get_solver(api_address,n,input_type,source=starting_address,num_steps=steps,api_type=api_type,par_list=par_list)
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

        functions_data=functions_dataframe(binary_path,project,call_graph,function_data,num_values,steps,nodes,distance,api_address,api_type,visitor.par_list)

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