#!/usr/bin python3

import sys
from tree_visitor import RuleVisitor
from call_graph import file_data
from graph_distance import first_distance
from solver_utility import SolverUtility
from networkx import shortest_path_length


# Find the successors with smaller distance
def find_succ(source,graph,addr,distance):
    elems_in_both_lists = set(addr) & set(list(graph.successors(source)))
    target_addr=[x for x in elems_in_both_lists if distance[source] > distance[x]]
    
    return target_addr


def entry_node(nodes,data,graph):
    start_nodes = [n for n, d in graph.in_degree() if d == 0]
    main_f=list(set(start_nodes) & set(nodes))[0]
    func=data.get_function_by_addr(main_f)
    input_type=func.type 

    return main_f,input_type,func


def refine_dcg(dcg,t,distance,function_data,temp_nodes,main_f):
    shortest_paths = shortest_path_length(dcg, target=t)
    different_keys=[k for k in shortest_paths if shortest_paths[k] != distance[k]]
    for node in different_keys:
        func=function_data.get_function_by_addr(node)
        func.set_distance(shortest_paths[node])
    nodes=temp_nodes + [k for k in different_keys if k not in temp_nodes]
    nodes.remove(main_f)

    return nodes



# Dataframe of functions, for each function: solver, values  
def functions_dataframe(binary_path, project, call_graph, function_data, n, steps,nodes,distance,api_address,api_type,visitor,register_inputs,dcg):
    
    # function 'main' of the binary
    main_f,input_type,func=entry_node(nodes,function_data,call_graph)

    main_solver=SolverUtility(project)
    # If 'api_address' are reachable from the main
    if distance[main_f]==1:
        v,a=main_solver.get_solver(api_address,n,input_type,binary=binary_path,num_steps=steps,api_type=api_type,visitor=visitor,register_inputs=register_inputs)         
        f_last_api=function_data.get_function_by_addr(api_address[-1])
        f_last_api.set_args(a)
    else:
        # Find successors with smaller distance
        target_func=find_succ(main_f,call_graph,nodes,distance)
        # Get the solver with constraints leading to reaching the target_func, and values to solve them
        v,_=main_solver.get_solver(target_func,n,input_type,binary=binary_path)

    if v is None:
            return
    
    func.set_values(v)

    nodes.remove(main_f)
    temp_nodes=nodes.copy()
    flag=True
    while flag:
        #TODO in parallel
        for starting_address in nodes:
            print(nodes)
            func_solver=SolverUtility(project)
            func=function_data.get_function_by_addr(starting_address)
            input_type=func.type 
            if func.distance==1:
                v,a=func_solver.get_solver(api_address,n,input_type,source=starting_address,num_steps=steps,api_type=api_type,visitor=visitor,register_inputs=register_inputs)
                f_last_api=function_data.get_function_by_addr(api_address[-1])
                f_last_api.set_args(a)
            else:
                print(func.name)
                # Find for each node successors with smaller distance
                target_func=find_succ(starting_address,call_graph,nodes,distance) #forse conviene non definire la funzione e mettere tutto nel main
                # Get the solver with constraints leading to reaching the target_func, and values to solve them
                v,_=func_solver.get_solver(target_func,n,input_type,source=starting_address)
                print(v)
                
            
            if v is None:
                    return
            elif v is False:
                # refine dcg
                for c in target_func:
                    dcg.remove_edge(func.address,c)
                nodes=refine_dcg(dcg,api_address[0],distance,function_data,temp_nodes,main_f)    
                break
                
            temp_nodes.remove(starting_address)
            func.set_values(v)
        flag=False

    return True


# Main function
def main(binary_path,rules):

    #TODO
    num_values=2
    steps=5

    project,call_graph,function_data,func_addr=file_data(binary_path)

    for tree in rules:
        visitor = RuleVisitor()
        visitor.visit(tree)

        nodes,distance,api_address,api_type,functions_data=first_distance(func_addr,visitor.api_list,function_data,call_graph)

        functions_data=functions_dataframe(binary_path,project,call_graph,function_data,num_values,steps,nodes,distance,api_address,api_type,visitor)

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