#!/usr/bin python3

import sys
from tree_visitor import RuleVisitor
from call_graph import file_data
from graph_distance import first_distance
from solver_utility import SolverUtility
from networkx import shortest_path_length


# Find the successors with smaller distance
def find_succ(source,graph,distance):
    elems_in_both_lists = set(distance.keys()) & set(list(graph.successors(source)))
    target_addr=[x for x in elems_in_both_lists if distance[source] > distance[x]]
    
    return target_addr

def refine_dcg(dcg,t,distance,function_data,temp_nodes,main_f):
    shortest_paths = shortest_path_length(dcg, target=t.address)
    different_keys=[k for k in shortest_paths if shortest_paths[k] != distance[k]]
    for node in different_keys:
        func=function_data.get_function_by_addr(node)
        func.set_distance(shortest_paths[node])
    nodes=temp_nodes + [k for k in different_keys if k not in temp_nodes]
    nodes.remove(main_f)

    return nodes

# Dataframe of functions, for each function: solver, values  
def functions_dataframe(binary_path, project, call_graph, function_data, n, steps,distance,api_list,visitor,dcg,tp_file):
    
    if tp_file:
        # function 'main' of the binary
        func=function_data.get_function_by_name('main')
        main_addr=func.address
        input_type=func.type
        main_solver=SolverUtility(project)
        # If 'api_address' are reachable from the main
        if distance[main_addr]==1:
            v,a=main_solver.get_solver(api_list,n,input_type,binary=binary_path,num_steps=steps,visitor=visitor)         
            f_last_api=api_list[-1]
            f_last_api.set_args(a)
        else:
            # Find successors with smaller distance
            target_func=find_succ(main_addr,call_graph,distance)
            # Get the solver with constraints leading to reaching the target_func, and values to solve them
            v,_=main_solver.get_solver(target_func,n,input_type,binary=binary_path)

        if v is None:
            return
        
        func.set_values(v)
        func.print_info()

        distance.pop(func.address, None)
    temp_nodes=distance.copy()
    flag=True
    while flag:
        #TODO in parallel
        for key in distance:
            func_solver=SolverUtility(project)
            func=function_data.get_function_by_addr(key)
            input_type=func.type 
            if func.distance==1:
                v,a=func_solver.get_solver(api_list,n,input_type,source=key,num_steps=steps,visitor=visitor)
                f_last_api=api_list[-1]
                f_last_api.set_args(a)
            else:
                # Find for each node successors with smaller distance
                target_func=find_succ(key,call_graph,distance) #forse conviene non definire la funzione e mettere tutto nel main
                # Get the solver with constraints leading to reaching the target_func, and values to solve them
                v,_=func_solver.get_solver(target_func,n,input_type,source=key)
                
            
            if v is None:
                return
            elif v is False:
                # refine dcg
                for c in target_func:
                    dcg.remove_edge(func.address,c)
                distance=refine_dcg(dcg,api_list[0],distance,function_data,temp_nodes,main_addr)    
                break
                
            temp_nodes.pop(key, None)
            func.set_values(v)
            func.print_info()
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

        nodes,distance,api_list,functions_data=first_distance(func_addr,visitor.api_list,function_data,call_graph)

        functions_data=functions_dataframe(binary_path,project,call_graph,function_data,num_values,steps,nodes,distance,api_list,visitor)

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