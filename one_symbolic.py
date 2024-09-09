#!/usr/bin python3

import sys
from tree_visitor import RuleVisitor
from call_graph import file_data
from graph_distance import first_distance
from solver_utility import SolverUtility
from networkx import shortest_path_length
from math import inf


# Find the successors with smaller distance
def find_succ(source,graph,distance):
    elems_in_both_lists = set(distance.keys()) & set(list(graph.successors(source)))
    target_addr=[x for x in elems_in_both_lists if distance[source] > distance[x]]
    
    return target_addr

def refine_dcg(dcg,t,function_data,temp_nodes,distance):
    shortest_paths = shortest_path_length(dcg, target=t.address)
    different_nodes={k: shortest_paths[k] for k in shortest_paths.keys() & distance.keys() if shortest_paths[k]!=distance[k]}
    new_nodes= {k: shortest_paths[k] for k in shortest_paths.keys() & temp_nodes.keys()}
    new_nodes.update(different_nodes)
    for node in new_nodes:
        if new_nodes[node]!=distance[node]:
            func=function_data.get_function_by_addr(node)
            func.set_distance(new_nodes[node])

    return new_nodes, shortest_paths

# Dataframe of functions, for each function: solver, values  
def functions_dataframe(binary_path, project, function_data, n, steps,distance,api_list,visitor,dcg,tp_file):
    
    source=function_data.get_function_by_name('compileRule')
    target=function_data.get_function_by_name('parse_cert_parameter')
    input_type=source.type
    func_solver=SolverUtility(project)
    v,_=func_solver.get_solver(target.address,n,input_type,source=source.address)
    source.set_values(v)
    # temp_nodes=distance.copy()
    # flag=True
    # while flag:
    #     #TODO in parallel
    #     for key in list(temp_nodes.keys()):
    #         func=function_data.get_function_by_addr(key)
    #         if func.distance !=1:
    #             temp_nodes.pop(key, None)
    #             continue
    #         func_solver=SolverUtility(project)
    #         input_type=func.type 

    #         # Find for each node successors with smaller distance
    #         target_func=find_succ(key,dcg,distance) #forse conviene non definire la funzione e mettere tutto nel main
    #         # Get the solver with constraints leading to reaching the target_func, and values to solve them
    #         v,_=func_solver.get_solver(target_func,n,input_type,source=key)
                
    #         temp_nodes.pop(key, None)

    #         if v is None:
    #             continue
    #         elif v is False:
    #             func.set_distance(inf)
    #             # refine dcg
    #             for c in target_func:
    #                 dcg.remove_edge(key,c)
    #                 t=function_data.get_function_by_addr(c)
    #             temp_nodes,distance=refine_dcg(dcg,t,function_data,temp_nodes,distance)#,main_addr)
    #             break

    #         func.set_values(v)
    #         func.print_info()
    #     if not temp_nodes:
    #         flag=False
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