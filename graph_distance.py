#!/usr/bin python3

import networkx as nx
import sys
from tree_visitor import FuncVisitor
from call_graph import file_data


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

    # Check that functions in 'trg' are called by the same function, if not cut the edge
    t=trg[0]
    g=graph.reverse(copy=False)
    t_parents=list(nx.predecessor(g,t,cutoff=1))[1:] #t's parents
    for p in t_parents:
        p_children=list(nx.predecessor(graph,p,cutoff=1))[1:]
        
        # For each function 'c' in 'trg', if 'c' is not child of a parent 'p' of 't', cut the edge (p,t)
        for c in trg[1:]:
            if c not in p_children:
                graph.remove_edge(p,t)
    
    shortest_paths = nx.shortest_path_length(graph, target=t)
    addresses=list(shortest_paths)

    return addresses,shortest_paths

# For each function graph distance and list of the targets 
def first_distance(func_addr,api_list,function_data,call_graph):
    # Find the address of the 'api_list'
    api_address=[find_func_address(x,func_addr) for x in api_list]
    # Check if the functions are found in the call graph
    if None in api_address:
        return
    
    api_type=[]
    for x in api_address:
        i=function_data.index[function_data['address']==x].item()
        api_type.append(function_data.loc[i,'type'])


    # Find minimum distance between nodes and target
    nodes,distance=nodes_distance(call_graph,api_address)

    if len(nodes)==1:
        return
    
    for node in nodes:
        i=function_data.index[function_data['address']==node].item()
        function_data.loc[i,'distance']=distance[node]
    
    return nodes,distance,api_address,api_type,function_data

# Main function
def main(binary_path,rules):

    _,call_graph,function_data,func_addr=file_data(binary_path)

    for tree in rules:
        visitor = FuncVisitor()
        visitor.visit(tree)

        nodes,distance,api_address,api_type,function_data=first_distance(func_addr,visitor.api_list,function_data,call_graph)


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

    main(binary_path,rules)