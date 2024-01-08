#!/usr/bin python3

import networkx as nx
import sys
from tree_visitor import RuleVisitor
from call_graph import file_data


# Label the nodes with the minimum path length to the target node
def nodes_distance(graph,g, trg):

    # Check that functions in 'trg' are called by the same function, if not cut the edge
    t=trg[0]
    t_parents=list(nx.predecessor(g,t,cutoff=1))[1:] #t's parents
    subgraph=graph.copy()
    for p in t_parents:
        p_children=list(nx.predecessor(graph,p,cutoff=1))[1:] 
        # For each function 'c' in 'trg', if 'c' is not child of a parent 'p' of 't', cut the edge (p,t)
        for c in trg[1:]:
            if c not in p_children:
                subgraph.remove_edge(p,t)
    
    shortest_paths = nx.shortest_path_length(subgraph, target=t)
    addresses=list(shortest_paths)

    return addresses,shortest_paths

# For each function graph distance and list of the targets 
def first_distance(api_address,function_data,call_graph,reverse_graph):
    
    # Find minimum distance between nodes and target
    nodes,distance=nodes_distance(call_graph,reverse_graph,api_address)

    if len(nodes)==1:
        return None,None,None
    
    for node in nodes:
        func=function_data.get_function_by_addr(node)
        func.set_distance(distance[node])

    for api in api_address[1:]:
        func=function_data.get_function_by_addr(api)
        func.set_distance(0)

    return nodes,distance

# Main function
def main(binary_path,rules):

    _,call_graph,function_data,_=file_data(binary_path)

    for tree in rules:
        visitor = RuleVisitor()
        visitor.visit(tree)

        nodes,distance,function_data=first_distance(visitor.api_list,function_data,call_graph)


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