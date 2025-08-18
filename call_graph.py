#!/usr/bin python3

from angr import Project
import networkx as nx
import matplotlib.pyplot as plt
import sys
from functionclass import ProgramFunction, FunctionList


# Generate call graph
def generate_call_graph(project,binary_type):
    # Set up the call graph analysis
    if binary_type:
        cfg = project.analyses.CFGEmulated()
    else:
        cfg = project.analyses.CFGFast()

    # Retrieve the call graph
    call_graph = cfg.functions.callgraph
    
    # Filter out internal functions and keep only the explicitly defined functions
    defined_functions = cfg.functions.values()
    program_functions = []
    program_functions_addr=[]
    #visualize(cfg,call_graph)
    
    for function in defined_functions:
        if not function.is_simprocedure and function.block_addrs_set and function.startpoint is not None:
            # Variable recovery
            try:
                project.analyses.VariableRecoveryFast(function)
            except AttributeError as e:
                continue
            cca = project.analyses.CallingConvention(function,cfg=cfg,analyze_callsites=True) # Set up the calling convention analysis for each function
            if cca.prototype is None:
                continue
            # Set up the calling convention analysis for each function
            program_functions.append(ProgramFunction(function,cca))
            program_functions_addr.append(function.addr)

    functions=FunctionList(program_functions)

    # Create a subgraph for the program functions
    sub_graph = call_graph.subgraph(program_functions_addr)

    # Visualize the call graph
    #visualize(cfg,sub_graph) 

    return sub_graph,functions

# Visualize the call graph
def visualize(cfg,graph):
    pos = nx.spring_layout(graph)
    node_labels = {function: cfg.kb.functions.function(function).name for function in graph.nodes}
    nx.draw_networkx(graph, pos, with_labels=True, labels=node_labels, node_size=500, node_color='lightblue', font_size=8, font_weight='bold', width=0.2, arrows=True)
    plt.title('Call Graph')
    plt.axis('off')
    plt.show()


# Main function: General info of 'binary' (functions name, address)
def file_data(binary_path,binary_type):
    # Create an angr project
    project = Project(binary_path, auto_load_libs=False, use_sim_procedures = True)

    # Generate the call graph
    call_graph, func_addr=generate_call_graph(project,binary_type)
    if call_graph is None:
        return None,None,None

    return project,call_graph,func_addr


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python call_graph.py  <filename>")
        #sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    project,call_graph,func_addr=file_data(binary_path,1)