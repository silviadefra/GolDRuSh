#!/usr/bin python3

from angr import Project
import networkx as nx
import matplotlib.pyplot as plt
from pandas import DataFrame
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
    function_data=DataFrame(data=d)

    # Create a subgraph for the program functions
    sub_graph = call_graph.subgraph(program_functions_addr)

    return sub_graph,program_functions,function_data,cfg


# Get functions' prototype
def get_type(project, functions,cfg):

    types=[]
    # Set up the calling convention analysis for each function
    for f in functions:
        # Variable recovery
        project.analyses.VariableRecoveryFast(f)
        
        cca = project.analyses.CallingConvention(f,cfg=cfg,analyze_callsites=True)
        types.append(cca.prototype)

    return types


# Visualize the call graph
def visualize(cfg,graph):
    pos = nx.spring_layout(graph)
    node_labels = {function: cfg.kb.functions.function(function).name for function in graph.nodes}
    nx.draw_networkx(graph, pos, with_labels=True, labels=node_labels, node_size=500, node_color='lightblue', font_size=8, font_weight='bold', width=0.2, arrows=True)
    plt.title('Call Graph')
    plt.axis('off')
    plt.show()


# Main function: General info of 'binary' (functions name, address)
def file_data(binary_path):

    # Create an angr project
    project = Project(binary_path, auto_load_libs=False)

    # Generate the call graph
    call_graph, func_addr,function_data, cfg=generate_call_graph(project)

    # Get functions' type inputs
    type_inputs=get_type(project, func_addr,cfg)
    function_data['type']=type_inputs

    # Visualize the call graph
    #visualize(cfg,call_graph) 

    return project,call_graph,function_data,func_addr


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python call_graph.py  <filename>")
        #sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    project,call_graph,function_data,func_addr=file_data(binary_path)