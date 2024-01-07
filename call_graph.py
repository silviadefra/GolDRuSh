#!/usr/bin python3

from angr import Project
import networkx as nx
import matplotlib.pyplot as plt
import sys
from functionclass import ProgramFunction, FunctionList



# Generate call graph
def generate_call_graph(project):

    # Set up the call graph analysis
    cfg = project.analyses.CFGEmulated(keep_state=True)
    #cfg = project.analyses.CFGFast()

    # Retrieve the call graph
    call_graph = cfg.functions.callgraph
    
    # Filter out internal functions and keep only the explicitly defined functions
    defined_functions = project.kb.functions.values()
    program_functions = []
    program_functions_addr=[]
    
    for function in defined_functions:
        if not function.is_simprocedure:
            program_functions_addr.append(function.addr)
            # Variable recovery
            project.analyses.VariableRecoveryFast(function)
            # Set up the calling convention analysis for each function
            cca = project.analyses.CallingConvention(function,cfg=cfg,analyze_callsites=True)
            program_functions.append(ProgramFunction(function,cca))
    functions=FunctionList(program_functions)

    register_input=get_register(cca)

    # Create a subgraph for the program functions
    sub_graph = call_graph.subgraph(program_functions_addr)

    return sub_graph,functions,register_input


# Inputs register name and position
def get_register(cca):
    
    register_inputs=[]    
    for regnum in cca.cc.arch.argument_registers:
        register_inputs.append([cca.cc.arch.argument_register_positions[regnum],cca.cc.arch.register_names[regnum]])
    register_inputs=sorted(register_inputs,key=lambda x:x[0])
    register_inputs=[x[1] for x in register_inputs]

    return register_inputs


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
    call_graph, func_addr, register_input=generate_call_graph(project)

    # Visualize the call graph
    #visualize(cfg,call_graph) 

    return project,call_graph,func_addr,register_input


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python call_graph.py  <filename>")
        #sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    project,call_graph,function_data,func_addr,register_input=file_data(binary_path)