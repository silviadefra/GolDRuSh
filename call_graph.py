#!/usr/bin python3

from angr import Project
import networkx as nx
import matplotlib.pyplot as plt
import sys
from functionclass import ProgramFunction, FunctionList
import logging


# Generate call graph
def generate_call_graph(project):
    # Set up the call graph analysis
    cfg = project.analyses.CFGEmulated()
    #cfg = project.analyses.CFGFast()

    # Retrieve the call graph
    call_graph = cfg.functions.callgraph
    
    # Filter out internal functions and keep only the explicitly defined functions
    defined_functions = cfg.functions.values()
    program_functions = []
    program_functions_addr=[]
    
    for function in defined_functions:

        if not function.is_simprocedure and function.block_addrs_set and function.startpoint is not None:
            # Variable recovery
            v=project.analyses.VariableRecoveryFast(function)
            # variable_manager = v.variable_manager[function.addr]
            # print(variable_manager.get_variables())
            # Set up the calling convention analysis for each function
            cca = project.analyses.CallingConvention(function,cfg=cfg,analyze_callsites=True)
            # vm=cca._variable_manager[function.addr]
            # print(function)
            # print(vm.input_variables())
            if cca.prototype is None:
                return None,None,None
                #continue
            program_functions.append(ProgramFunction(function,cca))
            program_functions_addr.append(function.addr)


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
    project = Project(binary_path)

    # Generate the call graph
    call_graph, func_addr, register_input=generate_call_graph(project)
    if call_graph is None:
        return None,None,None,None

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