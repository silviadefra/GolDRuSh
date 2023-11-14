#!/usr/bin python3

import sys
from os import path
import logging
logging.basicConfig(format='[+] %(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
from call_graph import file_data
from graph_distance import first_distance
from symbolic import functions_dataframe
from debug import trace_function_calls
from fitness import fitness_func
from fuzzy import fuzzy_func
from grammar import parse_file
from itertools import groupby
from tree_visitor import FuncVisitor


# Separete exported functions with the inputs from intenral functions
def separete_func(list_functions,prototype,exported_list):

    func_inputs=[x.args for x in prototype]

    exported_func=[(x,j) for x,j in zip(list_functions,func_inputs) if x in exported_list] 
    internal_func=[(x,j) for x,j in zip(list_functions,func_inputs) if (x,j) not in exported_func]

    return exported_func,internal_func


def del_duplicate(temp,l):

    temp = list(k for k,_ in groupby(temp)) #delete duplicate
    temp_l=[x[1] for x in l]
    tests=[x for x in temp if x not in temp_l] #delete children equal to parents

    return tests


def main(binary):
    
    #TODO Parameters for the algorithm: they must be passed from the command line
    num_values=2      #Number of solutions of the solver
    num_best_fit=8    #Number of individual in the population
    num_generations=100 
    tests = [['2358', 'ciao'],['35'], ['9124'], ['34'],['14'],['82375'],['2'],['1982674'],['736']]  #Our tests
    len_cache=100                #lenght cache for fitness
    rules_file="rules.txt"
    steps=5

    #TODO: non c'è bisogno di farlo ogni volta, se va bene il file 
    trees = parse_file(rules_file)
    
    #TODO
    exported_list=['strlen', 'strcmp']

    # General info of 'binary' (functions name, address)
    project,call_graph,function_data,func_addr=file_data(binary)

    # Iterate through the 'tree' to find the 'api' subtree.
    for num_tree,tree in enumerate(trees.children):
        visitor = FuncVisitor()
        visitor.visit(tree)  # Now, 'visitor.api_list' contains a list of 'api' elements.

        # For each function graph distance and list of the targets 
        nodes,distance,api_address,api_type,data=first_distance(func_addr,visitor.api_list,function_data,call_graph)

        # Dataframe of functions, for each function: solver, values
        data=functions_dataframe(binary_path,project,call_graph,function_data,num_values,steps,nodes,distance,api_address,api_type)
        # Check if the function is found in the call graph
        if data is None:
            continue

        logging.debug(data.values.tolist())

        # Separete exported functions from intenral functions
        exported_func,internal_func=separete_func(data['name'].tolist(),data['type'].tolist(),exported_list)
        
        l=[]
        i=0
        while i< num_generations:
            for t in tests: #TODO parallel
            
                # Run the binary and trace function calls with their arguments
                entries = trace_function_calls(binary, t,exported_func,internal_func)
                if not entries:
                    logging.warning(f"Warning: trace not found")
                    return
                logging.info('here')
                entries[0][1]=[len(t)+1]+ t #per il momento sostituisco a mano inputs del main
        
                reached_functions=[(x[0],x[1]) for x in entries if x[2]=="input"] # Functions (x[0]) and inputs (x[1])
    
                # Fitness function for each test
                fit=fitness_func(data,reached_functions,project)
                if fit==0:
                    logging.info('You found rule {num} with arguments: {fun}\n'.format(num=num_tree,fun=t))
                    break
                l.append([fit,t])
            
            if fit==0:
                break

            # 'num_best_fit' tests with best fitness
            l=sorted(l, key=lambda x: (x[0], len(str(x[0]).split('.')[1])))
            l=l[:len_cache]
            pop=l[:num_best_fit]
            logging.info('Initial population: {pop}'.format(pop=pop))

            # Fuzzing
            temp_tests=fuzzy_func(pop)
            logging.info('New generation: {new}\n'.format(new=temp_tests))

            # Delete duplicate
            tests=del_duplicate(temp_tests.sort(),l)
            
            i+=1
        if fit!=0:
            logging.info('The best arguments for rule {num} are: {arg}\n'.format(num=num_tree,arg=l[0][1]))
 
    

if __name__ == "__main__":

    #logging.basicConfig(filename='solutions.log', encoding='utf-8', level=logging.DEBUG)

    if len(sys.argv) < 1:
        print("Usage: python main_code.py <target_executable>")
        sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    # Check if the binary file exists
    if not path.isfile(binary_path):
        logging.warning(f"Error: File '{binary_path}' does not exist.")

    main(binary_path)

    