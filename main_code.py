#!/usr/bin python3

import sys
from os import path
import logging
logging.basicConfig(format='[+] %(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
from symbolic import file_data,functions_dataframe
from debug import trace_function_calls
from fitness import fitness_func
from fuzzy import fuzzy_func
from grammar import parse_file
from itertools import groupby
from tree_visitor import FuncVisitor




def main(binary):

    # Check if the binary file exists
    if not path.isfile(binary):
        logging.warning(f"Error: File '{binary}' does not exist.")
        return 
    
    #TODO Parameters for the algorithm: they must be passed from the command line
    num_values=2      #Number of solutions of the solver
    num_best_fit=8    #Number of individual in the population
    num_generations=100 
    tests = [['2358'],['35'], ['9124'], ['34'],['14'],['82375'],['2'],['1982674'],['736']]  #Our tests
    len_cache=100                #lenght cache for fitness
    rules_file="rules.txt"
    steps=5

    #TODO: non c'è bisogno di farlo ogni volta, se va bene il file 
    trees = parse_file(rules_file)
    
    #TODO
    exported_list=['strlen', 'strcmp']

    # General info of 'binary' (functions name, address)
    project,call_graph,function_data,func_addr=file_data(binary)
    #logging.info(function_data.values.tolist())

    # Iterate through the 'tree' to find the 'api' subtree.
    for num_tree,tree in enumerate(trees.children):
        visitor = FuncVisitor()
        visitor.visit(tree)

        # Now, 'visitor.func_list' contains a list of 'func' elements.
        logging.info(visitor.api_list)

        # Dataframe of functions, for each function: distance, solver, values  
        data=functions_dataframe(binary,project,call_graph,function_data,func_addr,num_values,visitor.api_list,steps)
    
        # Check if the function is found in the call graph
        if data is None:
            #logging.info(f"Error: '{api}' not found in the call graph.")
            continue

        logging.info(data.values.tolist())

        list_functions=data['name'].tolist()
        func_inputs=[x.args for x in data['type'].tolist()] # the functions inputs

        # Separete exported functions with the inputs from intenral functions
        exported_func=[(x,j) for x,j in zip(list_functions,func_inputs) if x in exported_list] 
        internal_func=[(x,j) for x,j in zip(list_functions,func_inputs) if (x,j) not in exported_func]

        l=[]
        i=0
        while i< num_generations:
            for t in tests: #TODO parallel
            
                # Run the binary and trace function calls with their arguments
                entries = trace_function_calls(binary, t,exported_func,internal_func)
                if not entries:
                    logging.warning(f"Warning: trace not found")
                    return
        
                entries[0][1]=[len(t)+1]+ t #per il momento sostituisco a mano inputs del main
        
                reached_functions=[(x[0],x[1]) for x in entries if x[2]=="input"] # Functions (x[0]) and inputs (x[1])

                # Fitness function for each test
                fit=fitness_func(data,reached_functions)
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
            temp_tests.sort()
            temp_tests = list(k for k,_ in groupby(temp_tests)) #delete duplicate
            temp_l=[x[1] for x in l]
            tests=[x for x in temp_tests if x not in temp_l] #delete children equal to parents
            logging.info('New generation: {new}\n'.format(new=temp_tests))
            i+=1
        if fit!=0:
            logging.info('The best arguments for rule {num} are: {arg}\n'.format(num=num_tree,arg=l[0][1]))
 
    
      

if __name__ == "__main__":

    #logging.basicConfig(format='[+] %(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG, stream=sys.stdout)
    #logging.basicConfig(filename='solutions.log', encoding='utf-8', level=logging.DEBUG)

    if len(sys.argv) < 1:
        print("Usage: python main_code.py <target_executable>")
        sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    # Specify the function name
    #api_call = sys.argv[2]

    main(binary_path)

    