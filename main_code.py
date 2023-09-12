#!/usr/bin python3

import sys
from os import path
import logging
logging.basicConfig(format='[+] %(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
from call_graph import functions_dataframe
from debug import trace_function_calls
from fitness import fitness_func
from fuzzy import fuzzy_func
from itertools import groupby




def main(binary,api):

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
    
    #TODO
    exported_list=['strlen', 'strcmp']

    # Dataframe of functions, for each function: name, address, distance, solver, values  
    data=functions_dataframe(binary,api,num_values)
    
    # Check if the function is found in the call graph
    if data is None:
        logging.info(f"Error: '{api}' not found in the call graph.")
        return

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
                logging.worning(f"Warning: trace not found")
                return
        
            entries[0][1]=[len(t)+1]+ t #per il momento sostituisco a mano inputs del main
        
            reached_functions=[(x[0],x[1]) for x in entries if x[2]=="input"] # Functions (x[0]) and inputs (x[1])

            # Fitness function for each test
            fit=fitness_func(data,reached_functions)
            if fit==0:
                logging.info('You reached the good function with the argument: {fun}\n'.format(fun=t))
                return
            l.append([fit,t])

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
    logging.info('The best argument to reach the good function is {arg}\n'.format(arg=l[0][1]))
 
    
      

if __name__ == "__main__":

    #logging.basicConfig(format='[+] %(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG, stream=sys.stdout)
    #logging.basicConfig(filename='solutions.log', encoding='utf-8', level=logging.DEBUG)

    if len(sys.argv) < 2:
        print("Usage: python main_code.py <target_executable> <api_call>")
        sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    # Specify the function name
    api_call = sys.argv[2]

    main(binary_path,api_call)

    