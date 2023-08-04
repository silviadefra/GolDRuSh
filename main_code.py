#!/usr/bin python3

import sys
from call_graph import *
from debug import *
from fitness import *
from fuzzy import *
import logging
import itertools



def main(binary,api):

    # Dataframe of functions, for each function: name, address, distance, solver, values
    num_values=2
    num_best_fit=4
    data=functions_dataframe(binary,api,num_values)
    if data is None:
        return

    list_functions=data['name'].tolist()
    func_inputs=[x.args for x in data['type'].tolist()] # the functions inputs

    # Usage example
    tests = [['7'],['ciao'], ['de9f'], ['39hnej'],['hallo']]
    num_ind=len(tests)
    exported_list=['strlen', 'strcmp']

    # Separete exported functions with the inputs from intenral functions
    exported_func=[(x,j) for x,j in zip(list_functions,func_inputs) if x in exported_list] 
    internal_func=[(x,j) for x,j in zip(list_functions,func_inputs) if x not in exported_list]

    l=[]
    i=0
    while i< 20:
        for t in tests: #TODO parallel
            # Run the binary and trace function calls with their arguments
            entries = trace_function_calls(binary, t,exported_func,internal_func)
            if not entries:
                print(f"Error: trace not found")
                return
        
            entries[0][1]=[len(t)+1]+ t #per il momento sostituisco a mano inputs del main
        
            reached_functions=[(x[0],x[1]) for x in entries if x[2]=="input"] # Functions with input values

            # Fitness function for each test
            fit,min_f=fitness_func(data,reached_functions)
            if fit==0:
                print('You reached the good function with the argument: {fun}\n'.format(fun=t))
                return
            l.append([fit,t,min_f])

        # 'num_best_fit' tests with best fitness
        l=sorted(l, key=lambda x: x[0])
        l=l[:num_best_fit]
        logging.debug('Initial population: {pop}'.format(pop=l))

        # Fuzzing
        temp_tests=fuzzy_func(l)
        temp_tests = list(k for k,_ in itertools.groupby(temp_tests)) #delete duplicate
        temp_l=[x[1] for x in l]
        tests=[x for x in temp_tests if x not in temp_l] #delete children equal to parents
        logging.debug('New generation: {new}\n'.format(new=temp_tests))
        i+=1
    logging.info('The best argument to reach the good function is {arg}\n'.format(arg=l[0][1]))
 
    
      

if __name__ == "__main__":

    logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.DEBUG)
    #logging.basicConfig(filename='solutions.log', encoding='utf-8', level=logging.DEBUG)

    if len(sys.argv) < 2:
        print("Usage: python main_code.py <target_executable> <api_call>")
        sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    # Specify the function name
    api_call = sys.argv[2]

    main(binary_path,api_call)

    