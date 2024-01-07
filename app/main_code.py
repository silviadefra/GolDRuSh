#!/usr/bin python3

import sys
from os import path
import logging
logging.basicConfig(format='[+] %(asctime)s %(levelname)s: %(message)s', level=logging.WARNING)
from app.call_graph import file_data
from app.graph_distance import first_distance
from app.symbolic import functions_dataframe
from app.debug import trace_function_calls
from app.fitness import fitness_func
from app.fuzzy import fuzzy_func
from app.grammar import parse_file
from app.tree_visitor import RuleVisitor
from itertools import groupby


# Find the address of the target
def find_func(target,func_data):

    func=func_data.get_function_by_name(target)
    if func is None:
        return None
    target_address = func.address
    api_prototype=func.type

    return [target_address,api_prototype]


def rules_api_list(api_list,function_data):
    # Find the address of the 'api_list'
    api=[find_func(x,function_data) for x in api_list]
    # Check if the functions are found in the call graph
    if None in api:
        return None,None
    
    api_address=[x[0] for x in api]
    api_type=[x[1] for x in api]
    
    return api_address,api_type


# Separete exported functions with the inputs from intenral functions
def separete_func(data,exported_list):
    list_functions=data.get_names()
    prototypes=data.get_prototypes()
    func_inputs=[x.args for x in prototypes]

    exported_func=[(x,j) for x,j in zip(list_functions,func_inputs) if x in exported_list] 
    internal_func=[(x,j) for x,j in zip(list_functions,func_inputs) if (x,j) not in exported_func]

    return exported_func,internal_func


def gen_pop(l,num_best_fit,len_cache):
    l=sorted(l, key=lambda x: (x[0], len(str(x[0]).split('.')[1])))
    l=l[:len_cache]
    pop=l[:num_best_fit]

    return pop,l


def del_duplicate(temp,l):
    temp.sort()
    temp = list(k for k,_ in groupby(temp)) #delete duplicate
    temp_l=[x[1] for x in l]
    tests=[x for x in temp if x not in temp_l] #delete children equal to parents

    return tests


def main(binary):
    
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
    project,call_graph,function_data,register_inputs=file_data(binary)
    #logging.info(function_data.values.tolist())

    # Iterate through the 'tree' to find the 'api' subtree.
    for num_tree,tree in enumerate(trees.children):
        visitor = RuleVisitor()
        visitor.visit(tree)  # Now, 'visitor.api_list' contains a list of 'api' elements.

        api_address,api_type=rules_api_list(visitor.api_list,function_data)
        # Check if the function is found in the call graph
        if api_address is None:
            continue

        # For each function graph distance and list of the targets
        nodes,distance,data=first_distance(api_address,function_data,call_graph)
        # Check if the function is found in the call graph
        if nodes is None:
            continue

        # Dataframe of functions, for each function: solver, values
        data=functions_dataframe(binary_path,project,call_graph,function_data,num_values,steps,nodes,distance,api_address,api_type,visitor,register_inputs)
        # Check if the function is found in the call graph
        if data is None:
            continue

        #data.print_function_info()

        # Separete exported functions from intenral functions
        exported_func,internal_func=separete_func(data,exported_list)
        
        # Only functions with distance =! infinity
        df=data.remove_functions_with_infinity_distance()
        
        l=[]
        i=0
        while i< num_generations:
            for t in tests: #TODO parallel
            
                # Run the binary and trace function calls with their arguments
                entries = trace_function_calls(binary, t,exported_func,internal_func)
                if not entries:
                    logging.warning(f"Warning: trace not found")
                    return
        
                reached_functions=[(x[0],x[1]) for x in entries if x[2]=="input"] # Functions (x[0]) and inputs (x[1])
    
                # Fitness function for each test
                fit=fitness_func(df,reached_functions)
                if fit==0:
                    logging.warning('You found rule {num} with arguments: {fun}\n'.format(num=num_tree+1,fun=t))
                    break
                l.append([fit,t])
            
            if fit==0:
                break

            # 'num_best_fit' tests with best fitness
            pop,l=gen_pop(l,num_best_fit,len_cache)
            logging.warning('Initial population: {pop}'.format(pop=pop))

            # Fuzzing
            temp_tests=fuzzy_func(pop)
            logging.warning('New generation: {new}\n'.format(new=temp_tests))

            # Delete duplicate
            tests=del_duplicate(temp_tests,l)
            
            i+=1
        if fit!=0:
            logging.warning('The best arguments for rule {num} are: {arg}\n'.format(num=num_tree+1,arg=l[0][1]))
 
    

if __name__ == "__main__":

    #logging.basicConfig(filename='solutions.log', encoding='utf-8', level=logging.DEBUG)

    if len(sys.argv) < 1:
        logging.info("Usage: python main_code.py <target_executable>")
        sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    # Check if the binary file exists
    if not path.isfile(binary_path):
        logging.warning(f"Error: File '{binary_path}' does not exist.")

    main(binary_path)

    
