#!/usr/bin python3

import sys
from os import path
import networkx as nx
import logging
from math import inf
logging.basicConfig(filename='solution/solutions.log',format='%(asctime)s : %(message)s', encoding='utf-8', level=logging.WARNING)
#logging.basicConfig(format='[+] %(asctime)s %(levelname)s: %(message)s', level=logging.WARNING)
from argparse import ArgumentParser
from call_graph import file_data
from parse_curl_symbolic import functions_dataframe
from debug import trace_function_calls
from parse_curl_fitness import fitness_func
from fuzzy import fuzzy_func
from grammar import parse_file
from tree_visitor import RuleVisitor
from itertools import groupby
from random import sample,choices
from string import ascii_letters,digits
from csv import writer


# For each function graph distance and list of the targets 
def first_distance(function_data,call_graph,target_f):
    
    # Find minimum distance between nodes and target
    trg = function_data.get_function_by_name(target_f)
    t=trg.address
    distance = nx.shortest_path_length(call_graph, target=t)

    if len(distance)==1:
        return None,None
    
    for key in list(distance.keys()):
        func=function_data.get_function_by_addr(key)
        func.set_distance(distance[key])

    
    func=function_data.get_function_by_name('_start')
    if func is not None:
        func.set_distance(inf)
        distance.pop(func.address, None)
    #function_data.print_function_info()

    return distance

def string_length(n):
    list_length=[8,16,32,64,128,264,526]
    return choices(list_length, k=n)

def generate_random_string(length):
    return [''.join(choices(ascii_letters + digits, k=length))]

def generate_tests(lengths):
    random_strings = [generate_random_string(length) for length in lengths]
    #logging.warning('Test genereted: {tests}'.format(tests=random_strings))
    return random_strings

def rule_api_list(api_list,function_data):
    # Find the address of the 'api_list'
    api=[function_data.get_function_by_name(x) for x in api_list]
    # Check if the functions are found in the call graph
    if None in api:
        return None
    
    return api 

# Separete exported functions with the inputs from intenral functions
def separete_func(data,exported_list):
    list_functions=data.get_names()
    prototypes=data.get_prototypes()
    for i,x in enumerate(prototypes):
        if x is None:
            f=data.get_function_by_name(list_functions[i])
            f.print_info()
    func_inputs=[x.args for x in prototypes]

    exported_func=[(x,j) for x,j in zip(list_functions,func_inputs) if x in exported_list] 
    internal_func=[(x,j) for x,j in zip(list_functions,func_inputs) if (x,j) not in exported_func]

    return exported_func,internal_func

# Generate initial population
def gen_pop(l,num_best_fit,len_cache):
    temp=sorted(l, key=lambda x: (x[0], len(str(x[0]).split('.')[1])))
    temp=list(k for k,_ in groupby(temp)) #delete duplicate
    l=temp[:len_cache]
    i=0
    pop=[]
    k=len(temp)
    while i< min(num_best_fit,k):
        min_fit=temp[0][0]
        mom=[x for x in l if x[0]==min_fit]
        ki=min(num_best_fit-i,len(mom))
        pop=pop + sample(mom,k=ki)
        i=i+ki
        temp=temp[len(mom):]
    return pop,l

# Delete duplicate and previously tested individuals
def del_duplicate(temp,l):
    temp.sort()
    temp = list(k for k,_ in groupby(temp)) #delete duplicate
    temp_l=[x[1] for x in l]
    tests=[x for x in temp if x not in temp_l] #delete children equal to parents

    return tests

# Create a csv with the best fitness for each generation
def write_n_to_csv(n):
    csv_file = 'fit_values.csv'
    # Write 'n' to the CSV file
    with open(csv_file, mode='a', newline='') as file:
        w = writer(file)
        w.writerow([n])

def main(binary, target_f, rules_file='rules.txt', file_type=True, num_values=4, num_best_fit=4, num_generations=10000, len_cache=100, steps=20, tests=None):
    # Check if the binary file exists
    if not path.isfile(binary):
        logging.warning(f"Error: File '{binary}' does not exist.")

    if tests is None:
        lengths_tests = string_length(num_best_fit)
        # tests=[[str(l)] for l in lengths_tests]
        tests = generate_tests(lengths_tests)  #Our tests
        logging.warning('Test genereted: {tests}'.format(tests=tests))
        
 
    tree = parse_file(rules_file) # Our rules
    exported_list=['strlen', 'strcmp', 'strncpy']

    # General info of 'binary' (functions name, address)
    logging.warning('Binary file: {file}'.format(file=binary))
    project,call_graph,general_function_data=file_data(binary)
    if project is None:
        return
    logging.warning('Call graph genereted')

    # Iterate through the 'tree' to find the 'api' subtree.
    visitor = RuleVisitor()
    visitor.visit(tree)  # Now, 'visitor.api_list' contains a list of 'api' elements.

    api_list=rule_api_list(visitor.api_list,general_function_data)
    
    function_data=general_function_data.copy()
    # For each function graph distance and list of the targets
    distance=first_distance(function_data,call_graph,target_f)
    
    logging.warning('Graph distance')
    # Only functions with distance =! infinity
    function_data.remove_functions_with_infinity_distance(visitor.api_list)
    function_data.print_function_info()

    # Dataframe of functions, for each function: solver, values
    flag=functions_dataframe(binary,project,function_data,num_values,steps,distance,api_list,visitor,call_graph.copy(),file_type)
    # Check if the function is found in the call graph
    function_data.print_function_info()
    if flag is None:
        logging.warning('Angr not able to evaluate solution')
        return
    logging.warning('Values calculated')

    l=[]
    i=0
    # Separete exported functions from intenral functions
    exported_func,internal_func=separete_func(function_data,exported_list)
    count_frida_execution=0
    while i< num_generations:
        for t in tests: #TODO parallel
            count_frida_execution += 1
            # Run the binary and trace function calls with their arguments
            entries = trace_function_calls(binary, t,exported_func,internal_func)
            if not entries:
                logging.warning(f"Warning: trace not found")
                return
            logging.warning('Trace function calls')

            # Fitness function for each test
            fit=fitness_func(function_data,entries,visitor)
            if fit==0:
                logging.warning('You found the rule with arguments: {fun}\n'.format(fun=t))
                logging.warning('Fitness calculated {count} times\n'.format(count=count_frida_execution))
                break
            elif fit is None:
                logging.warning(f"Fitness less then 1, but frida stopped before finishing the trace")
                return
            l.append([fit,t])
        if fit==0:
            break

        # 'num_best_fit' tests with best fitness
        pop,l=gen_pop(l,num_best_fit,len_cache)
        logging.warning('Initial population: {pop} at round {num_round}'.format(pop=pop,num_round=i))
        
        # Fuzzing
        temp_tests=fuzzy_func(pop)
        logging.warning('New generation: {new}\n'.format(new=temp_tests))

        # Delete duplicate
        tests=del_duplicate(temp_tests,l)
        logging.warning('New Tests: {new}\n'.format(new=tests))
        
        if tests:
            i+=1
        #write_n_to_csv(pop[0][0])
    if fit!=0:
        logging.warning('The best arguments for the rule are: {arg}\n'.format(arg=l[0][1]))
        logging.warning('Fitness calculated {count} times\n'.format(count=count_frida_execution))
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.info("Usage: python main_code.py <target_executable>")
        sys.exit(1)

    parser = ArgumentParser()
    # Required positional argument
    parser.add_argument('binary', type=str, help='The binary file to process')
    parser.add_argument('target', type=str, help='The target function to analyze')
    # Optional arguments with default values
    parser.add_argument('--rules_file', type=str, default='rules.txt', help='The rules file to use (default: rules.txt)')
    parser.add_argument('--file_type', type=str, default=True, help='Flag indicating whether the binary is an executable (True) or a library (False) (default: True)')
    parser.add_argument('--num_values', type=int, default=4, help='Number of symbolic solutions per function to compare with concrete executions (default: 4)')
    parser.add_argument('--num_best_fit', type=int, default=4, help='Number of individuals in the population (default: 4)')
    parser.add_argument('--num_generations', type=int, default=10000, help='Number of generations (default: 10000)')
    parser.add_argument('--len_cache', type=int, default=100, help='Number of test cases to store for fitness caching (default: 100)')
    parser.add_argument('--steps', type=int, default=20, help='Maximum number of steps from one API call of the rule to the next (default: 8)')
    parser.add_argument('--tests', nargs='+', help='List of test cases to be used (default: strings of randomly lenght between 8 and 256)')

    args = parser.parse_args()

    main(args.binary,args.target, args.rules_file, args.file_type, args.num_values, args.num_best_fit, args.num_generations, args.len_cache, args.steps,args.tests)

    
