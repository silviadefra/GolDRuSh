#!/usr/bin python3

import sys
from os import path
import logging
logging.basicConfig(filename='solution/solutions.log',format='%(asctime)s : %(message)s', encoding='utf-8', level=logging.WARNING)
#logging.basicConfig(format='[+] %(asctime)s %(levelname)s: %(message)s', level=logging.WARNING)
from argparse import ArgumentParser
from call_graph import file_data
from graph_distance import first_distance
from symbolic import functions_dataframe
from debug import trace_function_calls
from fitness import fitness_func
from fuzzy import fuzzy_func
from grammar import parse_file
from tree_visitor import RuleVisitor
from itertools import groupby
from random import sample,choices
from string import ascii_letters,digits
from csv import writer

def string_length(n):
    list_length=[8,16,32,64,128,264,526]
    return choices(list_length, k=n)

def generate_random_string(length):
    return [''.join(choices(ascii_letters + digits, k=length))]

def generate_tests(lengths):
    random_strings = [generate_random_string(length) for length in lengths]
    logging.warning('Test genereted: {tests}'.format(tests=random_strings))
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

def main(binary, rules_file='rules.txt', file_type=True, num_values=4, num_best_fit=4, num_generations=10000, len_cache=100, steps=8, tests=None):
    # Check if the binary file exists
    if not path.isfile(binary):
        logging.warning(f"Error: File '{binary}' does not exist.")
 
    trees = parse_file(rules_file) # Our rules
    exported_list=['strlen', 'strcmp', 'strncpy']

    # General info of 'binary' (functions name, address)
    logging.warning('Binary file: {file}'.format(file=binary))
    project,call_graph,general_function_data=file_data(binary)
    if project is None:
        return
    logging.warning('Call graph genereted')
    reverse_graph=call_graph.reverse(copy=False)

    # Separete exported functions from intenral functions
    exported_func,internal_func=separete_func(general_function_data,exported_list)

    # Iterate through the 'tree' to find the 'api' subtree.
    for num_tree,tree in enumerate(trees.children):
        visitor = RuleVisitor()
        visitor.visit(tree)  # Now, 'visitor.api_list' contains a list of 'api' elements.

        api_list=rule_api_list(visitor.api_list,general_function_data)
        # Check if the function is found in the call graph
        if api_list is None:
            continue
        for f in api_list:
            f.print_info()
        logging.warning('Rule {num}'.format(num=num_tree+1))
        
        function_data=general_function_data.copy()
        # For each function graph distance and list of the targets
        distance,dcg=first_distance(api_list,function_data,call_graph,reverse_graph)
        
        # Check if the function is found in the call graph
        if distance is None:
            continue
        logging.warning('Graph distance')
        # Only functions with distance =! infinity
        function_data.remove_functions_with_infinity_distance(visitor.api_list)
        function_data.print_function_info()


    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.info("Usage: python main_code.py <target_executable>")
        sys.exit(1)

    parser = ArgumentParser()
    # Required positional argument
    parser.add_argument('binary', type=str, help='The binary file to process')
    # Optional arguments with default values
    parser.add_argument('--rules_file', type=str, default='rules.txt', help='The rules file to use (default: rules.txt)')
    parser.add_argument('--file_type', type=str, default=True, help='Flag indicating whether the binary is an executable (True) or a library (False) (default: True)')
    parser.add_argument('--num_values', type=int, default=4, help='Number of symbolic solutions per function to compare with concrete executions (default: 4)')
    parser.add_argument('--num_best_fit', type=int, default=4, help='Number of individuals in the population (default: 4)')
    parser.add_argument('--num_generations', type=int, default=10000, help='Number of generations (default: 10000)')
    parser.add_argument('--len_cache', type=int, default=100, help='Number of test cases to store for fitness caching (default: 100)')
    parser.add_argument('--steps', type=int, default=8, help='Maximum number of steps from one API call of the rule to the next (default: 8)')
    parser.add_argument('--tests', nargs='+', help='List of test cases to be used (default: strings of randomly lenght between 8 and 256)')

    args = parser.parse_args()

    main(args.binary, args.rules_file, args.file_type, args.num_values, args.num_best_fit, args.num_generations, args.len_cache, args.steps,args.tests)

    
