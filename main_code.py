#!/usr/bin python3

import math
from call_graph import *
from debug import *
from fitness import *



def main(binary,api):

    # Dataframe of functions, for each function: name, address, distance, solver, values
    num_values=2
    data=functions_dataframe(binary,api,num_values)

    # Usage example
    arguments = ['7','8']
    list_functions=data['name'].tolist()
    num_inputs=[len(x.args) for x in data['type'].tolist()] # the number of input for each function
    #print(list_functions)

    # Run the binary and trace function calls with their arguments
    entries = trace_function_calls(binary, arguments,list_functions,num_inputs)
    reached_functions=[x[0] for x in entries] # Only functions
    reached_functions = list(dict.fromkeys(reached_functions)) # Without repetition

    # Fitness function for each test
    df=data[data['distance'] != math.inf] # Only functions with distance =! infinity
    func_in_both_list=set(reached_functions) & set(df['name'].tolist()) # Only functions with distance =! infinity
    fit=fitness_func(df,func_in_both_list,arguments)

    


        





if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python main_code.py <target_executable> <api_call>")
        sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    # Specify the function name
    api_call = sys.argv[2]

    main(binary_path,api_call)

    