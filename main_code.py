#!/usr/bin python3

import math
from call_graph import *
from debug import *
from fuzzy import *



def main(binary,api):

    # Dataframe of functions, for each function: name, address, distance, constraints
    data=functions_dataframe(binary,api)

    # Usage example
    arguments = ["args"]
    list_functions=data['name'].tolist()
    #print(list_functions)

    # Run the binary and trace function calls with their arguments
    entries = trace_function_calls(binary, arguments,list_functions)
    # Only functions
    reached_functions=[x[0] for x in entries]
    reached_functions = list(dict.fromkeys(reached_functions))


    num_values=2
    fuzzy_test(data,reached_functions,arguments,num_values)

    


        





if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python call_graph.py <target_executable> <api_call>")
        sys.exit(1)

    # Path to the binary program
    binary_path = sys.argv[1]

    # Specify the function name
    api_call = sys.argv[2]

    main(binary_path,api_call)

    