#!/usr/bin python3
from math import inf
import logging
from copy import deepcopy

class ProgramFunction:
    def __init__(self, function,cca):
        self.address =function.addr
        self.name = function.name
        self.type=cca.prototype
        self.reg=[str(x)[1:-1] for x in cca.cc.arg_locs(cca.prototype)]
        self.distance = inf
        self.values = [None]
        self.sympar= [None]

    def set_distance(self,num):
        self.distance=num

    def set_values(self,values):
        self.values=values

    def set_args(self,args):
        self.sympar=args

    def set_address(self,address):
        self.address=address

    def set_prototype(self,prototype):
        self.type=prototype

    def print_info(self):
        logging.warning(f"Function Name: {self.name}")
        logging.warning(f"Function Address: {self.address}")
        logging.warning(f"Function Type: {self.type}")
        logging.warning(f"Distance: {self.distance}")
        logging.warning(f"Values: {self.values}")
        logging.warning(f"Symbolic parameters: {self.sympar}")


class FunctionList:
    def __init__(self, program_functions):
        self.program_functions = program_functions

    def get_function_by_addr(self, function_addr):
        for func in self.program_functions:
            if func.address == function_addr:
                return func
        return None
    
    def get_function_by_name(self, function_name):
        for func in self.program_functions:
            if func.name == function_name:
                return func
        return None
    
    def get_addresses(self):
        list_functions=[func.address for func in self.program_functions]

        return list_functions
    
    def get_prototypes(self):
        prototype=[func.type for func in self.program_functions]

        return prototype
    
    def get_names(self):
        names=[func.name for func in self.program_functions]

        return names
    
    def remove_functions_with_infinity_distance(self,api_list):
        not_infinity=[func for func in self.program_functions if func.distance != inf]
        api=[func for func in self.program_functions if func.name in api_list]
        self.program_functions =not_infinity + api 
    
    def copy(self):
        # Use deepcopy to create a deep copy of the list of program functions
        copied_functions = deepcopy(self.program_functions)

        # Create a new FunctionList instance with the copied functions
        copied_function_list = FunctionList(copied_functions)

        return copied_function_list
    
    def print_function_info(self):
        for func in self.program_functions:
            func.print_info()
