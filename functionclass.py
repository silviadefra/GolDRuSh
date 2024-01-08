#!/usr/bin python3
from math import inf
import logging
from copy import deepcopy

class ProgramFunction:
    def __init__(self, function,cca):
        self.address =function.addr
        self.name = function.name
        self.type=cca.prototype
        self.distance = inf
        self.solver = [None]
        self.values = [None]


    def set_distance(self,num):
        self.distance=num

    def set_solver(self,solver):
        self.solver=solver

    def set_values(self,values):
        self.values=values


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
    
    def remove_functions_with_infinity_distance(self):
        new_list = [func for func in self.program_functions if func.distance != inf]

        return FunctionList(new_list)
    
    def copy(self):
        # Use deepcopy to create a deep copy of the list of program functions
        copied_functions = deepcopy(self.program_functions)

        # Create a new FunctionList instance with the copied functions
        copied_function_list = FunctionList(copied_functions)

        return copied_function_list
    
    def print_function_info(self):
        for func in self.program_functions:
            logging.warning(f"Function Name: {func.name}")
            logging.warning(f"Function Address: {func.address}")
            logging.warning(f"Function Type: {func.type}")
            logging.warning(f"Distance: {func.distance}")
            logging.warning(f"Solver: {func.solver}")
            logging.warning(f"Values: {func.values}")