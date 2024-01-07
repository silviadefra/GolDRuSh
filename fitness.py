#!/usr/bin python3

import sys
from itertools import zip_longest

# Function with minimum distance
def minimum_distance(data,functions):
    dist=sys.maxsize
    for f in functions:
        func=data.get_function_by_name(f)
        if func.distance<dist:
            min_f=f
            dist=func.distance
    return min_f,dist

# From characters to binary
def to_bit(args):
    ch_values=[]
    for elm in args:
        # If the argument is a string
        if isinstance(elm, str):
            c = ''.join(format(ord(i), 'b') for i in elm)
        else:
            c=format(elm,'b')
        ch_values.append(c)
    return ch_values

# Distance between strings
def distance_binary(target, values):

    # Initialize with very large value so that any comparison is better
    minimum = sys.maxsize

    for value in values:
        distance=0
        for v,t in zip(value,target):
            distance+=sum(c1 != c2 for c1, c2 in zip_longest(t, v)) 
        if distance < minimum:
            minimum = distance
    return minimum


#Main Function
def fitness_func(df,reached_functions):
 
    func_in_both_list=set([x[0] for x in reached_functions]) & set(df.get_names()) 
    
    # Function with minimum distance to the target
    f,node_dist=minimum_distance(df,func_in_both_list)
    # Values to reach the next 'good' function from the solver
    func=df.get_function_by_name(f)
    values=func.values
    
    if node_dist==0:
        for function in func_in_both_list:
            func=df.get_function_by_name(function)
            if func.distance==1:
                f=function
                values=func.values
                break


    # Inputs ('x[1]') of the good function 'f' from the debug function
    for x in reached_functions:
        if x[0]==f:
            ch_args=to_bit(x[1]) # From characters to binary

    ch_values=[]
    for value in values:
        ch_values.append(to_bit(value))

    # Distance to reach the next 'good' function
    minimum=distance_binary(ch_args,ch_values)
    
    # Between 0 and 1
    m=minimum/(minimum+1)

    fitness=node_dist+m

    return fitness



# Usage example
#data=None
#reached_functions=[]
#arguments=[]
#num_values=2

#fitness_func(data,reached_functions,arguments,num_values)


#