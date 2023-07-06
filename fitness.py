#!/usr/bin python3

import math
import sys
import pandas as pd

# Function with minimum distance
def minimum_distance(data,functions):
    dist=sys.maxsize
    for f in functions:
        i=data.index[data['name']==f].item()
        if data.loc[i,'distance']<dist:
            min_f=f
            dist=data.loc[i,'distance']
    return min_f,dist

# From characters to numbers
def to_num(args):
    ch_values=[]
    for elm in args:
        # If the argument is a string
        if isinstance(elm, str):
            c=0
            for pos in range(len(elm)):
                c += ord(elm[pos])
            ch_values.append(c)
        else:
            ch_values.append(elm)
    return ch_values

# Distance between strings
def distance_character(target, values):

    # Initialize with very large value so that any comparison is better
    minimum = sys.maxsize

    for value in values:
        distance=0
        for i in range(len(target)):
            distance += abs(target[i] - value[i])
        if distance < minimum:
            minimum = distance
    return minimum



def fitness_func(data,reached_functions,arguments):
    
    # Function with minimum distance to the target
    f,node_dist=minimum_distance(data,reached_functions)
    if node_dist==0:
        print('You reached the good function')
        return node_dist

    # Values to reach the next 'good' function
    i=data.index[data['name']==f].item()
    values=data.loc[i,'values']

    # From characters to numbers
    ch_args=to_num(arguments)
    ch_values=[]
    for value in values:
        ch_values.append(to_num(value))
    #print(ch_args)

    # Distance to reach the next 'good' function
    minimum=distance_character(ch_args,ch_values)
    # Between 0 and 1
    m=minimum/(minimum+1)

    fitness=node_dist+m
    #print(fitness)
    return fitness



# Usage example
#data=None
#reached_functions=[]
#arguments=[]
#num_values=2

#fitness_func(data,reached_functions,arguments,num_values)


#