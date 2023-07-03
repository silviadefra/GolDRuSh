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
def to_num(value):
    ch_values=[]
    for elm in value:
        c=0
        for pos in range(len(elm)):
            c += ord(elm[pos])
        ch_values.append(c)
    return ch_values

# Distance between strings
def distance_character(target, values):

    # Initialize with very large value so that any comparison is better
    minimum = sys.maxsize

    for i in range(len(target)):
        distance=0
        for elem,targ in zip(values[i],target[i]):
            distance += abs(targ - elem)
        if distance < minimum:
            minimum = distance
    return minimum





def fitness_func(df,reached_functions,arguments):

    # Only functions with distance =! infinity
    data=df[df['distance'] != math.inf]
    
    # Function with minimum distance to the target
    f,node_dist=minimum_distance(data,reached_functions)
    if node_dist==0:
        print('You reached the good function')
        return node_dist

    # 'n' values to reach the next 'good' function
    i=data.index[data['name']==f].item()
    values=data.loc[i,'solver']

    # From characters to numbers
    ch_args=to_num(arguments)
    ch_values=[]
    for value in values:
        ch_values.append(to_num(value))

    # Distance to reach the next 'good' function
    minimum=distance_character(ch_args,ch_values)
    # Between 0 and 1
    m=minimum/(minimum+1)

    fitness=node_dist+m

    return fitness



def fuzzy_test(data,reached_functions,arguments):



    # Fitness function for a single test
    fit=fitness_func(data,reached_functions,arguments)
    print(fit)


    




# Usage example
#data=None
#reached_functions=[]
#arguments=[]
#num_values=2

#fuzzy_test(data,reached_functions,arguments,num_values)


#