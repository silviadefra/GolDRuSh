#!/usr/bin python3

import sys
from itertools import zip_longest
from claripy import Solver, And

# Function with minimum distance
def func_with_minimum_distance(data,functions):
    dist=sys.maxsize
    for f in functions:
        func=data.get_function_by_name(f[0])
        if func.distance<dist:
            min_f=func
            values=f[1]
    return min_f,values

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

#Associate concrete value to symbolic parameters
def combine_concrete_symbolic(visitor,entries,par):
    api_list=visitor.api_list
    entries=[e for e in entries if e[0] in api_list]
    for x,y in zip(visitor.api_list,visitor.par_list):
        ent=[e for e in entries if e[0]==x]
        if y[0] is not None:
            output=[e for e in ent if e[2]=='output']
            par[y[0]]=output[0][1]
            
        # Symbolic input variables
        input=[e[1] for e in ent if e[2]=='input']
        for i,p in enumerate(y[1:]):
            if p!='?':
                par[p]=input[0][i]
    return par


def add_constraints(par,conc_val,visitor):
    s = Solver()
    constraints=visitor.predicate(par)
    print(conc_val)
    print(par)
    s.add(constraints)
    for key in conc_val:
        if type(conc_val[key]) is str:
            s.add(par[key] == int(conc_val[key],16))
        elif type(conc_val[key]) is int:
            s.add(par[key] == conc_val[key])
        else:
            print(f'tipo sconosciuto {type(conc_val[key])}')
    return s


def prev_func_vals(df,func_list):
    for function in func_list:
            f=df.get_function_by_name(function[0])
            if f.distance==1:
                break
    return f.values


#Main Function
def fitness_func(df,entries,visitor):
    reached_functions=[(x[0],x[1]) for x in entries if x[2]=="input"] # Functions (x[0]) and inputs (x[1])
    func_in_both_list=[x for x in reached_functions if x[0] in df.get_names()] 
    
    # Function with minimum distance to the target
    func,test_values=func_with_minimum_distance(df,func_in_both_list)
    # Values to reach the next 'good' function from the solver
    values=func.values
    
    # If it reached the last api
    if func.distance==-1:
        #Associate concrete value to symbolic parameters of the rules
        par=func.sympar
        conc_val=combine_concrete_symbolic(visitor,entries,par.copy())
        s=add_constraints(par,conc_val,visitor)
        if s.satisfiable():
            return 0
        else:
            values=prev_func_vals(df,func_in_both_list)
    #If it reached at least one api but not the last one
    elif func.distance==0:
        values=prev_func_vals(df,func_in_both_list)
        

    # From characters to binary
    ch_args=to_bit(test_values) 

    ch_values=[]
    for value in values:
        ch_values.append(to_bit(value))

    # Distance to reach the next 'good' function
    minimum=distance_binary(ch_args,ch_values)
    
    # Between 0 and 1
    m=minimum/(minimum+1)

    fitness=func.distance+m

    return fitness



# Usage example
#data=None
#reached_functions=[]
#arguments=[]
#num_values=2

#fitness_func(data,reached_functions,arguments,num_values)


#