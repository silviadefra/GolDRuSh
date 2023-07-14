#!/usr/bin python3
import numpy as np


# Select the parents using the roulette wheel selection technique
def roulette_selection(pop,n):
    max = sum([x[0] for x in pop])
    selection=[(max-x[0])/(max*(len(pop)-1)) for x in pop] # smaller the fitness, higher th probability
    index_list=np.random.choice(len(pop),n,p=selection, replace=False)
    parents=[pop[i][1] for i in index_list]
    return parents

# Single Point Crossover
def crossover(parent1, parent2):
    if len(parent1)==1:
        pos=1
    else:
        pos = np.random.randint(1, len(parent1))

    offspring1 = parent1[:pos] + parent2[pos:]
    offspring2 = parent2[:pos] + parent1[pos:]

    return (offspring1, offspring2)

# Flip one bit
def flip_random_character(s):   #cambia bit non carattere
    pos = np.random.randint(0, len(s))
    new_c = 1-s[pos]
    return s[:pos] + new_c + s[pos + 1:]

# Add only 1 random character
def add_random_character(s):
    pos = np.random.randint(0, len(s))
    new_c = chr(np.random.randrange(0, 65536)) #da vedere
    return s[:pos] + new_c + s[pos:]

# Remove only 1 random character
def remove_random_character(s):
    pos = np.random.randint(0, len(s) - 1)
    return s[:pos] + s[pos + 1:]

# Each child mutates in one of the possible mutations
def mutation(children):

    for child in children:
        prob=np.random.uniform()
        if prob<0.33:
            res = ''.join(format(ord(i), '08b') for i in child)
            child=flip_random_character(res)
        elif prob<0.66:
            child=add_random_character(child)
        else:
            child=remove_random_character(child)


def fuzzy_func(initial_pop,data):

    # Usage examples
    num_parents=2

    # Parents selection
    parents=roulette_selection(initial_pop,num_parents)
    
    # Single Point Crossover
    parent1=parents[0]
    parent2=parents[1]
    children=[]
    for p1,p2 in zip(parent1,parent2):
        children.append(crossover(p1,p2))

    # Mutation 
    mutation(children)