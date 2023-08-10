#!/usr/bin python3
import numpy as np
import logging


# Select the parents using the roulette wheel selection technique
def roulette_selection(pop):
    max = sum([x[0] for x in pop])
    selection=[(max-x[0])/(max*(len(pop)-1)) for x in pop] # smaller the fitness, higher th probability
    index_list=np.random.choice(len(pop),2,p=selection, replace=False)
    parents=[pop[i][1] for i in index_list]
    return parents

# Single Point Crossover 
def crossover(parent1, parent2):
    if len(parent1)==1:
        index=0
    else:
        index=np.random.randint(0, len(parent1)-1) # index of the list to crossover
    p1=parent1[index]
    p2=parent2[index]
    if len(p1)==1:
        pos=0
    else:
        pos = np.random.randint(0, len(p1)-1) # position of the word to cross
    c1=p1[:pos]+p2[pos:]
    c2=p2[:pos] + p1[pos:]
    offspring1 = parent1[:index] +[c1] + parent2[index +1:]
    offspring2 = parent2[:index] +[c2] + parent1[index +1:]

    return [offspring1, offspring2]

# Flip one bit
def flip_random_character(s):  
    res = ''.join(format(ord(i), 'b') for i in s)
    pos = np.random.randint(0, len(res)-1)
    new_c = str(1-int(res[pos]))
    new_bin=res[:pos] + new_c + res[pos + 1:]
    str_data =''
    for i in range(0, len(new_bin), 7):
        temp_data =new_bin[i:i + 7]
        decimal_data = int(temp_data,2)
        str_data = str_data + chr(decimal_data)
    return str_data
    

# Add only 1 random character
def add_random_character(s):
    pos = np.random.randint(0, len(s))
    new_c = chr(np.random.randint(0, 65536)) #da vedere
    return s[:pos] + new_c + s[pos:]

# Remove only 1 random character
def remove_random_character(s):
    if len(s)==1:              
        return ''
    pos = np.random.randint(0, len(s) - 1)
    return s[:pos] + s[pos + 1:]

# Each child mutates in one of the possible mutations
def mutation(child):  
    
    if len(child)==1:
        index=0
    else: 
        index=np.random.randint(0, len(child)-1) # index of the list to mute
    prob=np.random.uniform()
    if prob<0.33:
        child[index]=flip_random_character(child[index])
    elif prob<0.66:
        child[index]=add_random_character(child[index])
    else:
        child[index]=remove_random_character(child[index])
    return child


def fuzzy_func(initial_pop):

    # Usage examples
    num_children=len(initial_pop)
    children=[]

    for i in range(0,num_children,2):

        # Parents selection
        parents=roulette_selection(initial_pop)
        logging.debug(parents)
    
        # Single Point Crossover
        children.extend(crossover(parents[0],parents[1]))
    logging.debug(children)

    # Mutation 
    for child in children:
        if np.random.uniform()<0.05:
            child=mutation(child)

    return children


