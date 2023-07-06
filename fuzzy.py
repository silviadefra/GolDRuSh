#!/usr/bin python3
import numpy as np


# Select the parents using the roulette wheel selection technique
def roulette_selection(pop,n):
    max = sum([x[0] for x in pop])
    selection=[(max-x[0])/(max*(len(pop)-1)) for x in pop]
    print(selection)
    index_list=np.random.choice(len(pop),n,p=selection, replace=False)
    parents=[pop[i][1] for i in index_list]
    return parents




def fuzzy_func(initial_pop):

    # Usage examples
    num_parents=2

    #Parents selection
    parents=roulette_selection(initial_pop,num_parents)
    print(parents)