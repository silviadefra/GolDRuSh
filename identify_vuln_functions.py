#!/usr/bin python3
from sys import exit, argv
from os import path
import logging
from argparse import ArgumentParser
from call_graph import file_data
from graph_distance import first_distance
from grammar import parse_file
from tree_visitor import RuleVisitor
import claripy
from angr import sim_options
from gc import collect
from goldrush import create_logger,rule_api_list
from math import inf

def functions_with_call_distance(functions,call_distance):
    temp=None
    if functions.exists_functions(call_distance):
        temp=functions.copy()
        temp.specific_distance(call_distance)

    return temp

# Find next api
def next_api(project,s,find):
    sm=project.factory.simgr(s, save_unconstrained=True)
    sm.step()
    sm.explore(find=find, avoid=project.loader.find_symbol("exit").rebased_addr)
    return sm

# Get concrete value
def concrete_value(symb_val):
    val=symb_val.args[0]
    if isinstance(val, str):
        list = val.split('_')  # Extract the address part as a string
        address_str=list[1]
        if address_str[:2]=='0x':
            val = int(address_str, 16)
        elif list[0]=='mem':
            val=int('0x'+address_str,16)
        else:
            return list[:-2]
    return val

def symbolic_par(cc,x,par,st,project,par_val=None): 
    symb_par=claripy.BVS(x, par.size)
    if par_val is None: # if return value
        sim_reg=cc.return_val(par)
        par_val=sim_reg.reg_name
        symb_val = getattr(st.regs,par_val)
    elif par_val[0]=='0': # if stack
        arch = project.arch
        if arch.name == 'X86_64' or arch.name == 'AMD64': 
            esp = st.regs.rsp
        else:
            esp = st.regs.esp
        offset = int(par_val,16)
        symb_val = st.memory.load(esp + offset, 4, endness=arch.memory_endness)
    else: # if reg
        symb_val = getattr(st.regs,par_val)
    if isinstance(symb_val.args[0],claripy.ast.BV): # if more the one BV
        concrete=0
        logging.warning(f"symbolic::symbolic_par - symb_val.args = {symb_val}, type: {type(symb_val)}, args: {symb_val.args}")
        for val in symb_val.args:
            concrete_item=concrete_value(val)
            if isinstance(concrete_item, list):
               return concrete_item
            concrete = concrete + concrete_item
    else:
        concrete=concrete_value(symb_val)
    try:
        st.solver.add(symb_par == symb_val)
    except:
        pass
    setattr(st.regs,str(par_val),symb_par)
    try:
        return hex(concrete)
    except:
        return concrete

def rules_symbolic_par(cc,api,par_list,st,project):
    symb_input=dict()       
    input_arg=api.type.args 
    # Symbolic input variables
    for i,x in enumerate(par_list[1:]):
        if x!='?':
            val=symbolic_par(cc,x,input_arg[i],st,project,api.reg[i])
            symb_input[x]=val

    # Symbolic return variable
    if par_list[0] is not None:
        #while st.addr == api.address:
        if api.name == 'malloc':
            st=st.step().successors[0]
        st=st.step().successors[0]
        val=symbolic_par(cc,par_list[0],api.type.returnty,st,project)
        symb_input[par_list[0]]=val

    return symb_input

def explore_paths(api_list, source,prototype, num_steps,visitor,project):
    find=api_list[0].address # first api of the signature of the rule
    claripy_contstraints = solver = sm = symbolic_par = None
    extras = {sim_options.REVERSE_MEMORY_NAME_MAP, sim_options.TRACK_ACTION_HISTORY,sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}
    
    # Explore the program with symbolic execution
    state = project.factory.call_state(source,prototype=prototype,add_options=extras)
    sim = project.factory.simgr(state, save_unconstrained=True)
    results=[]
    try:
        sim.explore(find=find)
        cc=project.factory.cc() #Calling convention
        symbolic_par=dict() # dictionary for parameters of apis that we need for the predicate
        x=0
        if sim.found:
            sm=sim.copy()
            for s in sim.found:
                if len(api_list) > 1:
                    symbolic_par.update(rules_symbolic_par(cc,api_list[0],visitor.par_list[0],s,project))
                    sm=next_api(project,s,api_list[1].address)
                    if sm.found:
                        for i,a in enumerate(api_list[1:-1]):
                            for s1 in sm.found:
                                symbolic_par.update(rules_symbolic_par(cc,a,visitor.par_list[i+1],s1,project))
                                sm=next_api(project,s1,api_list[i+2].address)
                                if sm.found:
                                    break
                            if not sm.found:
                                break
                        if not sm.found:
                            results.append(None)
                            continue
                        else:
                          s=sm.found[0]  
                    else:
                        results.append(None)
                        continue
                while(x<num_steps):
                    symbolic_par.update(rules_symbolic_par(cc,api_list[-1],visitor.par_list[-1],s,project))
                    logging.warning("Parameters found: {par}".format(par=symbolic_par))
                    claripy_contstraints=visitor.predicate(symbolic_par) # put parameters value in the predicate
                    solver = s.solver
                    solver.add(claripy_contstraints)
                    if solver.satisfiable():
                        results.append(1) # predicate is satisfiable?
                        break
                    else:
                        results.append(0)
                        x +=1
                        sm2=next_api(project,s,api_list[-1].address)
                        if sm2.found:
                            s=sm2.found[0]
                        else:
                            results.append(None)
                            break
        else:
            return results
    except Exception as e:
        logging.warning("symbolic::explore_paths - Angr error reached: {err}".format(err = str(e)))
        return results
    finally:
        collect()
    return results

# For each function in function_data try to reach the signature of the rule and check if the pradicate is satisfiable   
def functions_dataframe(project, function_data, steps,api_list,visitor):
    none_lists=[]

    for func in function_data:
        try:
            # Execute the function and get the result
            v = explore_paths(api_list, func.address, func.type, steps, visitor, project)
            none_lists.append(v)
            if all(elem !=1 for elem in v):
                #logging.warning(f'Unsat result for {func.name}')
                func.set_distance(inf)
        except Exception as e:
            logging.warning(f"Unhandled exception for function at address {func.address}: {e}")
    for none_list in none_lists:
        if any(elem is not None for elem in none_list):
            return 0   
    return None

def main(binary, rules_file, steps,csv_file):
    callgraph_distance=1
    # Check if the binary file exists
    if not path.isfile(binary):
        print(f"Error: File '{binary}' does not exist.")
    create_logger(binary) # create logger
    logging.warning('Binary file: {file}'.format(file=binary))
    
    trees = parse_file(rules_file) # parse rules

    # General info of 'binary' (functions name and address,call graph)
    project,call_graph,general_function_data=file_data(binary,1)
    
    if project is None:
        return
    logging.warning('Call graph genereted')
    
    # Iterate through the rules ('trees.children') to check the rule ('tree') subtree.
    for num_tree,tree in enumerate(trees.children):
        visitor = RuleVisitor()
        visitor.visit(tree)  # Now, 'visitor.api_list' contains the list of apis of the rule (tree)
        api_list=rule_api_list(visitor.api_list,general_function_data)
        # Check if apis (api_list) are found in the call graph
        if api_list is None:
            continue # move to the next rule
        logging.warning('Rule {num}'.format(num=num_tree+1))
        
        function_data=general_function_data.copy()
        # For each function, graph distance to the target function
        distance,_=first_distance(api_list,function_data,call_graph)
        # Check if apis are called by the same function
        if distance is None:
            continue # move to the next rule
        logging.warning('Graph distance')
        
        function_data.remove_functions_with_infinity_distance(visitor.api_list) # Only functions with distance =! infinity
        functions_call_distance=functions_with_call_distance(function_data,callgraph_distance) # Only function with distance == call_distance
        
        flag=functions_dataframe(project,functions_call_distance,steps,api_list,visitor)
        if flag is None:
            logging.warning('Vulnerabilities not found')  
        else:
            logging.warning('Possible vulnerability in the function:')
            functions_call_distance.remove_functions_with_infinity_distance(visitor.api_list) # Only functions with distance =! infinity
            functions_call_distance.print_function_info()
            logging.warning('APIs involved:')
            for api in api_list:
                api.print_info()  

    
if __name__ == "__main__":
    if len(argv) < 2:
        print("Usage: python only_test_distance.py <target_executable>")
        exit(1)

    parser = ArgumentParser()
    # Required positional argument
    parser.add_argument('binary', type=str, help='The binary file to process')
    # Optional arguments with default values
    parser.add_argument('--rules_file', type=str, default='rules/rules.txt', help='The rules file to use (default: rules.txt)')
    parser.add_argument('--steps', type=int, default=20, help='Maximum number of steps from one API call of the rule to the next (default: 20)')
    parser.add_argument('--csv_file', type=str, default='test/log_file/features.csv', help='The csv file to write the list of found rules')
    args = parser.parse_args()

    main(args.binary, args.rules_file, args.steps, args.csv_file)
