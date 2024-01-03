from lark import Visitor, Tree, Token
import claripy
import operator

ops = {
    '+' : operator.add,
    '-' : operator.sub,
    '*' : operator.mul,
    '/' : operator.truediv,
    '<' : operator.lt,
    '<=' : operator.le,
    '==' : operator.eq,
    '!=' : operator.ne,
    '>=' : operator.ge,
    '>' : operator.gt, 
}

symb_val=dict()

# Define a custom visitor class
class RuleVisitor(Visitor):
    def __init__(self):
        self.api_list = []  # To store 'api' elements
        self.par_list= []
        self.pred_tree=None


    def rule(self,tree):
        self.pred_tree=tree.children[1]

    
    #api: CNAME"("[parlist]")" | CNAME "=" CNAME"("[parlist]")"
    def api(self, tree):
        cnames = []

        if len(tree.children) == 3:
            # Case: CNAME "=" CNAME"("[parlist]")"
            retpar=tree.children[0].value
            self.api_list.append(tree.children[1].value)
            parlist_tree = tree.children[2]
        else:
            # Case: CNAME "("[parlist]")"
            retpar=None
            self.api_list.append(tree.children[0].value)
            parlist_tree = tree.children[1]

        if isinstance(parlist_tree, Tree):
            cnames = self.parlist(parlist_tree)  # Use the parlist to handle the parlist
            self.par_list.append([retpar] + cnames)
        elif isinstance(parlist_tree,Token):
            self.par_list.append([retpar,parlist_tree.value])

    #parlist: (par ",")* par
    def parlist(self, tree):
        return [child.value for child in tree.children]
    
    def predicate(self, symb):
        global symb_val
        symb_val=symb
        claripy_contstraints=self.claripy_pred(self.pred_tree)
        return claripy_contstraints

    #pred: neg | pred BOP neg
    def claripy_pred(self,tree):
        if len(tree.children) == 3:
            lf=self.claripy_pred(tree.children[0])
            rf=self.claripy_neg(tree.children[2])
            op=tree.children[1].value
            if op=="AND":
                return claripy.And(lf,rf)
            elif op=="OR":
                return claripy.Or(lf,rf)
            else:
                pass

        elif len(tree.children)==1:
            return self.claripy_neg(tree.children[0])

        else:
            pass
     
    # neg: term | NEG term 
    def claripy_neg(self,tree):

        if len(tree.children) == 2:
            return claripy.Not(self.claripy_term(tree.children[1]))
                       
        elif len(tree.children)==1:
            return self.claripy_term(tree.children[0])

        else:
            pass

    # term: TRUE | FALSE | spred | apred | "("pred")"
    def claripy_term(self,tree):
        termtree=tree.children[0]
        if isinstance(termtree,Token):
            if termtree.value=='true':
                return claripy.true
            elif termtree.value=='false':
                return claripy.false
            else:
                pass
                
        elif termtree.data=='apred':
            return self.claripy_apred(termtree)
        
        elif termtree.data=='pred':
            return self.claripy_pred(termtree) #parentesi
        
        else:
            pass

    # apred: sum COP sum
    def claripy_apred(self,tree):
        lf=self.claripy_sum(tree.children[0])
        rf=self.claripy_sum(tree.children[2])
        op=tree.children[1].value
        # COP: "==" | "<" | ">" | ">=" | "<=" | "!="
        return ops[op](lf,rf)
        

    # sum: sum SOP prod | prod
    def claripy_sum(self,tree):
        if len(tree.children) == 3:
            lf=self.claripy_sum(tree.children[0])
            rf=self.claripy_prod(tree.children[2])
            op=tree.children[1].value
            # SOP: "+" | "-" 
            return ops[op](lf,rf)
        
        elif len(tree.children)==1:
            return self.claripy_prod(tree.children[0])

        else:
            pass

    # prod: atom| prod MOP atom
    def claripy_prod(self,tree):
        if isinstance(tree,Token):
            return symb_val[tree.value]
        
        elif len(tree.children) == 3:
            lf=self.claripy_prod(tree.children[0])
            rf=self.claripy_atom(tree.children[2])
            op=tree.children[1].value
            # MOP: "*" | "/"
            return ops[op](lf,rf)

        elif len(tree.children)==1:
            return self.claripy_atom(tree.children[0])

        else:
            pass


    # atom: NUMBER | CNAME | SIGN atom | "(" sum ")"
    def claripy_atom(self,tree):
        if len(tree.children) == 2:
            x= - self.claripy_atom(tree.children[1])
            return x

        elif isinstance(tree.children[0],Tree):
            return self.claripy_sum(tree.children[0])   #parentesi
        
        elif tree.children[0].type=='CNAME': 
            return symb_val[tree.children[0].value]
        
        elif tree.children[0].type=='NUMBER':
            return eval(tree.children[0].value)

        else:
            pass





        

        

