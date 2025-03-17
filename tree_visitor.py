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
        self.string_list=[]

    def pred(self,tree):
        self.pred_tree=tree
   
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
    
    #type:(CNAME par ",")* CNAME par ";"
    def type(self,tree):
        self.string_list= [child.value for i,child in enumerate(tree.children) if i !=0]
    
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

        elif termtree.data=='spred':
            return self.claripy_spred(termtree)

        elif termtree.data=='apred':
            return self.claripy_apred(termtree)
        
        elif termtree.data=='pred':
            return self.claripy_pred(termtree)
        
        else:
            pass

    # spred: sptr IOP sptr
    def claripy_spred(self,tree):
        lf=self.claripy_sptr(tree.children[0])
        rf=self.claripy_sptr(tree.children[2])
        
        if isinstance(lf, claripy.ast.BV) and isinstance(rf, claripy.ast.BV):
            lf_size = lf.size() // 8  # Convert bit size to byte size
            rf_size = rf.size() // 8
            idx = claripy.BVS("idx", 32)  # Symbolic index
            constraints = [
                idx >= 0,
                idx <= rf_size - lf_size
            ]
            substring_constraints = claripy.Or(*[
                claripy.And(*[
                    lf.get_byte(j) == rf.get_byte(i + j)  # Enforce byte-wise equality
                    for j in range(lf_size)
                ])
                for i in range(rf_size - lf_size + 1)  # Try all possible starting positions
            ])

            return claripy.And(*constraints, substring_constraints)  

        # Case 2: lf is concrete, rf is symbolic
        elif isinstance(lf, str) and isinstance(rf, claripy.ast.BV):
            lf_size = len(lf)

            lf_bv=claripy.BVV(int.from_bytes(lf.encode(), 'big'), lf_size * 8) # Convert concrete string to BV

            rf_size = rf.size() // 8
            idx = claripy.BVS("idx", 32)  # Symbolic index

            constraints = [
                idx >= 0,
                idx <= rf_size - lf_size
            ]

            substring_constraints = claripy.Or(*[
                claripy.And(*[
                    lf_bv.get_byte(j) == rf.get_byte(i + j)
                    for j in range(lf_size)
                ])
                for i in range(rf_size - lf_size + 1)
            ])

            return claripy.And(*constraints, substring_constraints)

        # Case 3: If both are already concrete
        elif isinstance(lf, str) and isinstance(rf, str):
            return claripy.StrContains(claripy.StringV(rf), claripy.StringV(lf))
        
    # CNAME | ESCAPED_STRING
    def claripy_sptr(self,tree):
        termtree=tree.children[0]
        if termtree.type=='ESCAPED_STRING':
            string=termtree.value[1:-1].lower()
            return string
        elif termtree.type=='CNAME':
            x=symb_val[termtree.value]
            if isinstance(x,str):
                return x.lower()
            else:
                return x

        else:
            pass
    
    # apred: sum COP sum
    def claripy_apred(self,tree):
        lf=self.claripy_sum(tree.children[0])
        rf=self.claripy_sum(tree.children[2])
        op=tree.children[1].value # COP: "==" | "<" | ">" | ">=" | "<=" | "!="
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
            return self.claripy_atom(tree)
        
        if len(tree.children) == 3:
            lf=self.claripy_prod(tree.children[0])
            rf=self.claripy_atom(tree.children[2])
            op=tree.children[1].value
            # MOP: "*" | "/"
            return ops[op](lf,rf)

        elif len(tree.children)==1:
            return self.claripy_atom(tree.children[0])

        else:
            pass

    #atom: decorhex | CNAME | "(" sum ")"  | "&"CNAME 
    def claripy_atom(self,tree):
        termtree=tree.children[0]
        if isinstance(termtree,Tree):
            if termtree.data=='decorhex':
                return self.claripy_decorhex(termtree)
        
            elif termtree.data=='sum':
                return self.claripy_sum(termtree)
        
        elif termtree.type=='CNAME': 
            if termtree.value[0]=='&':
                return                     #da sistemare
            else:
                return symb_val[termtree.value]

        else:
            pass
    
    # decorhex: ["+"|"-"] INT | "\\x" HEXDIGIT+ 
    def claripy_decorhex(self,tree):
        termtree=tree.children[0]
        if termtree.type=='INT':
            return int(termtree.value)
        
        elif termtree.type== 'HEXDIGIT':
            s=''.join(x.value for x in tree.children)
            return '0x'+ s




        

        

