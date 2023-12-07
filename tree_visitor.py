from lark import Visitor, Tree

# Define a custom visitor class
class FuncVisitor(Visitor):
    def __init__(self):
        self.api_list = []  # To store 'func' elements
        self.par_list= []

    def api(self, tree):
        cnames = []

        if len(tree.children) == 3:
            # Case: CNAME "=" func"("[parlist]")"
            retpar=tree.children[0].value
            self.api_list.append(tree.children[1].value)
            parlist_tree = tree.children[2]
        else:
            # Case: func"("[parlist]")"
            retpar=None
            self.api_list.append(tree.children[0].value)
            parlist_tree = tree.children[1]

        if isinstance(parlist_tree, Tree):
            cnames = self.parlist(parlist_tree)  # Use the parlist to handle the parlist
            self.par_list.append([retpar] + cnames)
        else:
            self.par_list.append([retpar,parlist_tree.value])

    def parlist(self, tree):
        return [child.value for child in tree.children]
        

