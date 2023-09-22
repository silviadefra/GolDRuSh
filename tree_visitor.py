from lark import Visitor

# Define a custom visitor class
class FuncVisitor(Visitor):
    def __init__(self):
        self.api_list = []  # To store 'func' elements

    def func(self, tree):
        self.api_list.append(tree.children[0].value)
                


