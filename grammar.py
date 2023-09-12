from lark import Lark
import logging

logging.basicConfig(level=logging.DEBUG)
grammar = r"""

    ?start: (line)*
    ?line: rule
    COMMENT: /#.*/


    ?rule: [decl] pattern pred ";" 
    ?decl: (type CNAME ",")* type CNAME ";" 
    ?type: integer | character | string | word #?type: number| character | pointer | void
    #?number: num | sign num 
    ?integer: "int"  #?num: "int" | "short" | "long" | "float" | "double" 
    #?sign: "signed" | "unsigned"
    ?character: "char" 
    ?string: "string"  #?pointer: "*" | type "*" 
    ?word: "word"       #?void: "void"
    ?pattern: (api ",")* api ";"
    ?api: CNAME"("[parlist]")" | CNAME "=" CNAME"("[parlist]")"
    ?parlist: (par ",")* par
    ?par: CNAME | QMARK
    QMARK: "?" 
    pred: neg | pred BOP neg 
    neg: term | NEG term 
    term: TRUE | FALSE | spred | apred | "("pred")" 
    spred: sptr IOP clist   #ci serve?
    sptr: CNAME | CNAME "[" NUMBER "]"
    clist: ESCAPED_STRING

    IOP: "IN"
    BOP: "AND" | "OR"
    NEG: "NOT"
    TRUE: "true"
    FALSE: "false"


    apred: sum COP sum
    COP: "==" | "<" | ">" | ">=" | "<=" | "!="
    sum: sum SOP prod | prod
    SOP: "+" | "-" 
    prod: atom| prod MOP atom
    MOP: "*" | "/" 
    atom: NUMBER | SIGN atom | CNAME | "(" sum ")" 
    SIGN: "-"


    %import common.NUMBER
    %import common.CNAME
    %import common.ESCAPED_STRING
    %import common.WS
    %ignore WS
    %ignore COMMENT
    %import common._STRING_ESC_INNER


"""


def parse_file(filename):
    # make a loop also

    p = Lark(grammar, parser='lalr', debug=True)  # lexer='standard'

    l = None

    with open(filename, "r") as file:
        data = file.read()
        l = p.parse(data)

    return l




def main():

    tree = parse_file("Features_ITASEC2021")   

    #print(tree.pretty)
    return tree


if __name__ == '__main__':
    tree = main()




