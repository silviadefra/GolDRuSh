from lark import Lark
from sys import exit, argv

grammar = r"""

    ?start: (line)*
    ?line: rule
    COMMENT: /#.*/


    ?rule:type pattern pred ";" 
    ?type: (CNAME par ",")* CNAME par ";"
    ?pattern: (api ",")* api ";"
    ?api: CNAME"("[parlist]")" | CNAME "=" CNAME"("[parlist]")"
    ?parlist: (par ",")* par
    ?par: CNAME | QMARK
    QMARK: "?" 
    pred: neg | pred BOP neg 
    neg: term | NEG term 
    term: TRUE | FALSE | spred | apred | "("pred")" 
    spred: sptr IOP sptr
    sptr: CNAME | CNAME "[" NUMBER "]"

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
    atom: decorhex | CNAME | "(" sum ")"  #| "&"CNAME #non riesco a differenziare tra i due
    decorhex: ["+"|"-"] INT | "\\x" HEXDIGIT+


    %import common.INT
    %import common.HEXDIGIT
    %import common.NUMBER
    %import common.CNAME
    %import common.ESCAPED_STRING
    %import common.WS
    %ignore WS
    %ignore COMMENT
    %import common._STRING_ESC_INNER


"""


def parse_file(filename):

    p = Lark(grammar, parser='lalr', debug=True)  # lexer='standard'

    l = None

    with open(filename, "r") as file:
        data = file.read()
        l = p.parse(data)
        
    return l


def main(rules):
    tree = parse_file(rules)   
    return tree


if __name__ == '__main__':
    if len(argv) < 2:
        print("Usage: python grammar.py  <filename>")
        exit(1)

    rules_file = argv[1]
    tree = main(rules_file)
    print(tree)
    




