from lark import Lark
import logging

logging.basicConfig(level=logging.DEBUG)
grammar = r"""

    ?start: (line)*
    ?line: rule
    COMMENT: /#.*/


    ?rule: pattern pred ";" 
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
    atom: NUMBER | CNAME | SIGN atom | "(" sum ")" | "0x"NUMBER #| "&"CNAME | "0x"NUMBER
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

    p = Lark(grammar, parser='lalr', debug=True)  # lexer='standard'

    l = None

    with open(filename, "r") as file:
        data = file.read()
        l = p.parse(data)

    return l




def main():

    tree = parse_file("rules.txt")   

    return tree


if __name__ == '__main__':
    tree = main()

    print(tree)
    




