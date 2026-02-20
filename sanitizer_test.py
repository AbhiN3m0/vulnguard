import ast

def run(cmd):
    safe = ast.literal_eval(cmd)
    eval(safe)

x = input()
eval(x)

