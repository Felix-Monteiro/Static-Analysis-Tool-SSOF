import ast
import json
import grammar
from pprint import pprint

def main(argv):
    with open(argv[0], "r") as program_json:
        program_dict = json.loads(program_json.read())

    program = Program()
    program.evaluate(program_dict)
    program.body[0]
    pass



class Program:
    def __init__(self):
        self.body = []
        pass

    def evaluate(self, statements):
        for statement in statements["body"]:
            statement_obj = globals()[statement["type"]]()
            statement_obj.evaluate(statement)
            self.body.append(statement_obj)


class BlockStatement:
    def __init__(self):
        self.body = []
        pass

    def evaluate(self, statements):
        for statement in statements["body"]:
            statement_obj = globals()[statement["type"]]()
            statement_obj.evaluate(statement)
            self.body.append(statement_obj)

class WhileStatement:
    def __init__(self):
        self.test = None
        self.body = None
        pass

    def evaluate(self, statements):
        self.test = globals()[statements["test"]["type"]]()
        self.test.evaluate(statements["test"])

        self.body = globals()[statements["body"]["type"]]()
        self.body.evaluate(statements["body"])
        pass
        
class IfStatement:
    def __init__(self):
        self.test = None
        self.consequent = None
        self.alternate = None
        pass
    
    def evaluate(self, statements):
        self.test = globals()[statements["test"]["type"]]()
        self.test.evaluate(statements["test"])
        
        self.consequent = globals()[statements["consequent"]["type"]]()
        self.consequent.evaluate(statements["consequent"])
        
        self.alternate = globals()[statements["alternate"]["type"]]()
        self.alternate.evaluate(statements["alternate"])
        pass

class ExpressionStatement:
    def __init__(self):
        self.expression = None
        self.directive = None
        pass

    def evaluate(self, statements):
        self.expression = globals()[statements["expression"]["type"]]()
        self.expression.evaluate(statements["expression"])
        pass

class AssignmentExpression:
    def __init__(self):
        self.operator = None
        self.left = None
        self.right = None
        pass

    def evaluate(self, statements):
        self.operator = statements["operator"]
       
        self.left = globals()[statements["left"]["type"]]()
        self.left.evaluate(statements["left"])
       
        self.right = globals()[statements["right"]["type"]]()
        self.right.evaluate(statements["right"])
        pass

class BinaryExpression:
    def __init__(self):
        self.operator = None
        self.left = None
        self.right = None
        pass

    def evaluate(self, statements):
        self.operator = statements["operator"]
       
        self.left = globals()[statements["left"]["type"]]()
        self.left.evaluate(statements["left"])
       
        self.right = globals()[statements["right"]["type"]]()
        self.right.evaluate(statements["right"])
        pass

class MemberExpression:
    def __init__(self):
        self.computed = None
        self.object = None
        self.property = None
        pass

    def evaluate(self, statements):
        self.computed = statements["computed"]
       
        self.object = globals()[statements["object"]["type"]]()
        self.object.evaluate(statements["object"])
       
        self.property = globals()[statements["property"]["type"]]()
        self.property.evaluate(statements["property"])
        pass

class CallExpression:
    def __init__(self):
        self.callee = None
        self.arguments = []
        pass

    def evaluate(self, statements):
        self.callee = globals()[statements["callee"]["type"]]()
        self.callee.evaluate(statements["callee"])
       
        for argument in statements["arguments"]:
            argument_obj = globals()[argument["type"]]()
            self.arguments.append(argument_obj)
            argument_obj.evaluate(argument)
        pass


class Identifier:
    def __init__(self):
        self.name = None
        self.raw = None
        pass

    def evaluate(self, statements):
        self.name = statements["name"]
        pass

class Literal:
    def __init__(self):
        self.value = None
        self.raw = None
        pass

    def evaluate(self, statements):
        self.value = statements["value"]
        self.raw = statements["raw"]
        pass