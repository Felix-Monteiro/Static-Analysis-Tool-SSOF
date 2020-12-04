import json

def main(argv):
    with open(argv[0], "r") as program_json:
        program_dict = json.loads(program_json.read())

    with open(argv[1], "r") as patterns_json:
        patterns_dict = json.loads(patterns_json.read())


    state.add_patterns(patterns_dict)
    program = Program()
    program.parse(program_dict)
    print(state.output)
    print(state.tainted_vars)
    pass


class State:
    def __init__(self):
        self.variables = {}
        self.tainted_vars = {}
        self.patterns = None
        self.output = []
        pass

    def add_patterns(self, patterns):
        self.patterns = patterns
        pass

    def add_tainted_var(self, var_name, source):
        self.tainted_vars[var_name] = source
        pass

    def remove_tainted_var(self, var_name):
        self.tainted_vars.pop(var_name)
        pass

    def var_is_tainted(self, var_name):
        return(self.tainted_vars.get(var_name))

    def add_variable(self, var_name, raw):
        self.variables[var_name] = raw
        pass

    # is the possible source in patterns
    def is_source(self, possible_source):
        for vulnerability in self.patterns:
            for source in vulnerability["sources"]:
                if(possible_source.__str__() == source):
                    return True
        return False

    # is the possible sanitizer in patterns
    def is_sanitizer(self, possible_sanitizer):
        for vulnerability in self.patterns:
            for sanitizer in vulnerability["sanitizers"]:
                if(possible_sanitizer.__str__() == sanitizer):
                    return True
        return False

    def check_sink(self,our_sink, our_source):
        sinks = []
        # get sinks related to this source
        for vulnerability in self.patterns:
            if(our_source in vulnerability["sources"] and our_source.find('(') == -1):
                sinks = vulnerability["sinks"]
                break
            elif(our_source.find('(') != -1 and self.get_sanitizer_and_source(our_source)[1] in vulnerability["sources"]):
                sinks = vulnerability["sinks"]

        # if sink is related to this source, then add it to result
        if(our_sink.find('.') == -1 and our_sink in sinks):
            self.add_vuln(our_source, our_sink)
        # for examples like our_sink: document.url.a  sink: document.url 
        elif(our_sink.find('.') != -1):
            for sink in sinks:
                if(our_sink.find(sink) != -1):
                    self.add_vuln(our_source, sink)
                    break
        pass

    # add vulnerability to output
    def add_vuln(self, source, sink):
        if(source.find("(") == -1):
            self.output.append({'source':source,'sink':sink})
        else:
            sanitizer, source = self.get_sanitizer_and_source(source) 
            self.output.append({'source': source, 'sink': sink, 'sanitizer':sanitizer})
        pass

    # get sanitized source and return list [santizer, source]
    def get_sanitizer_and_source(self, sanitized_source):
        return sanitized_source.split('(')

    # receives sanitizer and list of sources to sanitize
    def sanitize_sources(self, sanitizer, sources):
        sanitized_sources = []
        for source in sources:
            sanitized_sources.append(self.sanitize_source(sanitizer, source))
        return sanitized_sources
    
    # sanitize a single source with sanitizer
    # if sanitizer and source are of the same vulnerability then add sanitizer
    def sanitize_source(self, our_sanitizer, our_source):
        sanitizers = []
        for vulnerability in self.patterns:
            if(our_source.__str__() in vulnerability["sources"]):
                sanitizers = vulnerability["sanitizers"]
                break
        if(our_sanitizer in sanitizers):
            return self.add_sanitizer(our_source, our_sanitizer)
        return our_source

    # source -> sanitizer(source
    def add_sanitizer(self, source, sanitizer):
        return sanitizer + "(" + source



class Program:
    def __init__(self):
        self.body = []
        pass

    def parse(self, statements):
        for statement in statements["body"]:
            statement_obj = globals()[statement["type"]]()
            statement_obj.parse(statement)
            self.body.append(statement_obj)


class BlockStatement:
    def __init__(self):
        self.body = []
        pass

    def parse(self, statements):
        for statement in statements["body"]:
            statement_obj = globals()[statement["type"]]()
            statement_obj.parse(statement)
            self.body.append(statement_obj)
        pass


class WhileStatement:
    def __init__(self):
        self.test = None
        self.body = None
        pass

    def parse(self, statements):
        self.test = globals()[statements["test"]["type"]]()
        self.test.parse(statements["test"])

        self.body = globals()[statements["body"]["type"]]()
        self.body.parse(statements["body"])
        pass
        

class IfStatement:
    def __init__(self):
        self.test = None
        self.consequent = None
        self.alternate = None
        pass
    
    def parse(self, statements):
        self.test = globals()[statements["test"]["type"]]()
        self.test.parse(statements["test"])
        
        self.consequent = globals()[statements["consequent"]["type"]]()
        self.consequent.parse(statements["consequent"])
        
        self.alternate = globals()[statements["alternate"]["type"]]()
        self.alternate.parse(statements["alternate"])
        pass


class ExpressionStatement:
    def __init__(self):
        self.expression = None
        self.directive = None
        pass

    def parse(self, statements):
        self.expression = globals()[statements["expression"]["type"]]()
        self.expression.parse(statements["expression"])
        pass


class AssignmentExpression:
    def __init__(self):
        self.operator = ""
        self.left = None
        self.right = None
        pass
    
    def __str__(self):
        return self.left.__str__() + self.operator + self.right.__str__()

    def __repr__(self):
        return self.__str__()
    
    def parse(self, statements):
        self.operator = statements["operator"]
       
        left_type = statements["left"]["type"]
        self.left = globals()[left_type]()
        self.left.parse(statements["left"])
       
        self.right = globals()[statements["right"]["type"]]()
        self.right.parse(statements["right"])

        sources = self.right.is_source()

        if (left_type == "Identifier"):
            # if left is a variable mark as tainted
            if(sources):
                state.add_tainted_var(self.left.__str__(), sources)
                return
            # if left is a variable that was tainted now it is not
            # because it was assigned something with no sources
            elif(state.var_is_tainted(self.left)):
                state.remove_tainted_var(self.left)
                return

        elif(left_type == "MemberExpression"): 
            for source in sources:
                state.check_sink(self.left,source)
        pass

    def is_source(self):
        return self.right.is_source()


class BinaryExpression:
    def __init__(self):
        self.operator = None
        self.left = None
        self.right = None
        pass

    def __str__(self):
        return self.left.__str__() + self.operator + self.right.__str__()

    def __repr__(self):
        return self.__str__()

    def parse(self, statements):
        self.operator = statements["operator"]
       
        self.left = globals()[statements["left"]["type"]]()
        self.left.parse(statements["left"])
       
        self.right = globals()[statements["right"]["type"]]()
        self.right.parse(statements["right"])
        pass

    def is_source(self):
        sources = []
        sources.extend(self.right.is_source())
        sources.extend(self.left.is_source())
        return sources



class MemberExpression:
    def __init__(self):
        self.computed = None
        self.object = None
        self.property = None
        pass

    def __str__(self):
        return self.object.__str__() + "." + self.property.__str__()

    def __repr__(self):
        return self.__str__()

    def parse(self, statements):
        self.computed = statements["computed"]
       
        object_type = statements["object"]["type"]
        self.object = globals()[object_type]()
        self.object.parse(statements["object"])

        self.property = globals()[statements["property"]["type"]]()
        self.property.parse(statements["property"])
        pass

    def is_source(self):
        sources = []
        if(state.is_source(self.object)):
            sources.extend(self.__str__())
        elif (state.is_source(self)):
            sources.append(self.__str__())
        return sources


class CallExpression:
    def __init__(self):
        self.callee = None
        self.arguments = []
        pass
    
    def __str__(self):
        args_string = ",".join(map( str, self.arguments))
        return self.callee.__str__() + "(" + args_string + ")"

    def __repr__(self):
        return self.__str__()

    def parse(self, statements):
        self.callee = globals()[statements["callee"]["type"]]()
        self.callee.parse(statements["callee"])
        sources = []
        for argument in statements["arguments"]:
            argument_type = argument["type"]
            argument_obj = globals()[argument_type]()
            self.arguments.append(argument_obj)
            argument_obj.parse(argument)
            # get args that are sources
            sources.extend(argument_obj.is_source())
        
        for source in sources:
            state.check_sink(self.callee.__str__(),source.__str__())

        pass

    def is_source(self):
        sources = []
        callee = self.callee.__str__()
        if(state.is_source(callee)):
            sources.append(callee)
        
        for argument in self.arguments:
            res = argument.is_source()
            sources.extend(res)

        if(state.is_sanitizer(callee) and sources):
            sources = state.sanitize_sources(callee, sources)

        return sources

class Identifier:
    def __init__(self):
        self.name = ""
        pass

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

    def parse(self, statements):
        self.name = statements["name"]
        pass

    def is_source(self):
        res = state.var_is_tainted(self.name)
        return ( [] if res == None else res)


class Literal:
    def __init__(self):
        self.value = None
        self.raw = None
        pass

    def __str__(self):
        return self.raw

    def __repr__(self):
        return self.__str__()

    def parse(self, statements):
        self.value = statements["value"]
        self.raw = statements["raw"]
        pass

    def is_source(self):
        return []


state = State()