import json
import pprint
def main(argv):
    with open(argv[0], "r") as program_json:
        program_dict = json.loads(program_json.read())

    with open(argv[1], "r") as patterns_json:
        patterns_dict = json.loads(patterns_json.read())


    state.add_patterns(patterns_dict)
    program = Program()
    program.parse(program_dict)
    print(json.dumps(state.output))

    #print(state.tainted_vars)
    #print(state.variables)
    pass


class State:
    def __init__(self):
        self.variables = {}
        self.tainted_vars = {}
        self.scope = []
        self.patterns = None
        self.output = []
        self.just_parse = False
        self.in_optional = False
        pass

    def add_patterns(self, patterns):
        self.patterns = patterns
        pass

    def add_variable(self, var_name, raw):
        if(self.in_optional and self.is_variable(var_name)):
            self.variables[var_name].append(raw)
        else :
            self.variables[var_name] = [raw]
        pass

    def add_tainted_var(self, var_name, sources):
        if(self.in_optional and self.var_is_tainted(var_name)):
            self.tainted_vars[var_name].extend(sources)
        else:
            self.tainted_vars[var_name] = sources
        self.tainted_vars[var_name] = list(set(self.tainted_vars[var_name]))
        pass

    # append sources that are tainting the current scope 
    def add_scope(self, sources):
        self.scope.extend(sources)
        pass

    def get_variables(self):
        return self.variables.copy()

    def get_tainted_vars(self):
        return self.tainted_vars.copy()

    # remove sources that are no longer tainting the current scope
    def remove_a_scope(self, sources):
        for source in sources:
            self.scope.remove(source)
        pass
    
    def remove_tainted_var(self, var_name):
        if(not self.in_optional):
            self.tainted_vars.pop(var_name)
        pass

    # When we want to only parse, not find sinks
    # for example, the while statement. We first want to 
    # parse everything then look for sinks
    # For the cases where the source is after the sink in a while statement
    # while(a) {
    #    sink(b)
    #    b = source()
    # }
    def set_just_parse(self, boolean):
        self.just_parse = boolean
        pass

    def set_in_optional(self, boolean):
        self.in_optional = boolean
        pass

    def set_tainted_vars(self, tainted_vars):
        self.tainted_vars = tainted_vars
        pass

    def set_variables(self, variables):
        self.variables = variables
        pass

    def var_is_tainted(self, var_name):
        return(self.tainted_vars.get(var_name))

    # is the possible source in patterns
    def is_source(self, possible_source):
        possible_source = self.get_sanitizer_and_source(possible_source)[-1]
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

    # return true if source is sanitized
    def is_sanitized(self, source):
        return source.find(":") != -1

    def is_variable(self, var_name):
        return var_name in self.variables

    def get_variable(self, var_name):
        return self.variables[var_name]

    def get_tainted_variable(self, var_name):
        return self.tainted_vars[var_name]

    def check_sink(self,our_sink, our_source):
        sinks = []
        our_sanitizers = []
        # if sanitized, get source and sanitizer
        if(self.is_sanitized(our_source)):
            res = self.get_sanitizer_and_source(our_source)
            our_sanitizers = res[:-1]
            our_source = res[-1]
        
        # get sinks related to this source        
        for vulnerability in self.patterns:
            if(our_source in vulnerability["sources"]):
                sinks = vulnerability["sinks"]
                our_vulnerability = vulnerability["vulnerability"]
                # if sink is related to this source, then add it to result
                if(our_sink.find('.') == -1 and our_sink in sinks):
                    self.add_vuln(our_vulnerability, our_source, our_sink, our_sanitizers)
                # for examples like our_sink: document.url.a  sink: document.url 
                elif(our_sink.find('.') != -1):
                    for sink in sinks:
                        if(our_sink.find(sink) != -1):
                            self.add_vuln(our_vulnerability, our_source, sink, our_sanitizers)
                            break
        pass

    # add vulnerability to output
    def add_vuln(self, vulnerability, source, sink, sanitizer):
        self.output.append({"vulnerability": vulnerability ,"source": source, "sink": sink, "sanitizer":sanitizer})
        pass

    # get sanitized source and return list [santizer, source]
    def get_sanitizer_and_source(self, sanitized_source):
        return sanitized_source.split(":")

    def sanitize_variable(self, sanitizer_name, var_name):
        if(self.var_is_tainted(var_name)):
            sanitized = self.sanitize_sources(sanitizer_name, self.get_tainted_variable(var_name))
            self.add_tainted_var(var_name, sanitized)
        pass

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
            if(self.get_sanitizer_and_source(our_source.__str__())[-1] in vulnerability["sources"]):
                sanitizers = vulnerability["sanitizers"]
                break
        if(our_sanitizer in sanitizers):
            return self.add_sanitizer(our_source, our_sanitizer)
        return our_source

    # source -> sanitizer:source
    def add_sanitizer(self, source, sanitizer):
        return sanitizer + ":" + source


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

    def __str__(self):
        string = "{ \n"
        for statement in self.body:
            string += "    " + statement.__str__() + "\n" 
        return string + "}"

    def __repr__(self):
        return self.__str__()

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
        sources = self.test.is_source()

        state.add_scope(sources)
        prev_just_parse = state.just_parse
        prev_in_optional = state.in_optional
        state.set_just_parse(True)
        state.set_in_optional(True)
        self.body = globals()[statements["body"]["type"]]()
        self.body.parse(statements["body"])
        state.set_just_parse(False)
        self.body.parse(statements["body"])

        state.set_just_parse(prev_just_parse)
        state.set_in_optional(prev_in_optional)
        state.remove_a_scope(sources)
        pass
        

class SequenceExpression:
    def __init__(self):
        self.expressions = []
        pass

    def __str__(self):
        string = ""
        for expression in self.expressions:
            string += expression.__str__() + "," 
        return string[:-1]

    def __repr__(self):
        return self.__str__()

    def parse(self, statements):
        for statement in statements["expressions"]:
            statement_obj = globals()[statement["type"]]()
            statement_obj.parse(statement)
            self.expressions.append(statement_obj)
        pass

    def is_source(self):
        sources = []
        for expression in self.expressions:
            sources.extend(expression.is_source())
        return list(set(sources))

class IfStatement:
    def __init__(self):
        self.test = None
        self.consequent = None
        self.alternate = None
        pass
    
    def parse(self, statements):
        self.test = globals()[statements["test"]["type"]]()
        self.test.parse(statements["test"])
        sources = self.test.is_source()
        
        state.add_scope(sources)

        # dont commit variables but commit sinks
        variables_before = state.get_variables()
        tainted_vars_before = state.get_tainted_vars()

        self.consequent = globals()[statements["consequent"]["type"]]()
        self.consequent.parse(statements["consequent"])
        
        state.set_variables(variables_before)
        state.set_tainted_vars(tainted_vars_before)

        variables_before = state.get_variables()
        tainted_vars_before = state.get_tainted_vars()

        if(statements["alternate"]):
            self.alternate = globals()[statements["alternate"]["type"]]()
        if(self.alternate):
            self.alternate.parse(statements["alternate"])

        state.set_variables(variables_before)
        state.set_tainted_vars(tainted_vars_before)
        # dont commit variables but commit sinks


        # commit variables but dont commit sinks
        previous_just_parse = state.just_parse
        prev_in_optional = state.in_optional
        state.set_in_optional(True)
        state.set_just_parse(True)
        self.consequent.parse(statements["consequent"])
        if(self.alternate):
            self.alternate.parse(statements["alternate"])
        state.set_just_parse(previous_just_parse)
        state.set_in_optional(prev_in_optional)
        # commit variables but dont commit sinks


        state.remove_a_scope(sources)
        pass


class ExpressionStatement:
    def __init__(self):
        self.expression = None
        self.directive = None
        pass

    def __str__(self):
        return self.expression.__str__() + (self.directive if self.directive != None else "")

    def __repr__(self):
        return self.__str__()
    
    def parse(self, statements):
        self.expression = globals()[statements["expression"]["type"]]()
        self.expression.parse(statements["expression"])
        pass

    def is_source(self):
        return self.expression.is_source()

    def sanitize(self, sanitizer_name):
        self.expression.sanitize()
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
        # add sources that are tainting the scope
        sources.extend(state.scope)
        # dont commit variables inside ifs
        state.add_variable(self.left.__str__(), self.right.__str__())
        # if right has sources then had variable to tainted variables
        if(sources):
            state.add_tainted_var(self.left.__str__(), sources)

        # if left is a variable that was tainted now it is not
        # because it was assigned something with no sources
        if (not sources and state.var_is_tainted(self.left.__str__())):
            state.remove_tainted_var(self.left.__str__())

        # left side MemberExpression can be source
        elif(left_type == "MemberExpression" and not state.just_parse):
            for source in sources:
                state.check_sink(self.left.__str__(),source.__str__())
        pass

    def is_source(self):
        return self.right.is_source()

       
    def sanitize(self, sanitizer_name):
        self.left.sanitize()
        self.right.sanitize()
        pass
        

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
        return list(set(sources))

    # dont sanitize binary expressions
    def sanitize(self, sanitizer_name):
        pass
        


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

        if(object_type == "Identifier" and state.is_variable(self.object.__str__())):
            self.object = state.get_variable(self.object.__str__())
        pass

    def is_source(self):
        sources = []
        if(state.is_variable(self.__str__())):
            sources.extend(state.var_is_tainted(self.__str__()))
        elif(isinstance(self.object, list)):
            for option in self.object:
                option_member = option + "." + self.property.__str__()
                if(state.is_source(option)):
                    sources.append(option)
                elif(state.is_source(option_member)):
                    sources.append(option_member)

        elif(state.is_source(self.object.__str__())):
            sources.append(self.object.__str__())
        elif(state.is_source(self.__str__())):
            sources.append(self.__str__())
        return list(set(sources))

       
    def sanitize(self, sanitizer_name):
        member_name = self.__str__()
        if(state.is_source(member_name)):
            if(not state.is_variable(member_name)):
                state.add_variable(member_name, member_name)
                state.add_tainted_var(member_name, [member_name])
            state.sanitize_variable(sanitizer_name, member_name)
        pass
        

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
        callee_type = statements["callee"]["type"]
        self.callee = globals()[callee_type]()
        self.callee.parse(statements["callee"])
        
        if(callee_type == "MemberExpression" and isinstance(self.callee.object,list)):
                callee = []
                for option in self.callee.object:
                    callee.append(option + "." + self.callee.property.__str__())
                self.callee = callee
        elif(state.is_variable(self.callee.__str__())):
            self.callee = state.get_variable(self.callee.__str__())
        else:
            self.callee = [self.callee.__str__()]

        sources = []

        for argument in statements["arguments"]:
            argument_type = argument["type"]
            argument_obj = globals()[argument_type]()
            self.arguments.append(argument_obj)
            argument_obj.parse(argument)
            # get args that are sources
            print(argument_obj)
            sources.extend(argument_obj.is_source())
            
        for possible_callee in self.callee:
            if(state.is_sanitizer(possible_callee)):
                for argument in self.arguments:
                    argument.sanitize(possible_callee)
            
        # add sources that are tainting the scope
        sources.extend(state.scope)
        # remove repeated values
        sources = list(set(sources))
        if(not state.just_parse):
            for possible_callee in self.callee:
                for source in sources:
                    state.check_sink(possible_callee,source)
        pass

    def is_source(self):
        sources = []
        for argument in self.arguments:
                res = argument.is_source()
                sources.extend(res)

        for possible_callee in self.callee:
            if(state.is_source(possible_callee)):
                sources.append(possible_callee)
        
            if(state.is_sanitizer(possible_callee) and sources):
                sources = state.sanitize_sources(possible_callee, sources)

        return list(set(sources))

    
    def sanitize(self, sanitizer_name):
        pass
        

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

    def sanitize(self, sanitizer_name):
        state.sanitize_variable(sanitizer_name, self.name)
        pass


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

    def sanitize(self, sanitizer_name):
        pass

state = State()