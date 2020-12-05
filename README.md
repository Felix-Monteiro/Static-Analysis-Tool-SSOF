# Project2-Group37

## _Project Tests:_

-Test 1: Sources in Member Expressions [(link)](test1.json)
-Test 2: Sources in Call Expressions[(link)](test2.json)
-Test 3: Sanitizers Member Expression[(link)](test3.json)
-Test 4: Sanitizers Call Expression[(link)](test4.json)
-Test 5: Sinks in Member Expression[(link)](test5.json)
-Test 6: Sinks in Call Expression [(link)](test6.json)


## _Notes:_
sources:
    MemberExpression:
        right em assignements (a = document.url)
        em arguments call expression  (sink(document.url))
    CallExpression:
        right em assignements (a = source())
        em arguments call expression (sink(source) ou a = c(source))

    right em assignements
    arguments em call expression

    
sanitizers:
    CallExpression:
        callee = sanitizer (sanitize(source))

sinks:
    MemberExpression:
        left em assignements (sink = tainted)
    CallExpression:
        callee = sink (sink(tainted))
        

now get only unique sources 
for example if sink1(source1(),source1(),source1(),source1()) 
only output one source: source1()