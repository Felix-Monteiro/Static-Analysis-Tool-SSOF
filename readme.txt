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