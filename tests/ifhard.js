if(source2()) {
    a = source1()
} else {
    b = sink1
    c = source1()
    sanitize(c)
    sink1(c)
}
sink1(a)
sanitize(a)
sanitize(f)
b(a)
sink2(inner.html)
sink2(b)