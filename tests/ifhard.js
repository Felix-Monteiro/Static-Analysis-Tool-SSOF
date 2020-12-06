if (bla) {
    sink1(a)
    a = source1()
} else if (source1()){
    a = source2()
    sanitize(a)
    escape(a)
    sink2(a)
} else {
    sink1(a)
}