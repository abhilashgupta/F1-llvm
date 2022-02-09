import pyfuzzer
import sys
import json
import os
from pprint import pprint
def main():
    if len(sys.argv) < 2:
        print('''
Usage: python3 mymain.py <grammar.json>
                ''')
        sys.exit(1)
    gfile = sys.argv[1]
    with open(gfile) as gf:
        fc = gf.read()
        my_grammar = json.loads(fc)
    c_grammar = pyfuzzer.CTrans(my_grammar).translate()
    print(c_grammar)

    # vm_ops, main_src, fuzz_src = myfuzzer.CFWriteCTFuzzer(c_grammar).fuzz_src()
    # with open('vm_ops.s', 'w+') as f:
    #     print(vm_ops, file=f)
    # with open('main.c', 'w+') as f:
    #     print(main_src, file=f)
    # with open('fuzz.S', 'w+') as f:
    #     print(fuzz_src, file=f)

    t = pyfuzzer.PyRecCompiledFuzzer(c_grammar).fuzz_src()
    with open('fuzz.py', 'w') as f:
        print(t, file=f)

    # m,t = myfuzzer.CFuzzer(c_grammar).fuzz_src()
    # with open('t1.c', 'w+') as f:
    #     print(t, file=f)
    # with open('m1.c', 'w+') as f:
    #     print(m, file=f)

    # m,t = myfuzzer.CFWriteDTFuzzer(c_grammar).fuzz_src()

    # with open('ct.c', 'w+') as f:
    #     print(t, file=f)
    # with open('cm.c', 'w+') as f:
    #     print(m, file=f)

    l = pyfuzzer.LlvmIrFuzzer(c_grammar).fuzz_src()
    pprint(l)

    uname = os.uname()
    print('\nNext step:')
    if uname.sysname == "Darwin":
        print('$ cc -g -Ofast -o fuzzer main.c fuzz.S')
    elif uname.sysname == "Linux":
        print('$ clang -g -Ofast -mcmodel=medium  -o fuzzer main.c fuzz.S')
    print('''$ rm -f io.x
$ ./fuzzer 0 1000 1000
$ cat io.x
''')

main()
