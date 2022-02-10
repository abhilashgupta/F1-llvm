import fuzzer
import sys
import json
import os
from pprint import pprint
def main():
    if len(sys.argv) < 2:
        print('''
Usage: python3 main.py <grammar.json>
                ''')
        sys.exit(1)
    gfile = sys.argv[1]
    with open(gfile) as gf:
        fc = gf.read()
        my_grammar = json.loads(fc)
    c_grammar = pyfuzzer.CTrans(my_grammar).translate()

    l = pyfuzzer.LlvmIrFuzzer(c_grammar).fuzz_src()
    with open('fuzz.ll', 'w') as f:
        print(l, file=f)

    uname = os.uname()
    print('\nNext step:')
    if uname.sysname == "Darwin":
        print('$ clang -o fuzzer fuzz.ll')
    elif uname.sysname == "Linux":
        print('$ clang -o fuzzer fuzz.ll')
    print('''$ rm -f io.x
$ ./fuzzer > io.x
$ cat io.x
''')

main()
