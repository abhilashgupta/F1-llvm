# F1-llvm
llvm IR implementation of the F1 fuzzer (https://github.com/vrthra/F1)

To execute any of the handwritten IR files (`basic_handwritten_gram.ll` or `slightly_complex_handwritten_gram.ll`), just compile it with "clang <IR-file>" and then execute "./a.out".
These are the IR files corresponding to `basic_gram.json` and `slightly_complex_gram.json`.


To generate an IR file corresponding to any grammar, please run `python3 main.py <grammarfile>`.
The next steps are printed on the terminal.