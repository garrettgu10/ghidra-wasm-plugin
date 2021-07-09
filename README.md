Module to load WebAssembly files into Ghidra, supporting disassembly and decompilation.

Currently able to disassemble and decompile simple modules, still needs some debugging and feature work to be production-ready. 

![image](https://user-images.githubusercontent.com/10344380/124648385-cea1cd80-de5c-11eb-81b6-d2e0039e1a0f.png)

TODO:
- [x] Debug intraprocedural control flow
- [x] Parse type section
- [x] Convert type definitions to Ghidra function signatures (skipped, might be better to just let the decompiler infer)
- [x] Handle function call sites
- [ ] Table/ref instructions
- [ ] `br_table` disassembly
