Module to load WebAssembly files into Ghidra, supporting disassembly and decompilation.

Currently able to disassemble and decompile simple modules, still needs some debugging and feature work to be production-ready. 

TODO:
- [ ] Debug intraprocedural control flow
- [ ] Parse type section
- [ ] Convert type definitions to Ghidra function signatures
- [ ] Handle function call sites
- [ ] Table/ref instructions
- [ ] `br_table` disassembly
