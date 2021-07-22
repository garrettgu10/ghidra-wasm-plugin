package wasm.analysis;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import wasm.file.WasmModule;
import wasm.format.Utils;
import wasm.format.WasmFuncSignature;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmAnalysis {
	private static HashMap<Program, WasmAnalysis> states = new HashMap<>();
	public static WasmAnalysis getState(Program p) {
		if(!states.containsKey(p)) {
			System.out.println("Creating new analysis state for "+p.getName());
			states.put(p, new WasmAnalysis(p));
		}
		return states.get(p);
	}
	
	private Program program;
	private HashMap<Function, WasmFunctionAnalysis> funcStates = new HashMap<>();
	private WasmFunctionAnalysis currMetaFunc = null;
	private WasmModule module = null;
	private ArrayList<WasmFuncSignature> functions = null;
	
	public WasmAnalysis(Program p) {
		this.program = p;
		
		Memory mem = program.getMemory();
		Address moduleStart = mem.getBlock(".module").getStart();
		ByteProvider memByteProvider = new MemoryByteProvider(mem, moduleStart);
		BinaryReader memBinaryReader = new BinaryReader(memByteProvider, true);
		WasmModule module = null;
		try {
			module = new WasmModule(memBinaryReader);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		this.module = module;
		
		this.findFunctionSignatures();
	}
	
	public Program getProgram() {
		return program;
	}
	
	public WasmFunctionAnalysis getFuncState(Function f) {
		if(!funcStates.containsKey(f)) {
			System.out.println("Creating new function analysis state for "+f.getName());
			funcStates.put(f, new WasmFunctionAnalysis(this, f));
		}
		return funcStates.get(f);
	}
	
	public void setModule(WasmModule module) {
		this.module = module;
	}
	
	public WasmFuncSignature getFuncSignature(int funcIdx) {
		return functions.get(funcIdx);
	}
	
	public WasmTypeSection getTypeSection() {
		return (WasmTypeSection) module.getSection(WasmSectionId.SEC_TYPE).getPayload();
	}
	
	public void findFunctionSignatures() {
		functions = new ArrayList<>();
		WasmSection importSection = module.getSection(WasmSectionId.SEC_IMPORT);
		WasmImportSection importSec = (WasmImportSection) (importSection == null? null : importSection.getPayload());
		WasmTypeSection typeSec = (WasmTypeSection) module.getSection(WasmSectionId.SEC_TYPE).getPayload(); 
		if(importSec != null) {
			List<WasmImportEntry> imports = importSec.getEntries();
			int funcIdx = 0;
			for(WasmImportEntry entry : imports) {
				if(entry.getKind() != WasmExternalKind.EXT_FUNCTION) continue;
				int typeIdx = entry.getFunctionType();
				WasmFuncType funcType = typeSec.getType(typeIdx);
				Address addr = Utils.toAddr(program, Utils.IMPORTS_BASE + Utils.IMPORT_STUB_LEN * funcIdx);
				
				functions.add(new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(), entry.getName(), addr));
				funcIdx++;
			}
		}
		
		WasmFunctionSection funcSec = (WasmFunctionSection) module.getSection(WasmSectionId.SEC_FUNCTION).getPayload();
		if(funcSec != null) {
			FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
			int i = 0;
			//non-imported functions will show up first and in order since we are iterating by entry point
			for(Function func : funcIter) {
				if(i >= funcSec.getTypeCount()) break;
				int typeidx = funcSec.getTypeIdx(i);
				WasmFuncType funcType = typeSec.getType(typeidx);
				
				functions.add(new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(), null, func.getEntryPoint()));
				i++;
			}
		}
	}
	
	public boolean collectingMetas() {
		return currMetaFunc != null;
	}
	
	public void startCollectingMetas(WasmFunctionAnalysis f) {
		this.currMetaFunc = f;
	}
	
	public void stopCollectingMetas() {
		this.currMetaFunc = null;
	}
	
	public void performResolution() {
		for(HashMap.Entry<Function, WasmFunctionAnalysis> entry: funcStates.entrySet()) {
			entry.getValue().performResolution();
		}
	}
	
	public void collectMeta(MetaInstruction meta) {
		if(currMetaFunc == null) return;
		currMetaFunc.collectMeta(meta);
	}
}
