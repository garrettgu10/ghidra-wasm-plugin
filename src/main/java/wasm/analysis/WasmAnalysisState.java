package wasm.analysis;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import wasm.file.WasmModule;
import wasm.format.WasmFuncSignature;
import wasm.format.WasmEnums.WasmExternalKind;
import wasm.format.sections.WasmFunctionSection;
import wasm.format.sections.WasmImportSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.WasmTypeSection;
import wasm.format.sections.structures.WasmFuncType;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmAnalysisState {
	private static HashMap<Program, WasmAnalysisState> states = new HashMap<>();
	public static WasmAnalysisState getState(Program p) {
		if(!states.containsKey(p)) {
			System.out.println("Creating new analysis state for "+p.getName());
			states.put(p, new WasmAnalysisState(p));
		}
		return states.get(p);
	}
	
	private Program program;
	private HashMap<Function, WasmFunctionAnalysisState> funcStates = new HashMap<>();
	private WasmFunctionAnalysisState currMetaFunc = null;
	private WasmModule module = null;
	private ArrayList<WasmFuncSignature> functions = null;
	
	public WasmAnalysisState(Program p) {
		this.program = p;
	}
	
	public WasmFunctionAnalysisState getFuncState(Function f) {
		if(!funcStates.containsKey(f)) {
			System.out.println("Creating new function analysis state for "+f.getName());
			funcStates.put(f, new WasmFunctionAnalysisState(this));
		}
		return funcStates.get(f);
	}
	
	public void setModule(WasmModule module) {
		this.module = module;
	}
	
	public WasmFuncSignature getFuncSignature(int funcIdx) {
		return functions.get(funcIdx);
	}
	
	public void findFunctionSignatures() {
		functions = new ArrayList<>();
		WasmImportSection importSec = (WasmImportSection) module.getSection(WasmSectionId.SEC_IMPORT).getPayload();
		WasmTypeSection typeSec = (WasmTypeSection) module.getSection(WasmSectionId.SEC_TYPE).getPayload(); 
		if(importSec != null) {
			List<WasmImportEntry> imports = importSec.getEntries();
			for(WasmImportEntry entry : imports) {
				if(entry.getKind() != WasmExternalKind.EXT_FUNCTION) continue;
				int typeIdx = entry.getFunctionType();
				WasmFuncType funcType = typeSec.getType(typeIdx);
				
				functions.add(new WasmFuncSignature(funcType.getParamTypes(), funcType.getReturnTypes(), entry.getName(), null));
			}
		}
		
		WasmFunctionSection funcSec = (WasmFunctionSection) module.getSection(WasmSectionId.SEC_FUNCTION).getPayload();
		if(funcSec != null) {
			FunctionIterator funcIter = program.getFunctionManager().getFunctions(true);
			int i = 0;
			for(Function func : funcIter) {
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
	
	public void startCollectingMetas(Function f) {
		this.currMetaFunc = getFuncState(f);
	}
	
	public void stopCollectingMetas() {
		this.currMetaFunc = null;
	}
	
	public void performResolution() {
		for(HashMap.Entry<Function, WasmFunctionAnalysisState> entry: funcStates.entrySet()) {
			entry.getValue().performResolution();
		}
	}
	
	public void collectMeta(MetaInstruction meta) {
		if(currMetaFunc == null) return;
		currMetaFunc.collectMeta(meta);
	}
}
