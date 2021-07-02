package wasm.analysis;

import java.util.ArrayList;
import java.util.HashMap;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class WasmAnalysisState {
	private static HashMap<Program, WasmAnalysisState> states = new HashMap<>();
	public static WasmAnalysisState getState(Program p) {
		if(!states.containsKey(p)) {
			System.out.println("Creating new analysis state for "+p.getName());
			states.put(p, new WasmAnalysisState());
		}
		return states.get(p);
	}
	
	private HashMap<Function, WasmFunctionAnalysisState> funcStates = new HashMap<>();
	private WasmFunctionAnalysisState currMetaFunc = null;
	
	public WasmFunctionAnalysisState getFuncState(Function f) {
		if(!funcStates.containsKey(f)) {
			System.out.println("Creating new function analysis state for "+f.getName());
			funcStates.put(f, new WasmFunctionAnalysisState());
		}
		return funcStates.get(f);
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
