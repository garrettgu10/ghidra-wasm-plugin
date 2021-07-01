package wasm.analysis;

import java.util.ArrayList;

public class WasmFunctionAnalysisState {

	private ArrayList<MetaInstruction> metas = new ArrayList<>();
	
	public void collectMeta(MetaInstruction meta) {
		metas.add(meta);
	}
	
	@Override
	public String toString() {
		return metas.toString();
	}
}
