package wasm.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.MetaInstruction;
import wasm.analysis.WasmAnalysis;
import wasm.analysis.WasmFunctionAnalysis;

public class InjectMeta extends InjectPayloadWasm{
	MetaInstruction.Type opKind;
	
	public InjectMeta(String sourceName, SleighLanguage language, long uniqBase, MetaInstruction.Type opKind) {
		super(sourceName, language, uniqBase);
		this.opKind = opKind;
	}
	
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		WasmAnalysis analState = WasmAnalysis.getState(program);

		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, this.uniqueBase);
		if(analState.collectingMetas()) {
			analState.collectMeta(MetaInstruction.create(opKind, con, program));
			pCode.emitNop(); //just emit a nop so the pre-decompiler can move on
		}else {
			WasmFunctionAnalysis funcState = analState.getFuncState(
					program.getFunctionManager().getFunctionContaining(con.baseAddr));
			funcState.findMetaInstruction(con.baseAddr, this.opKind).synthesize(pCode);
		}
		
		return pCode.getPcodeOps();
	}
}
