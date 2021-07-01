package wasm.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import wasm.analysis.MetaInstruction;
import wasm.analysis.WasmAnalysisState;

public class InjectMeta extends InjectPayloadWasm{
	MetaInstruction.Type opKind;
	
	public InjectMeta(String sourceName, SleighLanguage language, long uniqBase, MetaInstruction.Type opKind) {
		super(sourceName, language, uniqBase);
		this.opKind = opKind;
	}
	
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		WasmAnalysisState analState = WasmAnalysisState.getState(program);
		analState.collectMeta(MetaInstruction.create(opKind, con, program));
		
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, this.uniqueBase);
		pCode.emitNop();
		return pCode.getPcodeOps();
	}
}
