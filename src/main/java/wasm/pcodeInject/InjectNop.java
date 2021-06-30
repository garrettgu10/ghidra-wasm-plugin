package wasm.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class InjectNop extends InjectPayloadWasm{
	public InjectNop(String sourceName, SleighLanguage language, long uniqBase) {
		super(sourceName, language, uniqBase);
	}
	
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOpEmitter pCode = new PcodeOpEmitter(language, con.baseAddr, this.uniqueBase);
		pCode.emitTestOp();
		return pCode.getPcodeOps();
	}
}
