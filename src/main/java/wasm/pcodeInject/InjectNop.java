package wasm.pcodeInject;

import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;

public class InjectNop extends InjectPayloadWasm{
	public InjectNop(String sourceName) {
		super(sourceName);
	}
	
	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		return new PcodeOp[] {};
	}
}
