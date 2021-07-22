package wasm.pcodeInject;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import wasm.analysis.MetaInstruction;

public class PcodeInjectLibraryWasm extends PcodeInjectLibrary{
	
	private Map<String, InjectPayloadWasm> implementedOps;
	
	public static final String POP = "popCallOther";
	public static final String PUSH = "pushCallOther";
	public static final String BR = "brCallOther";
	public static final String BEGIN_LOOP = "beginLoopCallOther";
	public static final String BEGIN_BLOCK = "beginBlockCallOther";
	public static final String END = "endCallOther";
	public static final String IF = "ifCallOther";
	public static final String ELSE = "elseCallOther";
	public static final String RETURN = "returnCallOther";
	public static final String CALL = "callCallOther";
	public static final String CALL_INDIRECT = "callIndirectCallOther";
	
	public static final String SOURCENAME = "wasmsource";
	
	private long nextUniqueBase;
	public static final long BASE_CHUNK_SIZE = 0x200;
	
	public long getNextUniqueBase() {
		long res = nextUniqueBase;
		nextUniqueBase += BASE_CHUNK_SIZE;
		return res;
	}

	public PcodeInjectLibraryWasm(SleighLanguage l) {
		super(l);
		nextUniqueBase = this.uniqueBase;
		
		implementedOps = new HashMap<>();
		implementedOps.put(POP, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.POP));
		implementedOps.put(PUSH, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.PUSH));
		implementedOps.put(BR, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.BR));
		implementedOps.put(BEGIN_LOOP, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.BEGIN_LOOP));
		implementedOps.put(BEGIN_BLOCK, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.BEGIN_BLOCK));
		implementedOps.put(END, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.END));
		implementedOps.put(IF, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.IF));
		implementedOps.put(ELSE, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.ELSE));
		implementedOps.put(RETURN, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.RETURN));
		implementedOps.put(CALL, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.CALL));
		implementedOps.put(CALL_INDIRECT, new InjectMeta(SOURCENAME, l, getNextUniqueBase(), MetaInstruction.Type.CALL_INDIRECT));
	}
	
	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			InjectPayloadWasm payload = implementedOps.get(name);
			if (payload != null) {
				return payload;
			}
		}
		return super.allocateInject(sourceName, name, tp);
	}
}
