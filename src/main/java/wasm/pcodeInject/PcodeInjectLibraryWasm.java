package wasm.pcodeInject;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryWasm extends PcodeInjectLibrary{
	
	private Map<String, InjectPayloadWasm> implementedOps;
	
	public static final String POP32 = "pop32CallOther";
	public static final String PUSH32 = "push32CallOther";
	public static final String POP64 = "pop64CallOther";
	public static final String PUSH64 = "push64CallOther";
	
	public static final String SOURCENAME = "wasmsource";

	public PcodeInjectLibraryWasm(SleighLanguage l) {
		super(l);
		
		implementedOps = new HashMap<>();
		implementedOps.put(POP32, new InjectNop(SOURCENAME));
		implementedOps.put(PUSH32, new InjectNop(SOURCENAME));
		implementedOps.put(POP64, new InjectNop(SOURCENAME));
		implementedOps.put(PUSH64, new InjectNop(SOURCENAME));
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
