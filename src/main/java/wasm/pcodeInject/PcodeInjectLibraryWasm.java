package wasm.pcodeInject;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

public class PcodeInjectLibraryWasm extends PcodeInjectLibrary{
	
	private Map<String, InjectPayloadWasm> implementedOps;
	
	public static final String POP = "popCallOther";
	public static final String PUSH = "pushCallOther";
	public static final String TEST = "testCallOther";
	
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
		implementedOps.put(POP, new InjectNop(SOURCENAME, l, getNextUniqueBase()));
		implementedOps.put(PUSH, new InjectNop(SOURCENAME, l, getNextUniqueBase()));
		implementedOps.put(TEST, new InjectNop(SOURCENAME, l, getNextUniqueBase()));
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
