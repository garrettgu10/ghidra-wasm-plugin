package wasm.pcodeInject;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayloadCallother;

public class InjectPayloadWasm extends InjectPayloadCallother {

	protected SleighLanguage language;
	protected long uniqueBase;

	public InjectPayloadWasm(String sourceName, SleighLanguage language, long uniqBase) {
		super(sourceName);
		this.language = language;
		this.uniqueBase = uniqBase;
	}

}
