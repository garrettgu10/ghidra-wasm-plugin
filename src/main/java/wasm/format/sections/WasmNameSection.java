package wasm.format.sections;

import java.io.IOException;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import wasm.format.Leb128;

public class WasmNameSection extends WasmCustomSection {
	String moduleName = "None";
	HashMap<Integer, String> functionNames = new HashMap<>();

	public WasmNameSection(Leb128 namelen, String name, BinaryReader r, int contentlen) throws IOException {
		super(namelen, name, r, contentlen);
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(this.contents), true);
		while(reader.getPointerIndex() < this.contents.length) {
			readSubsection(reader);
		}
	}
	
	private String readName(BinaryReader reader) throws IOException {
		long len = new Leb128(reader).getValue();
		return new String(reader.readNextByteArray((int)len));
	}
	
	private Map.Entry<Integer, String> readAssoc(BinaryReader reader) throws IOException {
		int idx = (int)new Leb128(reader).getValue();
		String name = readName(reader);
		
		return new AbstractMap.SimpleEntry<>(idx, name);
	}
	
	private void readSubsection(BinaryReader reader) throws IOException {
		byte sectionId = reader.readNextByte();
		long size = new Leb128(reader).getValue();
		byte[] subContents = reader.readNextByteArray((int)size);
		BinaryReader subReader = new BinaryReader(new ByteArrayProvider(subContents), true);
		switch(sectionId) {
		case 0: //module name section
			moduleName = readName(subReader);
			return;
		case 2: //local name section
			//no handling yet
			return;
		case 1: //function name section
			long numAssoc = new Leb128(subReader).getValue();
			for(int i = 0; i < numAssoc; i++) {
				Map.Entry<Integer, String> assoc = readAssoc(subReader);
				functionNames.put(assoc.getKey(), assoc.getValue());
			}
			return;
		}
	}
	
	public String getFunctionName(int idx) {
		return functionNames.getOrDefault(idx, null);
	}
	
	@Override
	public String getName() {
		return ".name";
	}
}
