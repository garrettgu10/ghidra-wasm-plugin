package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmCustomSection implements WasmPayload {
	Leb128 namelen;
	String name;
	byte[] contents;
	
	protected WasmCustomSection (Leb128 namelen, String name, BinaryReader reader, int contentlen) throws IOException {
		this.namelen = namelen;
		this.name = name;
		contents = reader.readNextByteArray(contentlen);
	}
	
	public static WasmCustomSection create(BinaryReader reader, long len) throws IOException {
		long readUntil = reader.getPointerIndex() + len;
		
		Leb128 namelen = new Leb128(reader);
		String name = new String(reader.readNextByteArray((int)namelen.getValue()));
		
		int contentlen = (int)(readUntil - reader.getPointerIndex());
		
		if(name.equals("name")) {
			return new WasmNameSection(namelen, name, reader, contentlen);
		}
		
		return new WasmCustomSection(namelen, name, reader, contentlen);
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(namelen.toDataType(), "name_len", null);
		structure.add(StructConverter.STRING, name.length(), "name", null);
		structure.add(StructConverter.STRING, contents.length, "contents", null);
	}

	@Override
	public String getName() {
		return ".custom";
	}

}
