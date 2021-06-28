package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmCustomSection implements WasmPayload {
	Leb128 namelen;
	byte[] name;
	byte[] contents;
	
	public WasmCustomSection (BinaryReader reader, int len) throws IOException {
		long readUntil = reader.getPointerIndex() + len;
		
		namelen = new Leb128(reader);
		name = reader.readNextByteArray((int)namelen.getValue());
		
		int contentlen = (int)(readUntil - reader.getPointerIndex());
		
		contents = reader.readNextByteArray(contentlen);
	}


	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("CustomSection", 0);
		structure.add(namelen.toDataType(), "name_len", null);
		structure.add(STRING, name.length, "name", null);
		structure.add(STRING, contents.length, "contents", null);
		return structure;
	}

	@Override
	public String getName() {
		return ".custom";
	}

}
