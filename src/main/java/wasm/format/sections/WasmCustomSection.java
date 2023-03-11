package wasm.format.sections;

import static ghidra.app.util.bin.StructConverter.BYTE;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;

public class WasmCustomSection implements WasmPayload {
	LEB128 namelen;
	String name;
	byte[] contents;
	
	protected WasmCustomSection (LEB128 namelen, String name, BinaryReader reader, int contentlen) throws IOException {
		this.namelen = namelen;
		this.name = name;
		contents = reader.readNextByteArray(contentlen);
	}
	
	public static WasmCustomSection create(BinaryReader reader, long len) throws IOException {
		long readUntil = reader.getPointerIndex() + len;
		
		LEB128 namelen = LEB128.readUnsignedValue(reader);
		String name = new String(reader.readNextByteArray((int)namelen.asInt32()));
		
		int contentlen = (int)(readUntil - reader.getPointerIndex());
		
		if(name.equals("name")) {
			return new WasmNameSection(namelen, name, reader, contentlen);
		}
		
		return new WasmCustomSection(namelen, name, reader, contentlen);
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add( new ArrayDataType( BYTE, namelen.getLength(), BYTE.getLength( ) ), "name_len", null );
		structure.add(StructConverter.STRING, name.length(), "name", null);
		structure.add(StructConverter.STRING, contents.length, "contents", null);
	}

	@Override
	public String getName() {
		return ".custom";
	}

}
