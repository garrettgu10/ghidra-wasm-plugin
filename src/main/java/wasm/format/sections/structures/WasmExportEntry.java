package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmExportEntry implements StructConverter {

	LEB128 field_len;
	String name;
	WasmExternalKind kind;
	LEB128 index;

	public enum WasmExternalKind {
		KIND_FUNCTION, KIND_TABLE, KIND_MEMORY, KIND_GLOBAL
	}

	public WasmExportEntry(BinaryReader reader) throws IOException {
		field_len = LEB128.readUnsignedValue(reader);
		name = reader.readNextAsciiString(field_len.asUInt32());
		kind = WasmExternalKind.values()[reader.readNextByte()];
		index = LEB128.readUnsignedValue(reader);
	}
	
	public String getName() {
		return name;
	}
	
	public int getIndex() {
		return (int) index.asLong();
	}
	
	public WasmExternalKind getType() {
		return kind;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("export_" + index, 0);
		structure.add(new ArrayDataType(BYTE, field_len.getLength(), BYTE.getLength()), "field_len", null);
		structure.add(STRING, name.length(), "name", null);
		structure.add(BYTE, 1, "kind", null);
		structure.add(new ArrayDataType(BYTE, index.getLength(), BYTE.getLength()), "index", null);
		return structure;
	}

	

}
