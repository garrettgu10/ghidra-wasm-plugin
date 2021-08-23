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

public class WasmLocalEntry implements StructConverter {

	
	public enum WasmLocalType {
		LOCAL_INT,
		LOCAL_BOOL,
		LOCAL_FLOAT
	}
	
	private LEB128 count;
	private LEB128 type;
	
	public WasmLocalEntry(BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		type = LEB128.readUnsignedValue(reader);
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("function_body", 0);
		structure.add(new ArrayDataType(BYTE, count.getLength(), BYTE.getLength()), "body_size", null);
		structure.add(new ArrayDataType(BYTE, type.getLength(), BYTE.getLength()), "local_count", null);
		return structure;
	}

}
