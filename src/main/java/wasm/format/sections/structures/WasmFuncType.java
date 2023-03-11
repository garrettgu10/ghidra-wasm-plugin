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

public class WasmFuncType implements StructConverter {

	byte form;
	LEB128 param_count;
	byte[] param_types = new byte[0];
	LEB128 return_count;
	byte[] return_types = new byte[0];

	public WasmFuncType(BinaryReader reader) throws IOException {
		form = reader.readNextByte();
		param_count = LEB128.readUnsignedValue(reader);
		if (param_count.asUInt32() > 0) {
			param_types = reader.readNextByteArray(param_count.asUInt32());
		}
		return_count = LEB128.readUnsignedValue(reader);
		if (return_count.asUInt32() > 0) {
			return_types = reader.readNextByteArray(return_count.asUInt32());
		}
	}
	
	public byte[] getParamTypes() {
		return param_types;
	}
	
	public byte[] getReturnTypes() {
		return return_types;
	}
	
	@Override
	public String toString() {
		return param_types.length + "T -> " + return_types.length + "T";
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("func_type", 0);
		structure.add(BYTE, 1, "form", null);
		structure.add(new ArrayDataType(BYTE, param_count.getLength(), BYTE.getLength()), "param_count", null);
		if (param_count.asUInt32() > 0) {
			structure.add(new ArrayDataType(BYTE, param_count.asUInt32(), 1), "param_types", null);
		}
		structure.add(new ArrayDataType(BYTE, return_count.getLength(), BYTE.getLength()), "return_count", null);
		if (return_count.asUInt32() > 0) {
			structure.add(new ArrayDataType(BYTE, return_count.asUInt32(), 1), "return_types", null);
		}
		return structure;
	}

}
