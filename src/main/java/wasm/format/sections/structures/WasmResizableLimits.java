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

public class WasmResizableLimits implements StructConverter {

	byte flags;
	LEB128 initial;
	LEB128 maximum;

	public WasmResizableLimits(BinaryReader reader) throws IOException {
		flags = reader.readNextByte();
		initial = LEB128.readUnsignedValue(reader);
		if (flags == 1) {
			maximum = LEB128.readUnsignedValue(reader);
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("global", 0);
		structure.add(BYTE, 1, "flags", null);
		structure.add(new ArrayDataType(BYTE, initial.getLength(), BYTE.getLength()), "mutability", null);
		if (flags == 1) {
			structure.add(new ArrayDataType(BYTE, maximum.getLength(), BYTE.getLength()), "maximum", null);
		}
		return structure;
	}


}
