package wasm.format.sections.structures;

import static ghidra.app.util.bin.StructConverter.BYTE;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmDataSegment implements StructConverter {

	private LEB128 index;
	private int offset;
	private LEB128 size;
	private byte[] data;

	public WasmDataSegment(BinaryReader reader) throws IOException {
		index = LEB128.readUnsignedValue(reader);	
		offset = reader.readNextInt();
		size = LEB128.readUnsignedValue(reader);
		data = reader.readNextByteArray(size.asInt32());
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("data_segment_" + index.asUInt32(), 0);
		structure.add(new ArrayDataType(BYTE, index.getLength(), BYTE.getLength()), "count", null);
		structure.add(DWORD, 4, "offset", null);
		structure.add(new ArrayDataType(BYTE, size.getLength(), BYTE.getLength()), "size", null);
		if (data.length != 0) {
			structure.add(new ArrayDataType(BYTE, data.length, BYTE.getLength()), "data", null);
		}
		return structure;
	}

}
