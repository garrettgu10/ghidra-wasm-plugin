package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmElementSegment implements StructConverter {

	private LEB128 index;
	private byte init_opcode;
	private short offset;
	private LEB128 size;
	private List<LEB128> data = new ArrayList<>();

	public WasmElementSegment(BinaryReader reader) throws IOException {
		index = LEB128.readUnsignedValue(reader);
		init_opcode = reader.readNextByte();
		offset = reader.readNextShort();
		size = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < size.asUInt32(); i++) {
			data.add(LEB128.readUnsignedValue(reader));
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("data_segment_" + index.asUInt32(), 0);
		structure.add(new ArrayDataType(BYTE, index.getLength(), BYTE.getLength()), "index", null);
		structure.add(BYTE, 1, "init_opcode", null);
		structure.add(WORD, 2, "offset", null);
		structure.add(new ArrayDataType(BYTE, size.getLength(), BYTE.getLength()), "size", null);
		for (int i = 0; i < size.asUInt32(); i++) {
			structure.add(new ArrayDataType(BYTE, data.get(i).getLength(), BYTE.getLength()), "element_" + i, null);
		}
		return structure;
	}
}
