package wasm.format.sections;

import static ghidra.app.util.bin.StructConverter.BYTE;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.sections.structures.WasmDataSegment;

public class WasmDataSection implements WasmPayload {

	private LEB128 count;
	private List<WasmDataSegment> dataSegments = new ArrayList<WasmDataSegment>();

	public WasmDataSection(BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asInt32(); ++i) {
			dataSegments.add(new WasmDataSegment(reader));
		}

	}

	@Override
	public void addToStructure(Structure structure)
			throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(new ArrayDataType(BYTE, count.getLength(), BYTE.getLength()), "count", null);
		for (int i = 0; i < count.asInt32(); ++i) {
			structure.add(dataSegments.get(i).toDataType(), dataSegments.get(i).toDataType().getLength(),
					"segment_" + i, null);
		}
	}

	@Override
	public String getName() {
		return ".data";
	}

	public List<WasmDataSegment> getDataSegments() {
		return dataSegments;
	}
	
	

}
