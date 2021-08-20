package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.sections.structures.WasmDataSegment;

public class WasmDataSection implements WasmPayload {

	
	private Leb128 count;
	private List<WasmDataSegment> dataSegments = new ArrayList<WasmDataSegment>();

	public WasmDataSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			dataSegments.add(new WasmDataSegment(reader));
		}

	}

	public List<WasmDataSegment> getSegments() {
		return Collections.unmodifiableList(dataSegments);
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(dataSegments.get(i).toDataType(), dataSegments.get(i).toDataType().getLength(), "segment_"+i, null);
		}
	}

	@Override
	public String getName() {
		return ".data";
	}


}
