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
import wasm.format.sections.structures.WasmResizableLimits;

public class WasmLinearMemorySection implements WasmPayload {

	private LEB128 count;
	private List<WasmResizableLimits> limits = new ArrayList<WasmResizableLimits>();
	
	public WasmLinearMemorySection (BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i =0; i < count.asInt32(); ++i) {
			limits.add(new WasmResizableLimits(reader));
		}	
	}


	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(new ArrayDataType(BYTE, count.getLength(), BYTE.getLength()), "count", null);
		for (int i = 0; i < count.asInt32(); ++i) {
			structure.add(limits.get(i).toDataType(), limits.get(i).toDataType().getLength(), "memory_type_"+i, null);
		}
	}

	@Override
	public String getName() {
		return ".linearMemory";
	}

}
