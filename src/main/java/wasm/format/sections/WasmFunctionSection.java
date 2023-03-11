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

public class WasmFunctionSection implements WasmPayload {

	private LEB128 count;
	private List<LEB128> types = new ArrayList<>();

	public WasmFunctionSection(BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asInt32(); ++i) {
			types.add(LEB128.readUnsignedValue(reader));
		}
	}
	
	public int getTypeIdx(int funcidx) {
		return (int) types.get(funcidx).asLong();
	}
	
	public int getTypeCount() {
		return types.size();
	}

	@Override
	public void addToStructure(Structure structure)
			throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(new ArrayDataType(BYTE, count.getLength(), BYTE.getLength()), "count", null);
		for (int i = 0; i < count.asInt32(); ++i) {
			structure.add(new ArrayDataType(BYTE, types.get(i).getLength(), BYTE.getLength()), "function_" + i, null);
		}
	}

	@Override
	public String getName() {
		return ".function";
	}

}
