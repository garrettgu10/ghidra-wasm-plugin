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
import wasm.format.sections.structures.WasmTableType;

public class WasmTableSection implements WasmPayload {

	private LEB128 count;
	private List<WasmTableType> types = new ArrayList<WasmTableType>();
	
	public WasmTableSection (BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i =0; i < count.asUInt32(); ++i) {
			types.add(new WasmTableType(reader));
		}	
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(new ArrayDataType(BYTE, count.getLength(), BYTE.getLength()), "count", null);
		for (int i = 0; i < count.asUInt32(); ++i) {
			structure.add(types.get(i).toDataType(), types.get(i).toDataType().getLength(), "table_type_"+i, null);
		}
	}


	@Override
	public String getName() {
		return ".table";
	}

}
