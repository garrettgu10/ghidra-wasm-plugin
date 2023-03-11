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
import wasm.format.sections.structures.WasmImportEntry;

public class WasmImportSection implements WasmPayload {

	private LEB128 count;
	private List<WasmImportEntry> imports = new ArrayList<WasmImportEntry>();

	public WasmImportSection (BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i =0; i < count.asInt32(); ++i) {
			imports.add(new WasmImportEntry(reader));
		}
	}

	public int getCount() {
		return (int) count.asLong();
	}
	
	public List<WasmImportEntry> getEntries() {
		return imports;
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(new ArrayDataType(BYTE, count.getLength(), BYTE.getLength()), "count", null);
		for (int i = 0; i < count.asUInt32(); ++i) {
			structure.add(imports.get(i).toDataType(), imports.get(i).toDataType().getLength(), "import_"+i, null);
		}
	}

	@Override
	public String getName() {
		return ".import";
	}
}
