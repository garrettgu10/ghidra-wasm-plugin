package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmImportEntry;

public class WasmImportSection implements WasmPayload {

	private Leb128 count;
	private List<WasmImportEntry> imports = new ArrayList<WasmImportEntry>();

	public WasmImportSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			imports.add(new WasmImportEntry(reader));
		}
	}

	public int getCount() {
		return count.getValue();
	}
	
	public List<WasmImportEntry> getEntries() {
		return imports;
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(imports.get(i).toDataType(), imports.get(i).toDataType().getLength(), "import_"+i, null);
		}
	}

	@Override
	public String getName() {
		return ".import";
	}
}
