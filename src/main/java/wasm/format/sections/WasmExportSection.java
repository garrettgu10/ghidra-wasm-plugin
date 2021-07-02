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
import wasm.format.sections.structures.WasmExportEntry.WasmExternalKind;

public class WasmExportSection implements WasmPayload {

	private Leb128 count;
	private List<WasmExportEntry> exports = new ArrayList<WasmExportEntry>();
	
	
		
	public WasmExportSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			exports.add(new WasmExportEntry(reader));
		}		
	}
	
	public WasmExportEntry findMethod(int id) {
		for (WasmExportEntry entry: exports) {
			if (entry.getType() == WasmExternalKind.KIND_FUNCTION && entry.getIndex() == id) {
				return entry;
			}
		}
		return null;
	}


	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(exports.get(i).toDataType(), exports.get(i).toDataType().getLength(), "export_"+i, null);
		}
	}

	@Override
	public String getName() {
		return ".export";
	}

}
