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
import wasm.format.sections.structures.WasmExportEntry;
import wasm.format.sections.structures.WasmExportEntry.WasmExternalKind;

public class WasmExportSection implements WasmPayload {

	private LEB128 count;
	private List<WasmExportEntry> exports = new ArrayList<WasmExportEntry>();

	public WasmExportSection(BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < count.asInt32(); ++i) {
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
	public void addToStructure(Structure structure)
			throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(new ArrayDataType(BYTE, count.getLength(), BYTE.getLength()), "count", null);
		for (int i = 0; i < count.asInt32(); ++i) {
			structure.add(exports.get(i).toDataType(), exports.get(i).toDataType().getLength(), "export_" + i, null);
		}
	}

	@Override
	public String getName() {
		return ".export";
	}

}
