package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.WasmEnums.WasmExternalKind;

public class WasmImportEntry implements StructConverter {

	LEB128 module_len;
	String module_str;
	LEB128 field_len;
	String field_str;
	WasmExternalKind kind;

	LEB128 function_type;
	WasmResizableLimits memory_type;
	WasmTableType table_type;
	WasmGlobalType global_type;

	public WasmImportEntry(BinaryReader reader) throws IOException {
		module_len = LEB128.readUnsignedValue(reader);
		module_str = reader.readNextAsciiString(module_len.asUInt32());
		field_len = LEB128.readUnsignedValue(reader);
		field_str = reader.readNextAsciiString(field_len.asUInt32());
		kind = WasmExternalKind.values()[reader.readNextByte()];
		switch (kind) {
		case EXT_FUNCTION:
			function_type = LEB128.readUnsignedValue(reader);
			;
			break;
		case EXT_MEMORY:
			memory_type = new WasmResizableLimits(reader);
			break;
		case EXT_GLOBAL:
			global_type = new WasmGlobalType(reader);
			break;
		case EXT_TABLE:
			table_type = new WasmTableType(reader);
			break;
		default:
			break;

		}
	}

	public WasmExternalKind getKind() {
		return kind;
	}

	public int getFunctionType() {
		if (kind != WasmExternalKind.EXT_FUNCTION) {
			throw new RuntimeException("Cannot get function type of non-function import");
		}
		return (int) function_type.asLong();
	}

	public String getName() {
		return module_str + "__" + field_str;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("import_" + "_" + module_str + "_" + field_str, 0);
		structure.add(new ArrayDataType(BYTE, module_len.getLength(), BYTE.getLength()), "module_len", null);
		structure.add(STRING, module_str.length(), "module_name", null);
		structure.add(new ArrayDataType(BYTE, field_len.getLength(), BYTE.getLength()), "field_len", null);
		structure.add(STRING, field_str.length(), "field_name", null);
		structure.add(BYTE, 1, "kind", null);
		switch (kind) {
		case EXT_FUNCTION:
			structure.add(new ArrayDataType(BYTE, function_type.getLength(), BYTE.getLength()), "type", null);
			break;
		case EXT_MEMORY:
			structure.add(memory_type.toDataType(), memory_type.toDataType().getLength(), "type", null);
			break;
		case EXT_GLOBAL:
			structure.add(global_type.toDataType(), global_type.toDataType().getLength(), "type", null);
			break;
		case EXT_TABLE:
			structure.add(table_type.toDataType(), table_type.toDataType().getLength(), "type", null);
			break;
		default:
			break;
		}
		return structure;
	}

}
