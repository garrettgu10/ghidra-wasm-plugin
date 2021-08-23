package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmSection implements StructConverter {
	
	private WasmSectionId id;
	private LEB128 payload_len;
	private long section_size;
	private long section_offset;
	private WasmPayload payload;
	private long payload_offset;

	public enum WasmSectionId {
		SEC_CUSTOM,
		SEC_TYPE,
		SEC_IMPORT,
		SEC_FUNCTION,
		SEC_TABLE,
		SEC_LINEARMEMORY,
		SEC_GLOBAL,
		SEC_EXPORT,
		SEC_START,
		SEC_ELEMENT,
		SEC_CODE,
		SEC_DATA
	}
	
	private static WasmPayload sectionsFactory(BinaryReader reader, WasmSectionId id, LEB128 len) throws IOException {
		switch (id) {
			case SEC_CUSTOM:
				return WasmCustomSection.create(reader, len.asUInt32());
			case SEC_TYPE:
				return new WasmTypeSection(reader);
			case SEC_IMPORT:
				return new WasmImportSection(reader);
			case SEC_FUNCTION:
				return new WasmFunctionSection(reader);
			case SEC_TABLE:
				return new WasmTableSection(reader);
			case SEC_LINEARMEMORY:
				return new WasmLinearMemorySection(reader);
			case SEC_GLOBAL:
				return new WasmGlobalSection(reader);
			case SEC_EXPORT:
				return new WasmExportSection(reader);
			case SEC_START:
				return new WasmStartSection(reader);
			case SEC_ELEMENT:
				return new WasmElementSection(reader);
			case SEC_CODE:
				return new WasmCodeSection(reader);
			case SEC_DATA:
				return new WasmDataSection(reader);
			default:
				return null;
		}
	}
	
	public WasmSection(BinaryReader reader) throws IOException {
		section_offset = reader.getPointerIndex();
		this.id = WasmSectionId.values()[LEB128.readAsUInt32(reader)];

		this.payload_len = LEB128.readUnsignedValue(reader);

		payload_offset = reader.getPointerIndex();
		
		byte payload_buf[] = reader.readNextByteArray(this.payload_len.asUInt32());
		
		payload = WasmSection.sectionsFactory(new BinaryReader(new ByteArrayProvider(payload_buf), true), id, this.payload_len);
		section_size = reader.getPointerIndex() - section_offset;
	}
	
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType(payload.getName(), 0);
		structure.add(BYTE, 1, "id", null);
		structure.add(new ArrayDataType(BYTE, payload_len.getLength(), BYTE.getLength()), "size", null);
		payload.addToStructure(structure);
		return structure;
	}
	
	public WasmSectionId getId() {
		return id;
	}
	
	public WasmPayload getPayload() {
		return payload;
	}
		
	public long getPayloadOffset() {
		return payload_offset;
	}

	public long getSectionSize() {
		return section_size;
	}

	public long getSectionOffset() {
		return section_offset;
	}
}
