package wasm.format.sections.structures;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmFunctionBody implements StructConverter {

	private LEB128 body_size;
	private List<WasmLocalEntry> locals = new ArrayList<WasmLocalEntry>();
	private LEB128 local_count;
	private long instructions_offset;
	private byte[] instructions;

	public WasmFunctionBody(BinaryReader reader) throws IOException {
		body_size = LEB128.readUnsignedValue(reader);
		int body_start_offset = (int) reader.getPointerIndex();
		local_count = LEB128.readUnsignedValue(reader);
		for (int i = 0; i < local_count.asUInt32(); ++i) {
			locals.add(new WasmLocalEntry(reader));
		}
		instructions_offset = reader.getPointerIndex();
		instructions = reader.readNextByteArray((int) (body_start_offset + body_size.asUInt32() - instructions_offset));
	}


	public long getOffset() {
		return instructions_offset;
	}
	
	public byte[] getInstructions() {
		return instructions;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("function_body_" + instructions_offset, 0);
		structure.add(new ArrayDataType(BYTE, body_size.getLength(), BYTE.getLength()), "body_size", null);
		structure.add(new ArrayDataType(BYTE, local_count.getLength(), BYTE.getLength()), "local_count", null);
		if (local_count.asUInt32() > 0) {
			// kind of hack, but I don't know how does it work for arrays of structures
			structure.add(new ArrayDataType(locals.get(0).toDataType(), locals.size(), 2), "locals", null);
		}
		structure.add(new ArrayDataType(BYTE, instructions.length, BYTE.getLength()), "instructions", null);
		return structure;
	}

}
