package wasm.format.sections;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WasmGlobalSection implements WasmPayload {

	
	public WasmGlobalSection (BinaryReader reader) throws IOException {
	}


	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		
	}

	@Override
	public String getName() {
		return ".global";
	}


}
