package wasm.format.sections;
import java.io.IOException;

import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;

abstract public interface WasmPayload {
	abstract public String getName();	

	abstract public void addToStructure(Structure s) throws IllegalArgumentException, DuplicateNameException, IOException;
}
