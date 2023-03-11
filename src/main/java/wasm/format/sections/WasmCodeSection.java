package wasm.format.sections;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.sections.structures.WasmFunctionBody;
import static ghidra.app.util.bin.StructConverter.BYTE;

public class WasmCodeSection implements WasmPayload {

	private LEB128 count;
	List<WasmFunctionBody> functions = new ArrayList <WasmFunctionBody>();
	
	public WasmCodeSection (BinaryReader reader) throws IOException {
		count = LEB128.readUnsignedValue(reader);
		for (int i =0; i < count.asInt32(); ++i) {
			functions.add(new WasmFunctionBody(reader));
		}
	}
	
	public List<WasmFunctionBody> getFunctions() {
		return functions;
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add( new ArrayDataType( BYTE, count.getLength(), BYTE.getLength( ) ), "count", null );
		int function_id = 0;
		for (WasmFunctionBody function: functions) {
			structure.add(function.toDataType(), function.toDataType().getLength(), "function_" + function_id, null);
			function_id ++;
		}
	}

	@Override
	public String getName() {
		return ".code";
	}


}
