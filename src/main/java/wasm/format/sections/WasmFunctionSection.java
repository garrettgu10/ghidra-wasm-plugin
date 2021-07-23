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
import wasm.format.sections.structures.WasmFuncType;

public class WasmFunctionSection implements WasmPayload {

	private Leb128 count;
	private List<Leb128> types = new ArrayList<Leb128>();
	
	public WasmFunctionSection (BinaryReader reader) throws IOException {
		count = new Leb128(reader);
		for (int i =0; i < count.getValue(); ++i) {
			types.add(new Leb128(reader));
		}		
	}
	
	public int getTypeIdx(int funcidx) {
		return (int)types.get(funcidx).getValue();
	}
	
	public int getTypeCount() {
		return types.size();
	}

	@Override
	public void addToStructure(Structure structure) throws IllegalArgumentException, DuplicateNameException, IOException {
		structure.add(count.toDataType(), count.toDataType().getLength(), "count", null);
		for (int i = 0; i < count.getValue(); ++i) {
			structure.add(types.get(i).toDataType(), types.get(i).toDataType().getLength(), "function_"+i, null);
		}
	}

	@Override
	public String getName() {
		return ".function";
	}

}
