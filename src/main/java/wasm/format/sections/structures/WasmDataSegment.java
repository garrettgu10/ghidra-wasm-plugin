package wasm.format.sections.structures;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import wasm.format.Leb128;

public class WasmDataSegment implements StructConverter {

	private Leb128 index;
	private Leb128 offset;
	private long fileOffset;
	private Leb128 size;
	private byte[] data;

	public WasmDataSegment(BinaryReader reader) throws IOException {
		index = new Leb128(reader);
		byte offsetOpcode = reader.readNextByte();
		/* Offset expression is an expr, which must be a constant expression evaluating to an i32.
		   For this datatype, there are only two possibilities: i32.const (0x41) or global.get (0x23). */
		if(offsetOpcode == 0x41) {
			/* i32.const */
			offset = new Leb128(reader);
			byte endByte = reader.readNextByte();
			if(endByte != 0x0b) {
				Msg.warn(this, "Data segment at file offset " + reader.getPointerIndex() + " does not look normal!");
			}
		} else if(offsetOpcode == 0x23) {
			/* global.get: offset is left as null */
			// skip globalidx
			new Leb128(reader);
			byte endByte = reader.readNextByte();
			if(endByte != 0x0b) {
				Msg.warn(this, "Data segment at file offset " + reader.getPointerIndex() + " does not look normal!");
			}
		} else {
			Msg.warn(this, "Unhandled data segment offset: opcode " + offsetOpcode + " at file offset " + reader.getPointerIndex());
			while(true) {
				byte endByte = reader.readNextByte();
				if(endByte == 0x0b)
					break;
			}
		}
		size = new Leb128(reader);
		fileOffset = reader.getPointerIndex();
		data = reader.readNextByteArray((int)size.getValue());
	}

	public long getIndex() {
		return index.getValue();
	}

	public long getFileOffset() {
		return fileOffset;
	}

	public long getOffset() {
		return (offset == null) ? -1 : offset.getValue();
	}

	public long getSize() {
		return size.getValue();
	}

	public byte[] getData() {
		return data;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType("data_segment_" + index.getValue(), 0);
		structure.add(index.toDataType(), index.toDataType().getLength(), "index", null);
		structure.add(DWORD, 4, "offset", null);
		structure.add(size.toDataType(), size.toDataType().getLength(), "size", null);
		if(data.length != 0) {
			structure.add(new ArrayDataType(BYTE, data.length, BYTE.getLength()), "data", null);
		}
		return structure;
	}

}
