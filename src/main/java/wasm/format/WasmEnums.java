package wasm.format;

import java.util.HashMap;

public class WasmEnums {
	public enum WasmExternalKind {
		EXT_FUNCTION,
		EXT_TABLE,
		EXT_MEMORY,
		EXT_GLOBAL
	}
	
	public enum ValType {
		i32(0x7f),
		i64(0x7e),
		f32(0x7d),
		f64(0x7c),
		
		funcref(0x70),
		externref(0x6f);
		
		private static final HashMap<Integer, ValType> BY_BYTE = new HashMap<>();
		public final int typeByte;
		
		static {
			for(ValType t : ValType.values()) {
				BY_BYTE.put(t.typeByte, t);
			}
		}
		
		private ValType(int v) {
			this.typeByte = v;
		}
		
		public static ValType fromByte(int b) {
			return BY_BYTE.get(b);
		}
	}
}
