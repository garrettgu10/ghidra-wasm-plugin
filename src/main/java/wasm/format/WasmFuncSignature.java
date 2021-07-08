package wasm.format;

import ghidra.program.model.address.Address;
import wasm.format.WasmEnums.ValType;

public class WasmFuncSignature {
	private ValType[] params;
	private ValType[] returns;
	private String name;
	private Address addr;
	
	public ValType[] getParams() {
		return params;
	}
	
	public ValType[] getReturns() {
		return returns;
	}
	
	public String getName() {
		return name;
	}
	
	public Address getAddr() {
		return addr;
	}
	
	public WasmFuncSignature (byte[] paramTypes, byte[] returnTypes, String name, Address addr) {
		this.name = name;
		this.addr = addr;
		
		this.params = new ValType[paramTypes.length];
		this.returns = new ValType[returnTypes.length];
		
		for(int i = 0; i < paramTypes.length; i++) {
			params[i] = ValType.fromByte(paramTypes[i]);
		}
		
		for(int j = 0; j < returnTypes.length; j++) {
			returns[j] = ValType.fromByte(returnTypes[j]);
		}
	}
	
	@Override
	public String toString() {
		return String.format("%s @ %s %dT -> %dT", name, addr.toString(), params.length, returns.length);
	}
}
