package wasm.pcodeInject;

import java.security.InvalidParameterException;

import ghidra.program.model.pcode.Varnode;

public class PcodeHelper {
	public static long resolveConstant(Varnode v) {
		if(v.isConstant()) {
			return v.getOffset();
		}
		
		throw new InvalidParameterException("Could not resolve " + v + " to a constant value");
	}
}
