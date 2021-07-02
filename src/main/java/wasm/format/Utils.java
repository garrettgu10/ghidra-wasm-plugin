package wasm.format;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class Utils {
	public final static long HEADER_BASE = 0x10000000;
	public final static long METHOD_ADDRESS = 0x20000000;
	public final static long MAX_METHOD_LENGTH = (long) Math.pow(2, 16) * 4;
	
	public static Address toAddr( Program program, long offset ) {
		return program.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( offset );
	}
}
