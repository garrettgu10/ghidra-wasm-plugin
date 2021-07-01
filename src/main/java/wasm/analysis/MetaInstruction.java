package wasm.analysis;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Varnode;
import wasm.format.Leb128;
import wasm.pcodeInject.PcodeHelper;

public class MetaInstruction {
	public enum Type {
		PUSH,
		POP,
		BEGIN_LOOP,
		BEGIN_BLOCK,
		IF,
		ELSE,
		END,
		BR
	}
	
	Address location;
	
	protected MetaInstruction() {}
	
	public static MetaInstruction create(Type ty, InjectContext con, Program p) {
		try {
			ArrayList<Varnode> inputs = con.inputlist;
			int param = 0;
			if(inputs != null && inputs.size() > 0) {
				Varnode input = inputs.get(0);
				param = (int)PcodeHelper.resolveConstant(input);
			}
			
			MetaInstruction res = null;
			
			switch(ty) {
			case PUSH:
				res = new PushMetaInstruction(param);
				break;
			case POP:
				res = new PopMetaInstruction(param);
				break;
			case BR:
				long lvl = getBrLvl(p, con.baseAddr);
				res = new BrMetaInstruction((int)lvl);
				break;
			}
			
			if(res != null) {
				res.location = con.baseAddr;
				return res;
			}
			
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	//We have to do this since we cannot resolve non-constant varnode inputs to our CallOther instruction
	//But ULeb128 creates a reference varnode
	public static long getBrLvl(Program p, Address brAddress) throws MemoryAccessException {
		byte[] buf = new byte[16];
		p.getMemory().getBytes(brAddress.add(1), buf); //add 1 to go past the opcode
		return Leb128.readUnsignedLeb128(buf);
	}
	
	@Override
	public String toString() {
		return location.toString();
	}
}

class PushMetaInstruction extends MetaInstruction{
	int bitsize;
	public PushMetaInstruction(int nbits) {
		super();
		this.bitsize = nbits;
	}
	
	@Override
	public String toString() {
		return super.toString() + " PUSH " + bitsize;
	}
}

class PopMetaInstruction extends MetaInstruction{
	int bitsize;
	public PopMetaInstruction(int nbits) {
		super();
		this.bitsize = nbits;
	}
	
	@Override
	public String toString() {
		return super.toString() + " POP " + bitsize;
	}
}

class BeginLoopMetaInstruction extends MetaInstruction {
	Address endLocation = null; //location of the corresponding end instruction
	
	@Override
	public String toString() {
		return super.toString() + " BEGIN_LOOP (end " + endLocation + ")";
	}
}

class BeginBlockMetaInstruction extends MetaInstruction {
	Address endLocation = null;
	
	@Override
	public String toString() {
		return super.toString() + " BEGIN_BLOCK (end " + endLocation + ")";
	}
}

class IfMetaInstruction extends MetaInstruction {
	Address elseLocation = null;
	Address endLocation = null;	
	
	@Override
	public String toString() {
		return super.toString() + " IF (else " + elseLocation + ") (end " + endLocation + ")";
	}
}

class ElseMetaInstruction extends MetaInstruction {
	Address endLocation = null;
	
	@Override
	public String toString() {
		return super.toString() + " ELSE (end " + endLocation + ")";
	}
}

class EndMetaInstruction extends MetaInstruction {
	boolean isReturn = false;
	
	@Override
	public String toString() {
		return super.toString() + " END" + (isReturn? " (return)" : "");
	}
}

class BrMetaInstruction extends MetaInstruction {
	int implicitPops = 0;
	Address destination = null;
	int level;
	
	public BrMetaInstruction(int lvl) {
		this.level = lvl;
	}
	
	@Override
	public String toString() {
		return super.toString() + " BR (pops " + implicitPops + ") (dest " + destination + ")";
	}
}