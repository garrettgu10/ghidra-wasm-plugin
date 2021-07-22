package wasm.analysis;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Varnode;
import wasm.format.Leb128;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.structures.WasmFuncType;
import wasm.pcodeInject.PcodeHelper;
import wasm.pcodeInject.PcodeOpEmitter;

public abstract class MetaInstruction {
	public enum Type {
		PUSH,
		POP,
		BEGIN_LOOP,
		BEGIN_BLOCK,
		IF,
		ELSE,
		END,
		BR,
		RETURN,
		CALL,
		CALL_INDIRECT
	}
	
	Address location;
	
	protected MetaInstruction() {}
	
	public static boolean hasNopSemantics(Type t) {
		switch(t) {
		case IF:
		case ELSE:
		case BR:
		case RETURN:
		case CALL:
		case CALL_INDIRECT:
			return false;
		default:
			return true;
		}
	}
	
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
				long lvl = getLeb128Operand(p, con.baseAddr);
				res = new BrMetaInstruction((int)lvl);
				break;
			case BEGIN_LOOP:
				res = new BeginLoopMetaInstruction();
				break;
			case BEGIN_BLOCK:
				res = new BeginBlockMetaInstruction();
				break;
			case IF: 
				res = new IfMetaInstruction();
				break;
			case ELSE:
				res = new ElseMetaInstruction();
				break;
			case END:
				res = new EndMetaInstruction();
				break;
			case RETURN:
				res = new ReturnMetaInstruction();
				break;
			case CALL:
				long idx = getLeb128Operand(p, con.baseAddr);
				res = new CallMetaInstruction((int) idx);
				break;
			case CALL_INDIRECT:
				long typeIdx = getLeb128Operand(p, con.baseAddr);
				res = new CallIndirectMetaInstruction((int)typeIdx);
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
	//But ULeb128 creates a reference varnode in sleigh
	public static long getLeb128Operand(Program p, Address brAddress) throws MemoryAccessException {
		byte[] buf = new byte[16];
		p.getMemory().getBytes(brAddress.add(1), buf); //add 1 to go past the opcode
		return Leb128.readUnsignedLeb128(buf);
	}
	
	public abstract Type getType();
	
	public Address getEndAddress() {
		throw new RuntimeException("Cannot get end address of " + getType());
	}
	
	public void synthesize(PcodeOpEmitter pcode) {
		pcode.emitNop();
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

	@Override
	public Type getType() {
		return Type.PUSH;
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

	@Override
	public Type getType() {
		return Type.POP;
	}
}

abstract class BranchDest extends MetaInstruction {
	public abstract Address getBranchDest();
}

class BeginLoopMetaInstruction extends BranchDest {
	Address endLocation = null; //location of the corresponding end instruction
	int stackDepthAtStart = 0;
	
	@Override
	public String toString() {
		return super.toString() + " BEGIN_LOOP (end " + endLocation + ")";
	}
	
	@Override
	public Address getEndAddress() {
		return endLocation;
	}

	@Override
	public Type getType() {
		return Type.BEGIN_LOOP;
	}

	@Override
	public Address getBranchDest() {
		return location;
	}
}

class BeginBlockMetaInstruction extends BranchDest {
	Address endLocation = null;
	
	@Override
	public String toString() {
		return super.toString() + " BEGIN_BLOCK (end " + endLocation + ")";
	}

	@Override
	public Address getEndAddress() {
		return endLocation;
	}
	
	@Override
	public Type getType() {
		return Type.BEGIN_BLOCK;
	}

	@Override
	public Address getBranchDest() {
		return endLocation;
	}
}

class IfMetaInstruction extends BranchDest {
	ElseMetaInstruction elseInstr = null;
	Address endLocation = null;	
	
	@Override
	public String toString() {
		return super.toString() + " IF (else " + elseInstr + ") (end " + endLocation + ")";
	}

	@Override
	public Address getEndAddress() {
		return endLocation;
	}
	
	@Override
	public void synthesize(PcodeOpEmitter pcode) {
		//the slaspec jumps to inst_next on the positive edge, we only need to emit the negative branch
		Address dest;
		if(elseInstr != null) {
			//jump to the instruction following the else byte
			dest = elseInstr.location.add(1);
		}else {
			//jump to the corresponding end
			dest = endLocation;
		}
		
		pcode.emitJump(dest);
	}
	
	@Override
	public Type getType() {
		return Type.IF;
	}

	@Override
	public Address getBranchDest() {
		return endLocation;
	}
}

class ElseMetaInstruction extends MetaInstruction {
	IfMetaInstruction ifInstr = null;;
	
	@Override
	public String toString() {
		return super.toString() + " ELSE (end " + (ifInstr == null? null: ifInstr.getEndAddress()) + ")";
	}
	
	@Override
	public void synthesize(PcodeOpEmitter pcode) {
		Address end = ifInstr.endLocation;
		//if we come across an else in normal control flow, simply jump to the end of the if..else..end
		pcode.emitJump(end);
	}

	@Override
	public Type getType() {
		return Type.ELSE;
	}
}

class EndMetaInstruction extends MetaInstruction {
	@Override
	public String toString() {
		return super.toString() + " END";
	}

	@Override
	public Type getType() {
		return Type.END;
	}
}

class ReturnMetaInstruction extends MetaInstruction {
	boolean returnsVal = false;
	@Override 
	public String toString() {
		return super.toString() + " RETURN" + (returnsVal? " v" : "");
	}
	
	@Override
	public void synthesize(PcodeOpEmitter pcode) {
		if(returnsVal) {
			pcode.emitPop64("ret0");
		}
		pcode.emitRet();
	}
	
	@Override
	public Type getType() {
		return Type.RETURN;
	}
}

class BrMetaInstruction extends MetaInstruction {
	int implicitPops = 0;
	BranchDest target = null;
	int level;
	
	public BrMetaInstruction(int lvl) {
		this.level = lvl;
	}
	
	@Override
	public String toString() {
		return super.toString() + " BR (pops " + implicitPops + ") (dest " + target + ")";
	}
	
	@Override
	public void synthesize(PcodeOpEmitter pcode) {
		if(implicitPops != 0) {
			pcode.emitPopn(implicitPops);			
		}
		
		pcode.emitJump(target.getBranchDest());
	}

	@Override
	public Type getType() {
		return Type.BR;
	}
}

class CallMetaInstruction extends MetaInstruction {
	int funcIdx;
	WasmFuncSignature signature;
	
	public CallMetaInstruction(int funcIdx) {
		this.funcIdx = funcIdx;
	}
	
	@Override
	public String toString() {
		return super.toString() + " CALL (index " + funcIdx + ") + (dest " + signature + ")";
	}
	
	@Override
	public void synthesize(PcodeOpEmitter pcode) {
		pcode.emitCall(signature);
	}

	@Override
	public Type getType() {
		return Type.CALL;
	}
}

class CallIndirectMetaInstruction extends MetaInstruction {
	int typeIdx;
	WasmFuncType signature;	
	
	public CallIndirectMetaInstruction(int typeIdx) {
		this.typeIdx = typeIdx;;
	}

	@Override
	public String toString() {
		return super.toString() + " CALL_INDIRECT (dest " + signature + ")";
	}

	@Override
	public Type getType() {
		return Type.CALL_INDIRECT;
	}
}