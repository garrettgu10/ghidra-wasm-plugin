package wasm.analysis;

import java.util.ArrayList;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.structures.WasmFuncType;

public class WasmFunctionAnalysis {

	private ArrayList<MetaInstruction> metas = new ArrayList<>();
	private WasmAnalysis parent;
	private Function function;
	
	public WasmFunctionAnalysis(WasmAnalysis parent, Function f) {
		this.parent = parent;
		this.function = f;
		Program program = parent.getProgram();
		
		DecompileOptions options = new DecompileOptions();
    	options.setWARNCommentIncluded(true);
    	DecompInterface ifc = new DecompInterface();
    	ifc.setOptions(options);
    	
    	if (!ifc.openProgram(program)) {
			throw new RuntimeException("Unable to decompile: "+ifc.getLastMessage());
		}
    	
    	ifc.setSimplificationStyle("firstpass");
		
		parent.startCollectingMetas(this);
    	
    	ifc.decompileFunction(f, 30, null);
		
    	parent.stopCollectingMetas();
		
		this.performResolution();

	}
	
	public Function getFunction() {
		return function;
	}
	
	public void collectMeta(MetaInstruction meta) {
		metas.add(meta);
	}
	
	@Override
	public String toString() {
		return metas.toString();
	}
	
	public MetaInstruction findMetaInstruction(Address a, MetaInstruction.Type type) {
		for(MetaInstruction instr: metas) {
			if(instr.location.equals(a) && instr.getType() == type) {
				return instr;
			}
		}
		return null;
	}
	
	private static BrTarget getTarget(int level, ArrayList<MetaInstruction> controlStack, int valueStackDepth) {
		MetaInstruction targetInstr = controlStack.get(controlStack.size() - 1 - level);
		BranchDest target;
		int implicitPops;
		
		switch(targetInstr.getType()) {
		case BEGIN_BLOCK:
		case IF:
			//jump to the end of the corresponding block
			target = (BranchDest)targetInstr;
			implicitPops = 0;
			break;
		case BEGIN_LOOP:
			//jump back to the beginning of the loop and pop everything that's been pushed since the start
			target = (BranchDest)targetInstr;
			BeginLoopMetaInstruction loop = (BeginLoopMetaInstruction)target;
			implicitPops = valueStackDepth - loop.stackDepthAtStart;
			break;
		default:
			throw new RuntimeException("Invalid item on control stack " + targetInstr);
		}
		
		return new BrTarget(target, implicitPops);
	}
	
	private static BrTable getBrTable(int[] rawCases, ArrayList<MetaInstruction> controlStack, int valueStackDepth) {
		BrTarget[] cases = new BrTarget[rawCases.length];
		for(int i = 0; i < rawCases.length; i++) {
			cases[i] = getTarget(rawCases[i], controlStack, valueStackDepth);
		}
		return new BrTable(cases);
	}

	//Resolve branch targets, implicit pops, call instructions to make them ready for pcode synthesis
	public void performResolution() {
		ArrayList<MetaInstruction> controlStack = new ArrayList<>();
		int valueStackDepth = 0; //number of items on the value stack
		
		for(MetaInstruction instr: this.metas) {
			switch(instr.getType()) {
			case PUSH:
				valueStackDepth++;
				break;
			case POP:
				valueStackDepth--;
				break;
			case BEGIN_LOOP:
				BeginLoopMetaInstruction beginLoop = (BeginLoopMetaInstruction) instr;
				beginLoop.stackDepthAtStart = valueStackDepth;
				controlStack.add(beginLoop);
				break;
			case BEGIN_BLOCK:
				controlStack.add(instr);
				break;
			case BR:
				BrMetaInstruction br = (BrMetaInstruction)instr;
				br.target = getTarget(br.level, controlStack, valueStackDepth);
				break;
			case ELSE:
				IfMetaInstruction ifStmt = (IfMetaInstruction) controlStack.get(controlStack.size() - 1);
				ElseMetaInstruction elseStmt = (ElseMetaInstruction)instr;
				ifStmt.elseInstr = elseStmt;
				elseStmt.ifInstr = ifStmt;
				break;
			case END:
				MetaInstruction begin = controlStack.remove(controlStack.size() - 1);
				switch(begin.getType()) {
				case BEGIN_BLOCK:
					BeginBlockMetaInstruction beginBlock = (BeginBlockMetaInstruction)begin;
					beginBlock.endLocation = instr.location;
					break;
				case IF:
					IfMetaInstruction ifInstr = (IfMetaInstruction)begin;
					ifInstr.endLocation = instr.location;
					break;
				case BEGIN_LOOP:
					BeginLoopMetaInstruction loop = (BeginLoopMetaInstruction)begin;
					loop.endLocation = instr.location;
					break;
				default:
					throw new RuntimeException("Invalid item on control stack " + begin);
				}
				break;
			case IF:
				controlStack.add(instr);
				break;
			case RETURN:
				if(valueStackDepth != 0) {
					if(valueStackDepth != 1) {
						System.out.println(metas);
						throw new RuntimeException("Too many items on stack at return (at " + instr.location + ")");
					}
					ReturnMetaInstruction ret = (ReturnMetaInstruction) instr;
					ret.returnsVal = true;
					valueStackDepth--;
				}
				break;
			case CALL:
				CallMetaInstruction callInstr = (CallMetaInstruction) instr;
				int funcidx = callInstr.funcIdx;
				WasmFuncSignature func = parent.getFuncSignature(funcidx);
				callInstr.signature = func;
				valueStackDepth -= func.getParams().length;
				valueStackDepth += func.getReturns().length;
				break;
			case CALL_INDIRECT:
				CallIndirectMetaInstruction callIndirect = (CallIndirectMetaInstruction) instr;
				int typeIdx = callIndirect.typeIdx;
				WasmFuncType type = parent.getTypeSection().getType(typeIdx);
				callIndirect.signature = type;
				valueStackDepth--;
				valueStackDepth -= type.getParamTypes().length;
				valueStackDepth += type.getReturnTypes().length;
				break;
			case BR_TABLE:
				BrTableMetaInstruction brTableInstr = (BrTableMetaInstruction) instr;
				valueStackDepth--;
				brTableInstr.table = getBrTable(brTableInstr.rawCases, controlStack, valueStackDepth);
				break;
			}
		}
	}
}
