package wasm.analysis;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.structures.WasmFuncType;

public class WasmFunctionAnalysis {

	private ArrayList<MetaInstruction> metas = new ArrayList<>();
	private WasmAnalysis parent;
	
	public WasmFunctionAnalysis(WasmAnalysis parent) {
		this.parent = parent;
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
				MetaInstruction target = controlStack.get(controlStack.size() - 1 - br.level);
				switch(target.getType()) {
				case BEGIN_BLOCK:
				case IF:
					//jump to the end of the corresponding block
					br.target = (BranchDest)target;
					br.implicitPops = 0;
					break;
				case BEGIN_LOOP:
					//jump back to the beginning of the loop and pop everything that's been pushed since the start
					br.target = (BranchDest)target;
					BeginLoopMetaInstruction loop = (BeginLoopMetaInstruction)target;
					br.implicitPops = valueStackDepth - loop.stackDepthAtStart;
					break;
				default:
					throw new RuntimeException("Invalid item on control stack " + target);
				}
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
						for(MetaInstruction meta: metas) {
							System.out.println(meta);
						}
						throw new RuntimeException("Too many items on stack at return");
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
			}
		}
	}
}
