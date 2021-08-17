/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package wasm.pcodeInject;
//based on the JVM version of the same class

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.app.plugin.processors.sleigh.symbol.UseropSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import wasm.analysis.BrTable;
import wasm.analysis.BrTarget;
import wasm.format.WasmFuncSignature;
import wasm.format.sections.structures.WasmFuncType;

public class PcodeOpEmitter {
	static final String RAM = "ram";
	static final String TABLE = "table0";

	private HashMap<String, Varnode> nameToReg;
	private ArrayList<PcodeOp> opList;
	private SleighLanguage language;
	private AddressSpace ramSpace;
	private AddressSpace tableSpace;
	private AddressSpace defSpace;
	private AddressSpace constSpace;
	private AddressSpace uniqueSpace;
	private Varnode spVarnode;
	private Varnode defSpaceId;
	private long uniqueBase;
	private Address opAddress;
	private int seqnum;

	private Varnode convertRegisterToVarnode(Register reg) {
		Varnode vn = new Varnode(reg.getAddress(), reg.getBitLength() / 8);
		return vn;
	}

	private String findTempName(Address addr) {
		if (addr.getAddressSpace() != uniqueSpace) {
			return null;
		}
		for (Entry<String, Varnode> entry : nameToReg.entrySet()) {
			if (entry.getValue().getAddress().equals(addr)) {
				return entry.getKey();
			}
		}
		return null;
	}

	private Varnode findRegister(String name) {
		Varnode vn = nameToReg.get(name);
		if (vn != null) {
			return vn;
		}
		Register reg = language.getRegister(name);
		if (reg == null) {
			throw new IllegalArgumentException("Register must already exist: " + name);
		}
		vn = convertRegisterToVarnode(reg);
		nameToReg.put(name, vn);
		return vn;
	}

	private Varnode findVarnode(String name, int size) {
		Varnode vn = nameToReg.get(name);
		if (vn != null) {
			if (vn.getSize() != size) {
				throw new IllegalArgumentException("Cannot find varnode: " + name);
			}
			return vn;
		}
		Register reg = language.getRegister(name);
		if (reg != null) {
			if (reg.getBitLength() == size * 8) {
				vn = convertRegisterToVarnode(reg);
				nameToReg.put(name, vn);
				return vn;
			}
		}
		vn = new Varnode(uniqueSpace.getAddress(uniqueBase), size);
		uniqueBase += 16;
		nameToReg.put(name, vn);
		return vn;
	}

	private Varnode getConstant(long val, int size) {
		return new Varnode(constSpace.getAddress(val), size);
	}
	
	private Varnode getAddress(Address addr) {
		return new Varnode(addr, 1);
	}
	
	public PcodeOpEmitter(SleighLanguage language, Address opAddr, long uniqBase) {
		nameToReg = new HashMap<String, Varnode>();
		opList = new ArrayList<PcodeOp>();
		this.language = language;
		ramSpace = language.getAddressFactory().getAddressSpace(RAM);
		tableSpace = language.getAddressFactory().getAddressSpace(TABLE);
		constSpace = language.getAddressFactory().getConstantSpace();
		defSpace = language.getDefaultSpace();
		uniqueSpace = language.getAddressFactory().getUniqueSpace();
		uniqueBase = uniqBase;
		opAddress = opAddr;
		seqnum = 0;
		spVarnode = findRegister("SP");
		defSpaceId = getConstant(defSpace.getSpaceID(), 4);
	}

	public PcodeOp[] getPcodeOps() {
		PcodeOp[] res = new PcodeOp[opList.size()];
		opList.toArray(res);
		return res;
	}

	public void defineTemp(String name, int size) {
		Varnode vn = findVarnode(name, size);
		if (!vn.isUnique() || vn.getSize() != size) {
			throw new IllegalArgumentException("Name is already assigned: " + name);
		}
	}
	
	public void emitNop() {
		Varnode[] in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(0, spVarnode.getSize());
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, in, spVarnode);
		opList.add(op);
	}
	
	public void emitJump(Address a) {
		Varnode[] in = new Varnode[1];
		in[0] = getAddress(a);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.BRANCH, in);
		opList.add(op);
	}
	
	public void emitCall(Address a) {
		Varnode[] in = new Varnode[1];
		in[0] = getAddress(a);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.CALL, in);
		opList.add(op);
	}
	
	public void emitCallInd(Varnode v) {
		opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.CALLIND, new Varnode[] { v }));
	}
	
	public void emitBrTable(BrTable tbl) {
		emitPop32("tmpBrIdx");
		Varnode brIdx = findVarnode("tmpBrIdx", 4);
		Varnode tmpSP = findVarnode("tmpSP", 8);
		opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.COPY, 
				new Varnode[] { spVarnode }, tmpSP));
		
		BrTarget[] cases = tbl.getCases();
		
		for(int i = 0; i < tbl.numCases(); i++) {
			BrTarget target = cases[i];
			Varnode takeBranch = findVarnode("tmpTakeBranch", 1);
			Varnode constComparator = getConstant((long)i, 4);
			Varnode subFromSP = getConstant((long)(target.getNumPops() * 8), 8); //this is how many bytes we should implicitly pop
			Varnode branchDest = getAddress(target.getDest());
			
			opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_EQUAL,
				new Varnode[] { brIdx, constComparator }, takeBranch));
			// takeBranch = brIdx == constComparator;
			opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SUB,
				new Varnode[] { tmpSP, subFromSP }, spVarnode ));
			// SP = tmpSP - subFromSP;
			opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.CBRANCH,
				new Varnode[] { branchDest, takeBranch }));
			// if takeBranch goto branchDest
		}
		
		//default case
		BrTarget defaultTarget = cases[cases.length - 1];
		Varnode subFromSP = getConstant((long)(defaultTarget.getNumPops() * 8), 8); 
		Varnode defaultDest = getAddress(defaultTarget.getDest());
		
		opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SUB,
				new Varnode[] { tmpSP, subFromSP }, spVarnode ));
		// SP = tmpSP - subFromSP;
		opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.BRANCH,
			new Varnode[] { defaultDest }));
		// goto defaultDest
	}
	
	/**
	 * Emits pcode to call a void black-box pcodeop
	 * @param pcodeop - name of pcodeop
	 * @param args - zero or more arguments for the pcodeop
	 */
	public void emitVoidPcodeOpCall(String pcodeop, Varnode[] args) {
		Symbol useropSym = language.getSymbolTable().findGlobalSymbol(pcodeop);
		Varnode[] in = new Varnode[args.length + 1];
		in[0] = getConstant(((UseropSymbol) useropSym).getIndex(), 4);
		for (int i = 0; i < args.length; ++i) {
			in[i + 1] = args[i];
		}
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.CALLOTHER, in);
		opList.add(op);
	}
	
	public void emitRet() {
		Varnode[] in = new Varnode[1];
		in[0] = findRegister("LR");
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.RETURN, in);
		opList.add(op);
	}
	
	public void emitPopn(int nqwords) {
		Varnode[] in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant((long)(nqwords * 8), 4);
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, in, spVarnode);
		opList.add(op);
	}

	/**
	 * Emits pcode to push a value of computational category 2 onto the stack.
	 * @param valueName - name of varnode to push.
	 */
	public void emitPush64(String valueName) {
		Varnode[] in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(8, spVarnode.getSize());
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_SUB, in, spVarnode);
		opList.add(op);
		in = new Varnode[3];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		in[2] = findRegister(valueName);
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.STORE, in);
		opList.add(op);
	}

	/**
	 * Emits pcode to pop a value of computational category 2 from the stack.
	 * @param destName - name of destination varnode.
	 */
	public void emitPop64(String destName) {
		Varnode out = findVarnode(destName, 8);
		Varnode[] in = new Varnode[2];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.LOAD, in, out);
		opList.add(op);
		in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(8, spVarnode.getSize());
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, in, spVarnode);
		opList.add(op);
	}
	
	public void emitPop32(String destName) {
		Varnode out = findVarnode(destName, 4);
		Varnode[] in = new Varnode[2];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.LOAD, in, out);
		opList.add(op);
		in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(8, spVarnode.getSize());
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, in, spVarnode);
		opList.add(op);
	}
	
	public void emitMov64(String from, String to) {
		Varnode[] src = new Varnode[] { findVarnode(from, 8) };
		Varnode dest = findVarnode(to, 8);
		PcodeOp mov = new PcodeOp(opAddress, seqnum++, PcodeOp.COPY, src, dest);
		opList.add(mov);
	}
	
	public void emitMov32(String from, String to) {
		Varnode[] src = new Varnode[] { findVarnode(from, 4) };
		Varnode dest = findVarnode(to, 4);
		PcodeOp mov = new PcodeOp(opAddress, seqnum++, PcodeOp.COPY, src, dest);
		opList.add(mov);
	}
	
	public void emitBackupLocals(int nlocals) {
		for(int i = 0; i < nlocals; i++) {
			emitMov64("l" + i, "tmp" + i);
		}
		
		emitMov32("SP", "tmpSP");
	}
	
	public void emitRestoreLocals(int nlocals) {
		for(int i = 0; i < nlocals; i++) {
			emitMov64("tmp" + i, "l" + i);
		}
		
		emitMov32("tmpSP", "SP");
	}
	
	public void emitPopParams(int n) {
		for(int i = 0; i < n; i++) {
			String dest = "l" + (n - 1 - i); // values are popped off in reverse order
			emitPop64(dest);
		}
	}
	
	public void emitCall(WasmFuncSignature target) {
		int numParams = target.getParams().length;
		int numReturns = target.getReturns().length;
		if(numReturns > 1) {
			throw new RuntimeException("Multiple returns not supported (yet)");
		}
		
		if(target.getAddr() == null) {
			throw new RuntimeException("Call target unresolved");
		}

		//move existing locals into temp registers
		emitBackupLocals(numParams);
		
		//pop parameters from the stack into local registers
		emitPopParams(numParams);
		
		//do the call
		emitCall(target.getAddr());
		
		//restore previous local values
		emitRestoreLocals(numParams);
		
		//if there is a return value, push it onto the stack
		if(numReturns == 1) {
			emitPush64("ret0");
		}
	}
	
	//pops the function index and loads its address from the table
	//result is stored in tmpFuncAddr
	public Varnode emitGetIndirectFuncAddr() {
		emitPop32("tmpFuncIdx");
		Varnode v = findVarnode("tmpFuncIdx", 4);
		
		Varnode off = findVarnode("tmpFuncOff", 4);
		opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.INT_MULT, new Varnode[] {
				v, getConstant(8, 4)
		}, off));
		
		Varnode res = findVarnode("tmpFuncAddr", 8);
		opList.add(new PcodeOp(opAddress, seqnum++, PcodeOp.LOAD, new Varnode[] {
				getConstant(tableSpace.getSpaceID(), 4), off
		}, res));
		
		return res;
	}
	
	public void emitCallIndirect(WasmFuncType type) {
		int numParams = type.getParamTypes().length;
		int numReturns = type.getReturnTypes().length;
		if(numReturns > 1) {
			throw new RuntimeException("Multiple returns not supported (yet)");
		}
		
		emitBackupLocals(numParams);
		Varnode funcAddr = emitGetIndirectFuncAddr();
		
		emitPopParams(numParams);
		
		emitCallInd(funcAddr);
		
		emitRestoreLocals(numParams);
		
		if(numReturns == 1) {
			emitPush64("ret0");
		}
	}

	private boolean compareVarnode(Varnode vn1, Varnode vn2, PcodeOpEmitter op2) {
		if (vn1 == null) {
			return (vn2 == null);
		}
		if (vn2 == null) {
			return false;
		}
		if (vn1.getSize() != vn2.getSize()) {
			return false;
		}
		AddressSpace spc1 = vn1.getAddress().getAddressSpace();
		AddressSpace spc2 = vn2.getAddress().getAddressSpace();
		if (spc1 != spc2) {
			return false;
		}
		long offset1 = vn1.getOffset();
		long offset2 = vn2.getOffset();
		if (offset1 == offset2) {
			return true;
		}
		String name1 = findTempName(vn1.getAddress());
		if (name1 == null) {
			return false;
		}
		String name2 = op2.findTempName(vn2.getAddress());
		if (name2 == null) {
			return false;
		}
		return name1.equals(name2);
	}

	@Override
	public boolean equals(Object obj) {
		PcodeOpEmitter op2 = (PcodeOpEmitter) obj;
		if (opList.size() != op2.opList.size()) {
			return false;
		}
		for (int i = 0; i < opList.size(); ++i) {
			PcodeOp aop = opList.get(i);
			PcodeOp bop = op2.opList.get(i);
			if (aop.getOpcode() != bop.getOpcode()) {
				return false;
			}
			if (aop.getNumInputs() != bop.getNumInputs()) {
				return false;
			}
			if (!compareVarnode(aop.getOutput(), bop.getOutput(), op2)) {
				return false;
			}
			for (int j = 0; j < aop.getNumInputs(); ++j) {
				if (!compareVarnode(aop.getInput(j), bop.getInput(j), op2)) {
					return false;
				}
			}
		}
		return true;
	}

}
