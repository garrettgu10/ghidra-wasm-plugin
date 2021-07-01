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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeOpEmitter {
	static final String RAM = "ram";

	private HashMap<String, Varnode> nameToReg;
	private ArrayList<PcodeOp> opList;
	private SleighLanguage language;
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
	
	public PcodeOpEmitter(SleighLanguage language, Address opAddr, long uniqBase) {
		nameToReg = new HashMap<String, Varnode>();
		opList = new ArrayList<PcodeOp>();
		this.language = language;
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

	/**
	 * Emits pcode to push a value of computational category 1 onto the stack.
	 * @param valueName - name of varnode to push.
	 */
	public void emitPushCat1Value(String valueName) {
		Varnode[] in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(4, spVarnode.getSize());
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
	 * Emits pcode to push a value of computational category 2 onto the stack.
	 * @param valueName - name of varnode to push.
	 */
	public void emitPushCat2Value(String valueName) {
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
	public void emitPopCat2Value(String destName) {
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

	/**
	 * Emits pcode to pop a value of computational category 1 from the stack.
	 * @param destName - name of destination varnode.
	 */
	public void emitPopCat1Value(String destName) {
		Varnode out = findVarnode(destName, 4);
		Varnode[] in = new Varnode[2];
		in[0] = defSpaceId;
		in[1] = spVarnode;
		PcodeOp op = new PcodeOp(opAddress, seqnum++, PcodeOp.LOAD, in, out);
		opList.add(op);
		in = new Varnode[2];
		in[0] = spVarnode;
		in[1] = getConstant(4, spVarnode.getSize());
		op = new PcodeOp(opAddress, seqnum++, PcodeOp.INT_ADD, in, spVarnode);
		opList.add(op);
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
