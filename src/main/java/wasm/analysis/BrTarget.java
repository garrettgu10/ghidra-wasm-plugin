package wasm.analysis;

import ghidra.program.model.address.Address;

public class BrTarget {
	BranchDest target = null;
	int implicitPops;
	
	public BrTarget(BranchDest target, int pops) {
		this.implicitPops = pops;
		this.target = target;
	}
	
	@Override
	public String toString() {
		return target + " (pops " + implicitPops + ")";
	}
	
	public Address getDest() {
		return target.getBranchDest();
	}
	
	public int getNumPops() {
		return implicitPops;
	}
}