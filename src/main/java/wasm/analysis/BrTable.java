package wasm.analysis;

public class BrTable {
	private BrTarget[] cases;
	
	public BrTable(BrTarget[] cases) {
		this.cases = cases;
	}
	
	public int numCases() {
		return cases.length - 1; // default case
	}
	
	public BrTarget[] getCases() {
		return cases;
	}
}