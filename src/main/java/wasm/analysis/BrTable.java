package wasm.analysis;

public class BrTable {
	private int[] cases;
	
	public BrTable(int[] cases) {
		this.cases = cases;
	}
	
	public int numCases() {
		return cases.length - 1; // default case
	}
	
	public int[] getCases() {
		return cases;
	}
}
