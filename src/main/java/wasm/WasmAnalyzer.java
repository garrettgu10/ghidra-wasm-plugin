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
package wasm;

import java.io.IOException;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import wasm.analysis.WasmAnalysisState;
import wasm.file.WasmModule;
import wasm.format.Utils;
import wasm.format.WasmHeader;
import wasm.format.sections.WasmCodeSection;
import wasm.format.sections.WasmSection;
import wasm.format.sections.WasmSection.WasmSectionId;
import wasm.format.sections.structures.WasmFunctionBody;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class WasmAnalyzer extends AbstractAnalyzer {

	public WasmAnalyzer() {
		super("Wasm Pre-Decompiler", 
				"Resolves branch targets and implicit pops for use during decompilation", 
				AnalyzerType.BYTE_ANALYZER);
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis(false);
		setPriority(AnalysisPriority.DISASSEMBLY.before());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return canAnalyze(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().toLowerCase().equals("webassembly");
	}

	@Override
	public void registerOptions(Options options, Program program) {
		//no options needed
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		WasmAnalysisState state = WasmAnalysisState.getState(program);
		
		DecompileOptions options = new DecompileOptions();
    	options.setWARNCommentIncluded(true);
    	DecompInterface ifc = new DecompInterface();
    	ifc.setOptions(options);
    	
    	if (!ifc.openProgram(program)) {
			throw new RuntimeException("Unable to decompile: "+ifc.getLastMessage());
		}
    	
    	ifc.setSimplificationStyle("firstpass");
		
		for(Function f : program.getFunctionManager().getFunctions(true)) {
			state.startCollectingMetas(f);
	    	
	    	DecompileResults res = ifc.decompileFunction(f, 30, null);
			
			state.stopCollectingMetas();
			
			System.out.println(state.getFuncState(f));
		}

		return false;
	}
}
