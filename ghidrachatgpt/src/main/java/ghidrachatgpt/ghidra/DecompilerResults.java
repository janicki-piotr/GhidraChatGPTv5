package ghidrachatgpt.ghidra;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public class DecompilerResults {
    public Program prog;
    public Function func;
    public String decompiledFunc;
    public String asmFunc;

    public DecompilerResults(Program prog, Function func,
                             String decompiledFunc, String asmFunc) {
        this.prog = prog;
        this.func = func;
        this.decompiledFunc = decompiledFunc;
        this.asmFunc = asmFunc;
    }

    public String getPromptElement() {
        StringBuilder prompt = new StringBuilder();
        if (asmFunc != null) {
            prompt.append("Asm function code:\n").append(asmFunc).append("\n");
        }
        if (decompiledFunc != null) {
            prompt.append("Decompiled C function code:").append(decompiledFunc);
        }
        return prompt.toString();
    }
}
