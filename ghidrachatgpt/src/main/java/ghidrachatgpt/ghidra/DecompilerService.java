package ghidrachatgpt.ghidra;

import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;

public class DecompilerService {
    private static final Logger LOGGER = new Logger(DecompilerService.class);

    public DecompilerResults decompileCurrentFunc() {
        ProgramLocation programLocation = ComponentContainer.getCodeViewerService().getCurrentLocation();
        Program program = programLocation.getProgram();
        FlatProgramAPI programApi = new FlatProgramAPI(program);
        Function function = programApi.getFunctionContaining(programLocation.getAddress());

        if (function == null) {
            LOGGER.error("Failed to find the current function");
            return null;
        }
        String decompiledFunctionString = getDecompiledFunction(function, programApi);
        String asmFunctionString = getAsmFunction(function, program);

        if (decompiledFunctionString == null && asmFunctionString == null) {
            return null;
        }

        return new DecompilerResults(program, function, decompiledFunctionString, asmFunctionString);
    }

    private String getDecompiledFunction(Function function, FlatProgramAPI programAPI) {
        FlatDecompilerAPI decompiler = new FlatDecompilerAPI(programAPI);
        String decompiledFunctionString = null;
        if (GlobalSettings.isAttachCCode()) {
            try {
                decompiledFunctionString = decompiler.decompile(function);
                LOGGER.debug("function: " + decompiledFunctionString);
            } catch (Exception exception) {
                LOGGER.error(String.format("Failed to decompile the function: %s with the error %s", function.getName(), exception));
            }
        }
        return decompiledFunctionString;
    }

    private String getAsmFunction(Function function, Program program) {
        String asmFunctionString = null;
        if (GlobalSettings.isAttachAsmCode()) {
            asmFunctionString = parseAsmFunction(function, program);
            LOGGER.debug("function: " + asmFunctionString);
        }
        return asmFunctionString;
    }

    private String parseAsmFunction(Function function, Program program) {
        CodeUnitFormat asmCodeFormatter = new BrowserCodeUnitFormat(ComponentContainer.getPluginTool());

        Listing listing = program.getListing();
        AddressSetView body = function.getBody();

        StringBuilder code = new StringBuilder();
        listing.getInstructions(body, true).forEach(instruction -> {
            code.append(instruction.getAddress()).append(": ")
                    .append(asmCodeFormatter.getRepresentationString(instruction))
                    .append('\n');
        });
        return code.toString();
    }
}
