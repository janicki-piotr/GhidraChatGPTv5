package ghidrachatgpt.ghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.log.Logger;
import ghidrachatgpt.openai.GPTService;
import org.json.JSONObject;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class CodeManipulationService {
    private static final Logger LOGGER = new Logger(GPTService.class);
    private static final String TRANSACTION_CODE = "GhidraChatGPT";

    public void addComment(Program prog, Function func, String comment, String commentHeader) {
        int id = prog.startTransaction(TRANSACTION_CODE);
        String currentComment = func.getComment() != null ?
                String.format("%s\n%s\n\n%s", commentHeader, comment, func.getComment()) :
                String.format("%s\n%s", commentHeader, comment);

        func.setComment(currentComment);
        prog.endTransaction(id, true);

        LOGGER.ok(String.format("Added the ChatGPT response as a comment to the function: %s", func.getName()));
    }

    public void updateVariables(Program prog, DecompilerResults decResult,
                                String result) {
        JSONObject jsonObj;
        try {
            jsonObj = new JSONObject(result);
        } catch (Exception exception) {
            LOGGER.error("Failed to parse beautify JSON", exception);
            return;
        }

        Variable[] vars = decResult.func.getAllVariables();
        if (vars == null) {
            LOGGER.info("No variables to beatify");
            addComment(decResult.prog, decResult.func, "", "[GhidraChatGPT] - Beautified the function");
            return;
        }

        int id = prog.startTransaction(TRANSACTION_CODE);
        for (Variable var : vars) {
            if (jsonObj.has(var.getName())) {
                String val = jsonObj.getString(var.getName());
                try {
                    var.setName(val, SourceType.USER_DEFINED);
                    LOGGER.ok(String.format("Beautified %s => %s", var.getName(), val));
                    addComment(decResult.prog, decResult.func, "", "[GhidraChatGPT] - Beautified the function");
                } catch (Exception exception) {
                    LOGGER.error(String.format("Failed to beautify %s => %s", var.getName(), val), exception);
                }
            }
        }

        if (jsonObj.has(decResult.func.getName())) {
            String val = jsonObj.getString(decResult.func.getName());
            try {
                decResult.func.setName(val, SourceType.USER_DEFINED);
                LOGGER.ok(String.format("Beautified %s => %s", decResult.func.getName(), val));
            } catch (Exception exception) {
                LOGGER.error(String.format("Failed to beautify %s => %s", decResult.func.getName(), val), exception);
            }
        }

        prog.endTransaction(id, true);
    }

    public List<Function> getAllDefinedFunctions(boolean includeExternals, boolean includeThunks) {
        ProgramLocation programLocation = ComponentContainer.getCodeViewerService().getCurrentLocation();
        Program program = programLocation.getProgram();
        return StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
                .filter(f -> includeExternals || !f.isExternal())
                .filter(f -> includeThunks || !f.isThunk())
                .collect(Collectors.toList());
    }

    public boolean isFunctionAlreadyProcessed(Function function) {
        String comment = function.getCallingConventionName();
        return comment != null && comment.contains("[GhidraChatGPT]");
    }

    public boolean isFunctionEntryInRange(Function f, Address start, Address end) {
        if (start.getAddressSpace() != end.getAddressSpace()) {
            throw new IllegalArgumentException("Start and end must be in the same AddressSpace");
        }

        if (start.compareTo(end) > 0) {
            Address t = start;
            start = end;
            end = t;
        }

        Address entry = f.getEntryPoint();
        if (entry.getAddressSpace() != start.getAddressSpace()) {
            return false;
        }
        return entry.compareTo(start) >= 0 && entry.compareTo(end) <= 0;
    }
}
