package ghidrachatgpt.ghidra;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.data.DataTypeParser;
import ghidra.util.task.TaskMonitor;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;
import ghidrachatgpt.openai.GPTService;
import org.json.JSONObject;

import java.util.Iterator;
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

    public void updateVariables(Program prog, DecompilerResults decResult, String result) {
        StringBuilder comment = new StringBuilder("Changes to function:\n");
        JSONObject jsonObj;
        try {
            jsonObj = new JSONObject(result);
        } catch (Exception exception) {
            LOGGER.error("Failed to parse beautify JSON", exception);
            return;
        }

        int id = prog.startTransaction(TRANSACTION_CODE);

        updateFunctionReturnType(prog, decResult, jsonObj, comment);
        updateFunctionName(decResult, jsonObj, comment);
        updateFunctionParameters(decResult, jsonObj, comment);
        updateFunctionsLocalVariables(prog, decResult, jsonObj, comment);

        addComment(decResult.prog, decResult.func, comment.toString(), "[GhidraChatGPT] - Beautified the function");
        prog.endTransaction(id, true);
    }

    private void updateFunctionsLocalVariables(Program prog, DecompilerResults decResult, JSONObject jsonObj, StringBuilder comment) {
        JSONObject namesObj = jsonObj.optJSONObject("names");
        if (namesObj == null) {
            LOGGER.info("No \"names\" object in beautify JSON");
            return;
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(prog);
        ifc.setSimplificationStyle("decompile");

        DecompileResults decompileResults = ifc.decompileFunction(decResult.func, 30, TaskMonitor.DUMMY);

        HighFunction hfunc = decompileResults.getHighFunction();
        if (hfunc == null) {
            LOGGER.error("No HighFunction (decompiler failed?)");
            return;
        }

        LOGGER.debug("Checking highSymbols");

        LocalSymbolMap lsm = hfunc.getLocalSymbolMap();
        Iterator<HighSymbol> it = lsm.getSymbols();

        boolean isFirstParam = true;
        while (it.hasNext()) {
            HighSymbol hs = it.next();
            LOGGER.debug("Checking highSymbol: " + hs.getName());
            HighVariable hv = hs.getHighVariable();
            if (hv == null) {
                continue;
            }

            LOGGER.debug("Checking variable: " + hv.getName());
            String oldName = hv.getName();
            if (!namesObj.has(oldName))
                continue;

            String newName = namesObj.getString(oldName);
            try {
                HighFunctionDBUtil.updateDBVariable(hs, newName, null, SourceType.USER_DEFINED);
                LOGGER.ok("Renamed " + oldName + " => " + newName);
                if (isFirstParam) {
                    comment.append("Local Variables:\n");
                    isFirstParam = false;
                }
                comment.append(oldName).append(" -> ").append(newName).append("\n");
            } catch (Exception e) {
                LOGGER.error("Failed to rename " + oldName + " => " + newName, e);
            }
        }
    }

    private void updateFunctionParameters(DecompilerResults decResult, JSONObject jsonObj, StringBuilder comment) {
        JSONObject namesObj = jsonObj.optJSONObject("names");
        if (namesObj == null) {
            LOGGER.info("No \"names\" object in beautify JSON");
            return;
        }

        Variable[] vars = decResult.func.getParameters();
        if (vars == null) {
            LOGGER.info("No parameters to beatify");
            return;
        }
        boolean isFirstParam = true;
        for (Variable var : vars) {
            String oldName = var.getName();
            LOGGER.debug("Checking variable: " + oldName);
            if (namesObj.has(oldName)) {
                String newName = namesObj.getString(oldName);
                try {
                    var.setName(newName, SourceType.USER_DEFINED);
                    LOGGER.ok(String.format("Beautified %s => %s", var.getName(), newName));
                    if (isFirstParam) {
                        comment.append("Function Parameters:\n");
                        isFirstParam = false;
                    }
                    comment.append(oldName).append(" -> ").append(newName).append("\n");
                } catch (Exception exception) {
                    LOGGER.error(String.format("Failed to beautify %s => %s", oldName, newName), exception);
                }
            }
        }
    }

    private void updateFunctionName(DecompilerResults decResult, JSONObject jsonObj, StringBuilder comment) {
        JSONObject namesObj = jsonObj.optJSONObject("names");
        if (namesObj == null) {
            LOGGER.info("No \"names\" object in beautify JSON");
            return;
        }

        String oldName = decResult.func.getName();
        if (namesObj.has(oldName)) {
            String newName = namesObj.getString(oldName);
            try {
                decResult.func.setName(newName, SourceType.USER_DEFINED);
                LOGGER.ok(String.format("Beautified %s => %s", decResult.func.getName(), newName));
                comment.append("Function Name: ").append(oldName).append(" -> ").append(newName).append("\n");
            } catch (Exception exception) {
                LOGGER.error(String.format("Failed to beautify %s => %s", decResult.func.getName(), newName), exception);
            }
        }
    }


    private void updateFunctionReturnType(Program prog, DecompilerResults decResult, JSONObject
            jsonObj, StringBuilder comment) {
        if (!jsonObj.has("returnType")) {
            return;
        }

        String returnTypeStr = jsonObj.optString("returnType", "").trim();
        if (returnTypeStr.isEmpty()) {
            return;
        }

        try {
            String oldReturnType = decResult.func.getReturnType().getName();
            updateFunctionReturnType(prog, decResult.func, returnTypeStr);
            LOGGER.ok(String.format("Beautified return type => %s", returnTypeStr));
            comment.append("Return Type: ").append(oldReturnType).append(" -> ").append(returnTypeStr).append("\n");
        } catch (Exception exception) {
            LOGGER.error(String.format("Failed to set return type => %s", returnTypeStr), exception);
        }
    }

    private void updateFunctionReturnType(Program program, Function func, String userTypeName) throws Exception {
        if (program == null || func == null || userTypeName == null) {
            return;
        }

        userTypeName = userTypeName.trim();
        if (userTypeName.isEmpty()) {
            return;
        }

        DataType dt;
        try {
            DataTypeManagerService dtService = ComponentContainer.getDockingTool().getService(DataTypeManagerService.class);
            DataTypeParser parser = new DataTypeParser(dtService, DataTypeParser.AllowedDataTypes.DYNAMIC);
            dt = parser.parse(userTypeName);
        } catch (Exception exception) {
            dt = resolveSimpleType(program, userTypeName);
        }

        if (dt == null) {
            throw new IllegalArgumentException("Unknown return type: " + userTypeName);
        }

        func.setReturnType(dt, SourceType.USER_DEFINED);
    }

    private DataType resolveSimpleType(Program program, String userTypeName) {
        switch (userTypeName) {
            case "void":
                return VoidDataType.dataType;
            case "char":
                return CharDataType.dataType;
            case "uchar":
            case "unsigned char":
                return UnsignedCharDataType.dataType;
            case "short":
                return ShortDataType.dataType;
            case "ushort":
            case "unsigned short":
                return UnsignedShortDataType.dataType;
            case "int":
            case "sint":
                return IntegerDataType.dataType;
            case "uint":
            case "unsigned int":
                return UnsignedIntegerDataType.dataType;
            case "long":
                return LongDataType.dataType;
            case "ulong":
            case "unsigned long":
                return UnsignedLongDataType.dataType;
            case "float":
                return FloatDataType.dataType;
            case "double":
                return DoubleDataType.dataType;
            default:
                break;
        }

        return program.getDataTypeManager().getDataType(CategoryPath.ROOT, userTypeName);
    }

    public List<Function> getAllDefinedFunctions(boolean includeExternals, boolean includeThunks) {
        ProgramLocation programLocation = ComponentContainer.getCodeViewerService().getCurrentLocation();
        Program program = programLocation.getProgram();
        return StreamSupport.stream(program.getFunctionManager().getFunctions(true).spliterator(), false)
                .filter(f -> includeExternals || !f.isExternal())
                .filter(f -> includeThunks || !f.isThunk())
                .collect(Collectors.toList());
    }

    public boolean isFunctionNotProcessedByPlugin(Function function) {
        String comment = function.getComment();
        return comment == null || !comment.contains("[GhidraChatGPT]");
    }

    public boolean isFunctionNotProcessedByCommentChars(Function function) {
        String comment = function.getComment();
        Long commentChars = GlobalSettings.getSkipByCommentChars();
        if (commentChars == 0 || comment == null || comment.isEmpty()) {
            return true;
        }
        return comment.length() < commentChars;
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
