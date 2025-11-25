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
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class CodeManipulationService {
    private static final Logger LOGGER = new Logger(GPTService.class);
    private static final String TRANSACTION_CODE = "GhidraChatGPT";
    private static final String ERROR_MARKER = "[AUTO_CHANGE_ERROR] ";
    private static final String TYPE_MARKER_PARAM = "[NO_TYPE_CHANGE_PARAM_WARNING] ";
    private static final String NAME_MARKER_PARAM = "[NO_NAME_CHANGE_PARAM_WARNING] ";
    private static final String TYPE_MARKER = "[NO_TYPE_CHANGE_WARNING] ";
    private static final String NAME_MARKER = "[NO_NAME_CHANGE_WARNING] ";

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
        updateFunctionParameters(prog, decResult, jsonObj, comment);
        updateFunctionsLocalVariables(prog, decResult, jsonObj, comment);

        addComment(decResult.prog, decResult.func, comment.toString(), "[GhidraChatGPT] - Beautified the function");
        prog.endTransaction(id, true);
    }

    private void updateFunctionsLocalVariables(Program prog, DecompilerResults decResult, JSONObject jsonObj, StringBuilder comment) {
        JSONObject namesObj = jsonObj.optJSONObject("names");
        JSONObject typesObj = jsonObj.optJSONObject("types");
        if (namesObj == null) {
            namesObj = new JSONObject();
        }
        if (typesObj == null) {
            typesObj = new JSONObject();
        }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(prog);
        ifc.setSimplificationStyle("decompile");

        DecompileResults decompileResults = ifc.decompileFunction(decResult.func, 30, TaskMonitor.DUMMY);

        HighFunction hfunc = decompileResults.getHighFunction();
        if (hfunc == null) {
            LOGGER.error("No HighFunction (decompiler failed?)");
            comment.append(ERROR_MARKER).append("Local Variables\n");
            return;
        }

        LOGGER.debug("Checking highSymbols");

        LocalSymbolMap lsm = hfunc.getLocalSymbolMap();
        Iterator<HighSymbol> it = lsm.getSymbols();


        if (it.hasNext()) {
            comment.append("Local Variables:\n");
        }
        while (it.hasNext()) {
            HighSymbol hs = it.next();
            LOGGER.debug("Checking highSymbol: " + hs.getName());
            HighVariable hv = hs.getHighVariable();
            if (hv == null) {
                continue;
            }

            String oldName = hv.getName();
            String newName = oldName;
            String oldType = hv.getDataType().toString();
            String newType = oldType;

            if ("UNNAMED".equals(oldName)) {
                continue;
            }

            LOGGER.debug("Checking variable: " + hv.getName());

            if (typesObj.has(oldName)) {
                newType = typesObj.getString(oldName);
            } else {
                comment.append(TYPE_MARKER);
            }

            if (namesObj.has(oldName)) {
                newName = namesObj.getString(oldName);
            } else {
                comment.append(NAME_MARKER);
            }

            try {
                if (!Objects.equals(newName, oldName) && !Objects.equals(newType, oldType)) {
                    HighFunctionDBUtil.updateDBVariable(hs, newName, parseDataType(prog, newType), SourceType.USER_DEFINED);
                } else if (!Objects.equals(newName, oldName)) {
                    HighFunctionDBUtil.updateDBVariable(hs, newName, null, SourceType.USER_DEFINED);
                } else if (!Objects.equals(newType, oldType)) {
                    HighFunctionDBUtil.updateDBVariable(hs, null, parseDataType(prog, newType), SourceType.USER_DEFINED);
                }

                LOGGER.ok(String.format("Beautified " + oldType + " " + oldName + " => " + newType + " " + newName));
            } catch (Exception e) {
                LOGGER.error("Failed to beautify  " + oldType + " " + oldName + " => " + newType + " " + newName, e);
                comment.append(ERROR_MARKER);
            }
            comment.append(oldType).append(" ").append(oldName).append(" -> ").append(newType).append(" ").append(newName).append("\n");
        }
    }

    private void updateFunctionParameters(Program prog, DecompilerResults decResult, JSONObject jsonObj, StringBuilder comment) {
        JSONObject namesObj = jsonObj.optJSONObject("names");
        JSONObject typesObj = jsonObj.optJSONObject("types");
        if (namesObj == null) {
            namesObj = new JSONObject();
        }
        if (typesObj == null) {
            typesObj = new JSONObject();
        }

        Variable[] vars = decResult.func.getParameters();
        if (vars == null) {
            LOGGER.info("No parameters to beatify");
            return;
        }
        if (vars.length > 0) {
            comment.append("Function Parameters:\n");
        }
        for (Variable var : vars) {
            String oldName = var.getName();
            String newName = oldName;
            String oldType = var.getDataType().toString();
            String newType = oldType;
            if ("UNNAMED".equals(oldName)) {
                continue;
            }
            LOGGER.debug("Checking variable: " + oldName);
            if (typesObj.has(oldName)) {
                newType = typesObj.getString(oldName);
                try {
                    updateVariableType(prog, var, newType);
                    LOGGER.ok(String.format("Beautified " + oldName + " type => " + newType));
                } catch (Exception exception) {
                    LOGGER.error(String.format("Failed to set" + oldName + " type => " + newType), exception);
                    comment.append(ERROR_MARKER);
                }
            } else {
                comment.append(TYPE_MARKER_PARAM);
            }

            if (namesObj.has(oldName)) {
                newName = namesObj.getString(oldName);
                try {
                    var.setName(newName, SourceType.USER_DEFINED);
                    LOGGER.ok(String.format("Beautified %s => %s", var.getName(), newName));
                } catch (Exception exception) {
                    LOGGER.error(String.format("Failed to beautify %s => %s", oldName, newName), exception);
                    if (!comment.toString().contains(ERROR_MARKER)) {
                        comment.append(ERROR_MARKER);
                    }
                }
            } else {
                comment.append(NAME_MARKER_PARAM);
            }
            comment.append(oldType).append(" ").append(oldName).append(" -> ").append(newType).append(" ").append(newName).append("\n");
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

        String oldReturnType = decResult.func.getReturnType().getName();
        try {
            updateFunctionReturnType(prog, decResult.func, returnTypeStr);
            LOGGER.ok(String.format("Beautified return type => %s", returnTypeStr));
            comment.append("Return Type: ").append(oldReturnType).append(" -> ").append(returnTypeStr).append("\n");
        } catch (Exception exception) {
            LOGGER.error(String.format("Failed to set return type => %s", returnTypeStr), exception);
            comment.append(ERROR_MARKER).append("Return Type: ").append(oldReturnType).append(" -> ").append(returnTypeStr).append("\n");
        }
    }

    private void updateVariableType(Program program, Variable var, String userTypeName) throws Exception {
        if (program == null || var == null || userTypeName == null) {
            return;
        }

        userTypeName = userTypeName.trim();
        if (userTypeName.isEmpty()) {
            return;
        }

        DataType dt = parseDataType(program, userTypeName);

        var.setDataType(dt, SourceType.USER_DEFINED);
    }

    private void updateFunctionReturnType(Program program, Function func, String userTypeName) throws Exception {
        if (program == null || func == null || userTypeName == null) {
            return;
        }

        userTypeName = userTypeName.trim();
        if (userTypeName.isEmpty()) {
            return;
        }

        DataType dt = parseDataType(program, userTypeName);

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

    private DataType parseDataType(Program program, String userTypeName) {
        DataType dt;
        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataTypeManagerService dtService = ComponentContainer.getDockingTool().getService(DataTypeManagerService.class);
            DataTypeParser parser = new DataTypeParser(dtm, dtm, new FirstMatchDataTypeQueryService(dtService), DataTypeParser.AllowedDataTypes.DYNAMIC);
            dt = parser.parse(userTypeName);
        } catch (Exception exception) {
            dt = resolveSimpleType(program, userTypeName);
        }

        if (dt == null) {
            throw new IllegalArgumentException("Unknown return type: " + userTypeName);
        }

        return dt;
    }
}
