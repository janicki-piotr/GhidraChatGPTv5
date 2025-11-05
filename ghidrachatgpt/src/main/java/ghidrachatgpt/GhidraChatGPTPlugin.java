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

package ghidrachatgpt;


import ghidra.app.CorePluginPackage;
import ghidra.app.decompiler.flatapi.FlatDecompilerAPI;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;
import ghidrachatgpt.ui.component.MenuComponent;
import ghidrachatgpt.ui.action.UpdateTokenAction;
import org.json.JSONObject;

import static ghidrachatgpt.ui.action.UpdateTokenAction.censorToken;


@PluginInfo(
        status = PluginStatus.RELEASED,
        packageName = CorePluginPackage.NAME,
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "ChatGPT Plugin for Ghidra",
        description = "Brings the power of ChatGPT to Ghidra!",
        servicesRequired = {ConsoleService.class, CodeViewerService.class}
)
public class GhidraChatGPTPlugin extends ProgramPlugin {
    private static final String GCG_IDENTIFY_STRING =
            "Describe the function with as much detail as possible and include a link to an open source version if there is one\n %s";
    private static final String GCG_VULNERABILITY_STRING =
            "Describe all vulnerabilities in this function with as much detail as possible\n %s";
    private static final String GCG_BEAUTIFY_STRING =
            "Analyze the decompiled C function and suggest function and variable names in a json format where the key is the previous name and the value is the suggested name\n %s";

    private static final Logger LOGGER = new Logger(GhidraChatGPTPlugin.class);


    public GhidraChatGPTPlugin(PluginTool tool) {
        super(tool);
        ComponentContainer.initGhidraChatGPTPlugin(this);
        MenuComponent menuComponent = new MenuComponent(this, getName());
        String topicName = this.getClass().getPackage().getName();
        String anchorName = "HelpAnchor";
        menuComponent.setHelpLocation(new HelpLocation(topicName, anchorName));
    }

    @Override
    public void init() {
        super.init();
        ComponentContainer.initConsoleService(tool.getService(ConsoleService.class));
        ComponentContainer.initCodeViewerService(tool.getService(CodeViewerService.class));

        GlobalSettings.setAccessToken(System.getenv("OPENAI_TOKEN"));
        if (GlobalSettings.getAccessToken() != null)
            LOGGER.ok(String.format("Loaded OpenAI Token: %s", censorToken(GlobalSettings.getAccessToken())));

        ComponentContainer.initGhidraChatGPTPlugin(this);
        LOGGER.ok(String.format("Default model is: %s", GlobalSettings.getOpenAiModel()));
    }

    public void testCall() {
        DecompilerResults decResult = decompileCurrentFunc();
        if (decResult == null)
            return;

        LOGGER.info(String.format("Test call result will be added to function: %s", decResult.func.getName()));

        String result = askChatGPT("2+2", null);
        if (result == null)
            return;

        addComment(decResult.prog, decResult.func, result, "[GhidraChatGPT] - Test response");
    }

    public void identifyFunction() {
        String result;
        DecompilerResults decResult = decompileCurrentFunc();
        if (decResult == null)
            return;

        LOGGER.info(String.format("Identifying the current function: %s",
                decResult.func.getName()));
        result = askChatGPT(
                String.format(GCG_IDENTIFY_STRING, decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null)
            return;

        addComment(decResult.prog, decResult.func, result, "[GhidraChatGPT] - Identify Function");
    }

    public void findVulnerabilities() {
        String result;
        DecompilerResults decResult = decompileCurrentFunc();
        if (decResult == null)
            return;

        LOGGER.info(String.format("Finding vulnerabilities in the current function: %s",
                decResult.func.getName()));
        result = askChatGPT(
                String.format(GCG_VULNERABILITY_STRING, decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null)
            return;

        addComment(decResult.prog, decResult.func, result,
                "[GhidraChatGPT] - Find Vulnerabilities");
    }

    public void beautifyFunction() {
        String result;
        DecompilerResults decResult = decompileCurrentFunc();
        if (decResult == null || decResult.decompiledFunc == null)
            return;

        LOGGER.info(String.format("Beautifying the function: %s",
                decResult.func.getName()));
        result = askChatGPT(
                String.format(GCG_BEAUTIFY_STRING, decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null)
            return;

        updateVariables(decResult.prog, decResult, result);
        LOGGER.ok(String.format("Beautified the function: %s", decResult.func.getName()));
    }

    private Boolean checkOpenAIToken() {
        if (GlobalSettings.getAccessToken() != null && !GlobalSettings.getAccessToken().isEmpty()) {
            return true;
        }
        new UpdateTokenAction("", "").actionPerformed(null);
        if (GlobalSettings.getAccessToken() == null || GlobalSettings.getAccessToken().isEmpty()) {
            LOGGER.error("Failed to update the OpenAI API token");
            return false;
        }
        return true;
    }

    private static class DecompilerResults {
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
            StringBuilder sb = new StringBuilder();
            if (asmFunc != null) {
                sb.append("Asm function code:\n").append(asmFunc).append("\n");
            }
            if (decompiledFunc != null) {
                sb.append("Decompiled C function code:").append(decompiledFunc);
            }
            LOGGER.debug("Prompt element: " + sb);
            return sb.toString();
        }
    }

    private DecompilerResults decompileCurrentFunc() {
        String decompiledFunc = null;
        String asmFunc = null;

        ProgramLocation progLoc = ComponentContainer.getCodeViewerService().getCurrentLocation();
        Program prog = progLoc.getProgram();
        FlatProgramAPI programApi = new FlatProgramAPI(prog);
        FlatDecompilerAPI decompiler = new FlatDecompilerAPI(programApi);
        Function func = programApi.getFunctionContaining(progLoc.getAddress());

        if (func == null) {
            LOGGER.error("Failed to find the current function");
            return null;
        }

        if (GlobalSettings.isAttachCCode()) {
            try {
                decompiledFunc = decompiler.decompile(func);
                LOGGER.debug("function: " + decompiledFunc);
            } catch (Exception e) {
                LOGGER.error(String.format(
                        "Failed to decompile the function: %s with the error %s",
                        func.getName(), e));
                if (!GlobalSettings.isAttachAsmCode()) {
                    return null;
                }
            }
        }

        if (GlobalSettings.isAttachAsmCode()) {
            asmFunc = getAsmFunction(func, prog);
            LOGGER.debug("function: " + asmFunc);
        }

        return new DecompilerResults(prog, func, decompiledFunc, asmFunc);
    }

    private String getAsmFunction(Function function, Program program) {
        CodeUnitFormat fmt = new BrowserCodeUnitFormat(tool);

        Listing listing = program.getListing();
        AddressSetView body = function.getBody();

        StringBuilder asm = new StringBuilder();
        for (Instruction ins : listing.getInstructions(body, true)) {
            asm.append(ins.getAddress()).append(": ")
                    .append(fmt.getRepresentationString(ins))
                    .append('\n');
        }

        return asm.toString();
    }

    private void updateVariables(Program prog, DecompilerResults decResult,
                                 String result) {
        JSONObject jsonObj;
        try {
            jsonObj = new JSONObject(result);
        } catch (Exception e) {
            LOGGER.error("Failed to parse beautify JSON");
            return;
        }

        Variable[] vars = decResult.func.getAllVariables();
        if (vars == null) {
            LOGGER.info("Nothing to beautify");
            return;
        }

        var id = prog.startTransaction("GhidraChatGPT");
        for (Variable var : vars) {
            if (jsonObj.has(var.getName())) {
                String val = jsonObj.getString(var.getName());
                try {
                    var.setName(val, SourceType.USER_DEFINED);
                    LOGGER.ok(String.format("Beautified %s => %s", var.getName(), val));
                } catch (Exception e) {
                    LOGGER.error(
                            String.format("Failed to beautify %s => %s", var.getName(), val));
                }
            }
        }

        if (jsonObj.has(decResult.func.getName())) {
            String val = jsonObj.getString(decResult.func.getName());
            try {
                decResult.func.setName(val, SourceType.USER_DEFINED);
                LOGGER.ok(String.format("Beautified %s => %s", decResult.func.getName(), val));
            } catch (Exception e) {
                LOGGER.error(String.format("Failed to beautify %s => %s",
                        decResult.func.getName(), val));
            }
        }

        prog.endTransaction(id, true);
    }

    private void addComment(Program prog, Function func, String comment,
                            String commentHeader) {
        var id = prog.startTransaction("GhidraChatGPT");
        String currentComment = func.getComment();
        if (currentComment != null) {
            currentComment =
                    String.format("%s\n%s\n\n%s", commentHeader, comment, currentComment);
        } else {
            currentComment = String.format("%s\n%s", commentHeader, comment);
        }

        func.setComment(currentComment);
        prog.endTransaction(id, true);
        LOGGER.ok(String.format(
                "Added the ChatGPT response as a comment to the function: %s",
                func.getName()));
    }

    private String askChatGPT(String prompt, String instructions) {
        if (!checkOpenAIToken()) {
            return null;
        }

        String responseId = ComponentContainer.getGptClient().sendOpenAIRequestAsync(prompt, instructions);
        if (responseId == null) {
            LOGGER.error("The ChatGPT response was empty, try again!");
            return null;
        }
        String result;
        int currentTry = 1;
        do {
            try {
                Thread.sleep(15000);
            } catch (InterruptedException e) {
                LOGGER.error("Error during waiting for response: " + e.getMessage(), e);
                Thread.currentThread().interrupt();
            }
            LOGGER.info("Asking for response for " + responseId + " " + currentTry + " try");
            currentTry++;
            result = ComponentContainer.getGptClient().checkAndGetOpenAIResponseAsync(responseId);
        } while (result == null);

        return result;
    }
}
