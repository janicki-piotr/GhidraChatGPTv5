package ghidrachatgpt.openai;

import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.ghidra.CodeManipulationService;
import ghidrachatgpt.ghidra.DecompilerResults;
import ghidrachatgpt.ghidra.DecompilerService;
import ghidrachatgpt.log.Logger;
import ghidrachatgpt.ui.action.UpdateTokenAction;

import static ghidrachatgpt.config.PromptConstraints.*;

public class GPTService {
    private static final Logger LOGGER = new Logger(GPTService.class);
    private final DecompilerService decompilerService;
    private final CodeManipulationService codeManipulationService;
    private final GPTClient gptClient;

    public GPTService(DecompilerService decompilerService, CodeManipulationService codeManipulationService, GPTClient gptClient) {
        this.decompilerService = decompilerService;
        this.codeManipulationService = codeManipulationService;
        this.gptClient = gptClient;
    }

    public void testCall() {
        DecompilerResults decResult = decompilerService.decompileCurrentFunc();
        if (decResult == null)
            return;

        LOGGER.info(String.format("Test call result will be added to function: %s", decResult.func.getName()));

        String result = askChatGPT("2+2", null);
        if (result == null)
            return;

        codeManipulationService.addComment(decResult.prog, decResult.func, result, "[GhidraChatGPT] - Test response");
    }

    public void identifyFunction() {
        String result;
        DecompilerResults decResult = decompilerService.decompileCurrentFunc();
        if (decResult == null)
            return;

        LOGGER.info(String.format("Identifying the current function: %s",
                decResult.func.getName()));
        result = askChatGPT(
                String.format(getGcgIdentifyString(), decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null)
            return;

        codeManipulationService.addComment(decResult.prog, decResult.func, result, "[GhidraChatGPT] - Identify Function");
    }

    public void findVulnerabilities() {
        String result;
        DecompilerResults decResult = decompilerService.decompileCurrentFunc();
        if (decResult == null)
            return;

        LOGGER.info(String.format("Finding vulnerabilities in the current function: %s",
                decResult.func.getName()));
        result = askChatGPT(
                String.format(getGcgVulnerabilityString(), decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null)
            return;

        codeManipulationService.addComment(decResult.prog, decResult.func, result,
                "[GhidraChatGPT] - Find Vulnerabilities");
    }

    public void beautifyFunction() {
        String result;
        DecompilerResults decResult = decompilerService.decompileCurrentFunc();
        if (decResult == null || decResult.decompiledFunc == null)
            return;

        LOGGER.info(String.format("Beautifying the function: %s",
                decResult.func.getName()));
        result = askChatGPT(
                String.format(getGcgBeautifyString(), decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null)
            return;

        codeManipulationService.updateVariables(decResult.prog, decResult, result);
        LOGGER.ok(String.format("Beautified the function: %s", decResult.func.getName()));
    }

    private String askChatGPT(String prompt, String instructions) {
        if (!checkOpenAIToken()) {
            return null;
        }

        String responseId = gptClient.sendOpenAIRequestAsync(prompt, instructions);
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
            result = gptClient.checkAndGetOpenAIResponseAsync(responseId);
        } while (result == null);

        return result;
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
}
