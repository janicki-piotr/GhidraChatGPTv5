package ghidrachatgpt.openai;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.ghidra.CodeManipulationService;
import ghidrachatgpt.ghidra.DecompilerResults;
import ghidrachatgpt.ghidra.DecompilerService;
import ghidrachatgpt.ghidra.StopProcessingException;
import ghidrachatgpt.log.Logger;
import ghidrachatgpt.ui.action.UpdateTokenAction;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import static ghidrachatgpt.config.PromptConstraints.*;

public class GPTService {
    private static final Logger LOGGER = new Logger(GPTService.class);
    private final DecompilerService decompilerService;
    private final CodeManipulationService codeManipulationService;
    private final GPTClient gptClient;
    private final AtomicBoolean stop = new AtomicBoolean(false);

    public GPTService(DecompilerService decompilerService, CodeManipulationService codeManipulationService, GPTClient gptClient) {
        this.decompilerService = decompilerService;
        this.codeManipulationService = codeManipulationService;
        this.gptClient = gptClient;
    }

    public void stop() {
        LOGGER.info("Stopping the identifying process");
        stop.set(true);
    }

    private void unstop() {
        stop.set(false);
    }

    public void autoMode() {
        unstop();
        autoMode(limitStream(findAllFunctionsToProcess()));

        LOGGER.info("Auto Mode is done.");
        ComponentContainer.getComponentStateService().enableProcessingFunctions();
        ComponentContainer.getComponentStateService().disableStopFunction();
    }

    public void autoMode(Address start, Address end) {
        unstop();
        autoMode(limitStream(findAllFunctionsToProcess(start, end)));

        LOGGER.info("Auto Mode is done.");
        ComponentContainer.getComponentStateService().enableProcessingFunctions();
        ComponentContainer.getComponentStateService().disableStopFunction();
    }

    private void autoMode(List<Function> functions) {
        if (!checkOpenAIToken()) {
            return;
        }

        ProgramLocation programLocation = ComponentContainer.getCodeViewerService().getCurrentLocation();
        ExecutorService executor = Executors.newFixedThreadPool(GlobalSettings.getAutoModeThreads());
        try {
            functions.forEach(function -> executor.submit(() -> {
                if (stop.get()) {
                    return;
                }
                try {
                    autoModeFunctionProcess(function);
                } catch (StopProcessingException exception) {
                    executor.shutdownNow();
                }
            }));
            executor.shutdown();
            executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            LOGGER.error("Error during processing:" + e);
        } finally {
            executor.shutdownNow();
        }
    }

    private void autoModeFunctionProcess(Function function) {
        DecompilerResults decResult = decompilerService.decompileCurrentFunc(function.getProgram(), function);
        if (stop.get()) {
            throw new StopProcessingException();
        }
        if (GlobalSettings.isEnableBeautifyFunctionInAuto()) {
            beautifyFunction(decResult);
        }
        if (stop.get()) {
            throw new StopProcessingException();
        }
        if (GlobalSettings.isEnableIdentifyFunctionInAuto()) {
            identifyFunction(decResult);
        }
        if (stop.get()) {
            throw new StopProcessingException();
        }
        if (GlobalSettings.isEnableFindVulnerabilitiesInAuto()) {
            findVulnerabilities(decResult);
        }
    }

    private List<Function> limitStream(Stream<Function> stream) {
        Long limit = GlobalSettings.getLimitFunctions();
        if (limit != 0) {
            return stream.limit(limit).toList();
        }
        return stream.toList();
    }

    private Stream<Function> findAllFunctionsToProcess(Address start, Address end) {
        return codeManipulationService.getAllDefinedFunctions(GlobalSettings.isAutoModeIncludeExternals(), GlobalSettings.isAutoModeIncludeThunks())
                .stream()
                .filter(function -> !GlobalSettings.isSkipProcessed() || codeManipulationService.isFunctionNotProcessedByPlugin(function))
                .filter(codeManipulationService::isFunctionNotProcessedByCommentChars)
                .filter(function -> codeManipulationService.isFunctionEntryInRange(function, start, end));
    }

    private Stream<Function> findAllFunctionsToProcess() {
        return codeManipulationService.getAllDefinedFunctions(GlobalSettings.isAutoModeIncludeExternals(), GlobalSettings.isAutoModeIncludeThunks())
                .stream()
                .filter(function -> !GlobalSettings.isSkipProcessed() || codeManipulationService.isFunctionNotProcessedByPlugin(function))
                .filter(codeManipulationService::isFunctionNotProcessedByCommentChars);
    }

    public void testCall() {
        unstop();
        DecompilerResults decResult = decompilerService.decompileCurrentFunc();
        if (decResult == null) {
            ComponentContainer.getComponentStateService().enableProcessingFunctions();
            ComponentContainer.getComponentStateService().disableStopFunction();
            return;
        }

        LOGGER.info(String.format("Test call result will be added to function: %s", decResult.func.getName()));

        String result = askChatGPT("2+2", null);
        if (result == null) {
            ComponentContainer.getComponentStateService().enableProcessingFunctions();
            ComponentContainer.getComponentStateService().disableStopFunction();
            return;
        }

        codeManipulationService.addComment(decResult.prog, decResult.func, result, "[GhidraChatGPT] - Test response");
        ComponentContainer.getComponentStateService().enableProcessingFunctions();
        ComponentContainer.getComponentStateService().disableStopFunction();
    }

    public void identifyFunction() {
        unstop();
        DecompilerResults decResult = decompilerService.decompileCurrentFunc();
        identifyFunction(decResult);
        ComponentContainer.getComponentStateService().enableProcessingFunctions();
        ComponentContainer.getComponentStateService().disableStopFunction();
    }

    private void identifyFunction(DecompilerResults decResult) {
        if (decResult == null)
            return;

        LOGGER.info(String.format("Identifying the current function: %s",
                decResult.func.getName()));
        String result = askChatGPT(
                String.format(getGcgIdentifyString(), decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null)
            return;

        codeManipulationService.addComment(decResult.prog, decResult.func, result, "[GhidraChatGPT] - Identify Function");
    }

    public void findVulnerabilities() {
        unstop();
        DecompilerResults decResult = decompilerService.decompileCurrentFunc();
        findVulnerabilities(decResult);
        ComponentContainer.getComponentStateService().enableProcessingFunctions();
        ComponentContainer.getComponentStateService().disableStopFunction();
    }

    private void findVulnerabilities(DecompilerResults decResult) {
        if (decResult == null) {
            return;
        }

        LOGGER.info(String.format("Finding vulnerabilities in the current function: %s",
                decResult.func.getName()));
        String result = askChatGPT(
                String.format(getGcgVulnerabilityString(), decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null) {
            return;
        }

        codeManipulationService.addComment(decResult.prog, decResult.func, result,
                "[GhidraChatGPT] - Find Vulnerabilities");
    }

    public void beautifyFunction() {
        unstop();
        DecompilerResults decResult = decompilerService.decompileCurrentFunc();
        beautifyFunction(decResult);
        ComponentContainer.getComponentStateService().enableProcessingFunctions();
        ComponentContainer.getComponentStateService().disableStopFunction();
    }

    private void beautifyFunction(DecompilerResults decResult) {
        if (decResult == null || decResult.decompiledFunc == null) {
            return;
        }

        LOGGER.info(String.format("Beautifying the function: %s",
                decResult.func.getName()));
        String result = askChatGPT(
                String.format(getGcgBeautifyString(), decResult.getPromptElement()), GlobalSettings.getInstructions());
        if (result == null) {
            return;
        }
        int firstBrace = result.indexOf('{');
        int lastBrace = result.lastIndexOf('}');
        if (firstBrace >= 0 && lastBrace > firstBrace) {
            result = result.substring(firstBrace, lastBrace + 1);
        }
        codeManipulationService.updateVariables(decResult.prog, decResult, result);

        LOGGER.ok(String.format("Beautified the function: %s", decResult.func.getName()));
    }

    private String askChatGPT(String prompt, String instructions) {
        if (stop.get()) {
            LOGGER.info("Process stopped by user");
            return null;
        }

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
            if (currentTry > ((GlobalSettings.getRequestTimeout() + 14) / 15) * 15) {
                LOGGER.error("OpenAI Request timeout");
                return null;
            }
            if (stop.get()) {
                LOGGER.info("Process stopped by user");
                return null;
            }
            try {
                Thread.sleep(30000);
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
