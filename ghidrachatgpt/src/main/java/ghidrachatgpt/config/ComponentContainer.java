package ghidrachatgpt.config;

import docking.Tool;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidrachatgpt.GhidraChatGPTPlugin;
import ghidrachatgpt.openai.GPTClient;

public final class ComponentContainer {

    public static void initDockingTool(Tool dockingTool) {
        ComponentContainer.dockingTool = dockingTool;
    }

    public static void initConsoleService(ConsoleService consoleService) {
        ComponentContainer.consoleService = consoleService;
    }

    public static void initCodeViewerService(CodeViewerService codeViewerService) {
        ComponentContainer.codeViewerService = codeViewerService;
    }

    public static void initGhidraChatGPTPlugin(GhidraChatGPTPlugin ghidraChatGPTPlugin) {
        ComponentContainer.ghidraChatGPTPlugin = ghidraChatGPTPlugin;
    }

    private static Tool dockingTool;

    public static Tool getDockingTool() {
        return dockingTool;
    }

    private static ConsoleService consoleService;

    public static ConsoleService getConsoleService() {
        return consoleService;
    }

    private static CodeViewerService codeViewerService;

    public static CodeViewerService getCodeViewerService() {
        return codeViewerService;
    }

    private final static GPTClient gptClient = new GPTClient();

    public static GPTClient getGptClient() {
        return gptClient;
    }

    private static GhidraChatGPTPlugin ghidraChatGPTPlugin;

    public static GhidraChatGPTPlugin getGhidraChatGPTPlugin() {
        return ghidraChatGPTPlugin;
    }


}
