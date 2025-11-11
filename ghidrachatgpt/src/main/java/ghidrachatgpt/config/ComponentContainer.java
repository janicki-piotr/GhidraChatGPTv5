package ghidrachatgpt.config;

import docking.Tool;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidrachatgpt.GhidraChatGPTPlugin;
import ghidrachatgpt.ghidra.CodeManipulationService;
import ghidrachatgpt.ghidra.DecompilerService;
import ghidrachatgpt.openai.GPTClient;
import ghidrachatgpt.openai.GPTService;
import ghidrachatgpt.ui.component.ComponentStateService;

public final class ComponentContainer {
    private static Tool dockingTool;
    private static ConsoleService consoleService;
    private static CodeViewerService codeViewerService;
    private static PluginTool pluginTool;

    private static GhidraChatGPTPlugin ghidraChatGPTPlugin;
    private static ComponentStateService componentStateService;


    private static final GPTService GPT_SERVICE = new GPTService(new DecompilerService(), new CodeManipulationService(), new GPTClient());

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

    public static Tool getDockingTool() {
        return dockingTool;
    }

    public static ConsoleService getConsoleService() {
        return consoleService;
    }

    public static CodeViewerService getCodeViewerService() {
        return codeViewerService;
    }

    public static GhidraChatGPTPlugin getGhidraChatGPTPlugin() {
        return ghidraChatGPTPlugin;
    }

    public static PluginTool getPluginTool() {
        return pluginTool;
    }

    public static void initCPluginTool(PluginTool pluginTool) {
        ComponentContainer.pluginTool = pluginTool;
    }

    public static GPTService getGptService() {
        return GPT_SERVICE;
    }

    public static ComponentStateService getComponentStateService() {
        return componentStateService;
    }

    public static void initComponentStateService(ComponentStateService componentStateService) {
        ComponentContainer.componentStateService = componentStateService;
    }
}
