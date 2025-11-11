package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.openai.GPTService;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import static ghidrachatgpt.ui.UIConstants.*;

public class AutoAllFunctionsAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Analyze all functions in the program";
    private static final String MENU_NAME = "Analyze All Functions";
    private final GPTService gptService;

    public AutoAllFunctionsAction(String name, String owner) {
        super(name, owner);
        this.gptService = ComponentContainer.getGptService();
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        new Thread(gptService::autoMode).start();
        ComponentContainer.getComponentStateService().disableProcessingFunctions();
        ComponentContainer.getComponentStateService().enableStopFunction();
    }

    @Override
    public void setUp() {
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, AUTO_MODE, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
