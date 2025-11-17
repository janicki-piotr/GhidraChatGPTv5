package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.script.AskDialog;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;
import ghidrachatgpt.ui.component.TextAskDialog;

import static ghidrachatgpt.ui.UIConstants.*;

public class SetThreadsAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Set amount of threads for auto mode";
    private static final String MENU_NAME = "Set Threads Amount";
    private final Logger logger;

    public SetThreadsAction(String name, String owner) {
        super(name, owner);
        logger = new Logger(this.getClass());
    }

    private String askForTimeout() {
        return TextAskDialog.open("Set Threads Amount", "Set Threads Amount:", AskDialog.LONG, String.valueOf(GlobalSettings.getAutoModeThreads()));
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        if (GlobalSettings.setAutoModeThreads(askForTimeout())) {
            logger.ok("Updated the thread amount to : " + GlobalSettings.getAutoModeThreads());
        } else {
            logger.ok("Thread  amount not updated");
        }
    }

    @Override
    public void setUp() {
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(
                new MenuData(new String[]{ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, AUTO_MODE,
                        SETTINGS_MENU, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
