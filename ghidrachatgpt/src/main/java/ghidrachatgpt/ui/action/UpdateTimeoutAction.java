package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.script.AskDialog;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;
import ghidrachatgpt.ui.component.TextAskDialog;

import static ghidrachatgpt.ui.UIConstants.ROOT_MENU_NAME;
import static ghidrachatgpt.ui.UIConstants.SETTINGS_MENU;

public class UpdateTimeoutAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Update the request timeout";
    private static final String MENU_NAME = "Set Request Timeout";
    private final Logger logger;

    public UpdateTimeoutAction(String name, String owner) {
        super(name, owner);
        logger = new Logger(this.getClass());
    }

    private String askForTimeout() {
        return TextAskDialog.open("Update OpenAI Request Timeout", "Timeout in seconds, will be rounded up to 15 seconds:", AskDialog.LONG, String.valueOf(GlobalSettings.getRequestTimeout()));
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        if (GlobalSettings.setRequestTimeout(askForTimeout())) {
            logger.ok("Updated the request timeout to: " + GlobalSettings.getRequestTimeout());
        } else {
            logger.ok("Request Timeout not updated");
        }
    }

    @Override
    public void setUp() {
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(
                new MenuData(new String[]{ToolConstants.MENU_TOOLS, ROOT_MENU_NAME,
                        SETTINGS_MENU, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
