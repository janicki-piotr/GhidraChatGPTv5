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

public class UpdateLimitFunctionsAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Update the max functions amount than can be analysed";
    private static final String MENU_NAME = "Function Amount Limit";
    private final Logger logger;

    public UpdateLimitFunctionsAction(String name, String owner) {
        super(name, owner);
        logger = new Logger(this.getClass());
    }

    private String askForLimit() {
        return TextAskDialog.open("Update Functions Limit", "Limit functions to analyze, 0 to disable the limit", AskDialog.LONG, String.valueOf(GlobalSettings.getLimitFunctions()));
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        if (GlobalSettings.setLimitFunctions(askForLimit())) {
            logger.ok("Updated the functions limit to: " + GlobalSettings.getLimitFunctions());
        } else {
            logger.ok("Functions limit not updated");
        }
    }

    @Override
    public void setUp() {
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(
                new MenuData(new String[]{
                        ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, AUTO_MODE, SETTINGS_MENU, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
