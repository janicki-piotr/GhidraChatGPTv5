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

public class UpdateInstructionsAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Update the current Instructions";
    private static final String MENU_NAME = "Update Instructions";
    private final Logger logger;

    public UpdateInstructionsAction(String name, String owner) {
        super(name, owner);
        logger = new Logger(this.getClass());
    }

    private String askForInstructions() {
        return TextAskDialog.open("Instructions configuration", "Enter instructions:", AskDialog.STRING, GlobalSettings.getInstructions());
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        if (GlobalSettings.setInstructions(askForInstructions())) {
            var currentInstructions = GlobalSettings.getInstructions();
            if (currentInstructions == null) {
                logger.ok("Instructions disabled");
            } else {
                logger.ok("Updated the instructions to: " + currentInstructions);
            }
        } else {
            logger.ok("Instructions not updated");
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
