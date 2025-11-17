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

public class SetSkipByCommentCharsAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Skip function, when chars amount is bigger than";
    private static final String MENU_NAME = "Skip Functions By Comment Size";
    private final Logger logger;

    public SetSkipByCommentCharsAction(String name, String owner) {
        super(name, owner);
        logger = new Logger(this.getClass());
    }

    private String askForTimeout() {
        return TextAskDialog.open("Skip Functions By Comment Characters", "Set the comment character amount (0 to disable skipping by characters)", AskDialog.LONG, String.valueOf(GlobalSettings.getSkipByCommentChars()));
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        if (GlobalSettings.setSkipByCommentChars(askForTimeout())) {
            logger.ok("Updated the Skip Functions By Comment Size to : " + GlobalSettings.getSkipByCommentChars());
        } else {
            logger.ok("Skip Functions By Comment Size not updated");
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
