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

public class UpdateTokenAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Update the current OpenAI API Token";
    private static final String MENU_NAME = "Update OpenAI Token";
    private final Logger logger;

    public UpdateTokenAction(String name, String owner) {
        super(name, owner);
        logger = new Logger(this.getClass());
    }

    private String askForOpenAIToken() {
        return TextAskDialog.open("OpenAI API token configuration", "Enter OpenAI API Token:", AskDialog.STRING, censorToken(GlobalSettings.getAccessToken()));
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        if(GlobalSettings.setAccessToken(askForOpenAIToken())) {
            logger.ok("Updated the access token to: " + censorToken(GlobalSettings.getAccessToken()) );
        } else {
            logger.ok("Token not updated" );
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

    public static String censorToken(String token) {
        if (token == null || token.isEmpty()) {
            return token;
        }
        return token.substring(0, 2) +
                "*".repeat(Math.max(0, token.length() - 2));
    }
}
