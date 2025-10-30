package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.log.LogType;
import ghidrachatgpt.log.Logger;

import static ghidrachatgpt.ui.UIConstants.ROOT_MENU_NAME;
import static ghidrachatgpt.ui.UIConstants.SETTINGS_MENU;

public class SetLogLevelAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Set Log Level to:";
    private static final String MENU_NAME = "Log Level";
    private final String logLevel;
    private final Logger logger;

    public SetLogLevelAction(String name, String owner, String logLevel) {
        super(name, owner);
        this.logLevel = logLevel;
        logger = new Logger(this.getClass());
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        Logger.setLevel(LogType.getLogType(logLevel).get());
        logger.ok(String.format("Updated log level to %s", logLevel));
    }

    @Override
    public void setUp() {
        this.setDescription(DESCRIPTION + logLevel);
        this.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, SETTINGS_MENU, MENU_NAME, logLevel}));

        ComponentContainer.getDockingTool().addAction(this);
    }
}
