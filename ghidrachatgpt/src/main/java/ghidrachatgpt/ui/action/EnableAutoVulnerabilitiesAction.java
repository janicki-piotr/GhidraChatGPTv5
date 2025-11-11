package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;

import static ghidrachatgpt.ui.UIConstants.*;

public class EnableAutoVulnerabilitiesAction extends ToggleDockingActionExtended {
    public static final String DESCRIPTION = "Enable find vulnerabilities during auto mode";
    private static final String MENU_NAME = "Enable Find Vulnerabilities";

    public EnableAutoVulnerabilitiesAction(String name, String owner) {
        super(name, owner);
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        GlobalSettings.setEnableFindVulnerabilitiesInAuto(isSelected());
    }

    @Override
    public void setUp() {
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(
                new MenuData(new String[]{
                        ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, AUTO_MODE, SETTINGS_MENU, SETTINGS_ENABLED_ANALYSIS, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
        this.setSelected(GlobalSettings.isEnableFindVulnerabilitiesInAuto());
    }
}
