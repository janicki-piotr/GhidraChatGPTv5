package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;

import static ghidrachatgpt.ui.UIConstants.*;

public class EnableAutoBeatifyAction extends ToggleDockingActionExtended {
    public static final String DESCRIPTION = "Enable beautify function during auto mode";
    private static final String MENU_NAME = "Enable Beautify Function";

    public EnableAutoBeatifyAction(String name, String owner) {
        super(name, owner);
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        GlobalSettings.setEnableBeautifyFunctionInAuto(isSelected());
    }

    @Override
    public void setUp() {
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(
                new MenuData(new String[]{
                        ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, AUTO_MODE, SETTINGS_MENU, SETTINGS_ENABLED_ANALYSIS, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
        this.setSelected(GlobalSettings.isEnableBeautifyFunctionInAuto());
    }
}
