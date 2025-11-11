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

public class EnableAutoIdentifyAction extends ToggleDockingActionExtended {
    public static final String DESCRIPTION = "Enable identify function during auto mode";
    private static final String MENU_NAME = "Enable Identify Function";

    public EnableAutoIdentifyAction(String name, String owner) {
        super(name, owner);
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        GlobalSettings.setEnableIdentifyFunctionInAuto(isSelected());
    }

    @Override
    public void setUp() {
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(
                new MenuData(new String[]{
                        ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, AUTO_MODE, SETTINGS_MENU, SETTINGS_ENABLED_ANALYSIS, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
        this.setSelected(GlobalSettings.isEnableIdentifyFunctionInAuto());
    }
}
