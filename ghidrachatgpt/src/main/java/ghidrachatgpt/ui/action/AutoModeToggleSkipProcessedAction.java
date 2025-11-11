package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;

import static ghidrachatgpt.ui.UIConstants.*;

public class AutoModeToggleSkipProcessedAction extends ToggleDockingActionExtended {
    public static final String DESCRIPTION = "Enable skipping processed function";
    private static final String MENU_NAME = "Skip Processed Functions";

    public AutoModeToggleSkipProcessedAction(String name, String owner) {
        super(name, owner);
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        GlobalSettings.setSkipProcessed(isSelected());
    }

    @Override
    public void setUp() {
        this.setSelected(GlobalSettings.isAttachAsmCode());
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, AUTO_MODE, SETTINGS_MENU, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
