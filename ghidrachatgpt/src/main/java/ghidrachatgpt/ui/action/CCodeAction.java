package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;

import static ghidrachatgpt.ui.UIConstants.*;

public class CCodeAction extends ToggleDockingActionExtended {
    public static final String DESCRIPTION = "Attach decompiled C Code to the prompt";
    private static final String MENU_NAME = "Attach C Code";

    public CCodeAction(String name, String owner) {
        super(name, owner);
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        GlobalSettings.setAttachCCode(isSelected());
    }

    @Override
    public void setUp() {
        this.setSelected(GlobalSettings.isAttachCCode());
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, SETTINGS_MENU, SETTINGS_PROMPT_MENU,MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
