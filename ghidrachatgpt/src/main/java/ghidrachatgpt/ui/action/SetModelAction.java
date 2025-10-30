package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;

import static ghidrachatgpt.ui.UIConstants.ROOT_MENU_NAME;
import static ghidrachatgpt.ui.UIConstants.SETTINGS_MENU;

public class SetModelAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Set GPT Model to:";
    private static final String MENU_NAME = "Model Category";
    private final String model;
    private final Logger logger;

    public SetModelAction(String name, String owner, String model) {
        super(name, owner);
        this.model = model;
        logger = new Logger(this.getClass());
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        GlobalSettings.setOpenAiModel(model);
        logger.ok(String.format("Updated model to %s", model));
    }

    @Override
    public void setUp() {
        this.setDescription(DESCRIPTION + model);
        this.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, SETTINGS_MENU, MENU_NAME, model}));

        ComponentContainer.getDockingTool().addAction(this);
    }
}
