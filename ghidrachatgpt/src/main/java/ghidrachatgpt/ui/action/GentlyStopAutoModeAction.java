package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.openai.GPTService;

import static ghidrachatgpt.ui.UIConstants.AUTO_MODE;
import static ghidrachatgpt.ui.UIConstants.ROOT_MENU_NAME;

public class GentlyStopAutoModeAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Gently stop the auto mode";
    private static final String MENU_NAME = "Stop Analysis";
    private final GPTService gptService;

    public GentlyStopAutoModeAction(String name, String owner) {
        super(name, owner);
        this.gptService = ComponentContainer.getGptService();
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        new Thread(gptService::stop).start();
    }

    @Override
    public void setUp() {
        this.setDescription(DESCRIPTION);
        this.setEnabled(false);
        this.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
