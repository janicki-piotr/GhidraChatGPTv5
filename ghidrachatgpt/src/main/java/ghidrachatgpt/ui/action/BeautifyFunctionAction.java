package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.openai.GPTService;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import static ghidrachatgpt.ui.UIConstants.ROOT_MENU_NAME;

public class BeautifyFunctionAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Beautify the function with the help of ChatGPT";
    private static final String MENU_NAME = "Beautify Function";
    private final GPTService gptService;

    public BeautifyFunctionAction(String name, String owner) {
        super(name, owner);
        this.gptService = ComponentContainer.getGptService();
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        new Thread(gptService::beautifyFunction).start();
    }

    @Override
    public void setUp() {
        this.setEnabled(true);
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, MENU_NAME}));
        this.setKeyBindingData(new KeyBindingData(
                KeyEvent.VK_B, InputEvent.SHIFT_DOWN_MASK | InputEvent.ALT_DOWN_MASK |
                InputEvent.CTRL_DOWN_MASK));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
