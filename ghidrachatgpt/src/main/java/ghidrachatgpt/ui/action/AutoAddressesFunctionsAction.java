package ghidrachatgpt.ui.action;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.openai.GPTService;
import ghidrachatgpt.ui.component.AddressRangeDialog;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import static ghidrachatgpt.ui.UIConstants.AUTO_MODE;
import static ghidrachatgpt.ui.UIConstants.ROOT_MENU_NAME;

public class AutoAddressesFunctionsAction extends DockingActionExtended {
    public static final String DESCRIPTION = "Analyze all functions in address range";
    private static final String MENU_NAME = "Analyze Functions in Address Range";
    private final GPTService gptService;
    String preStart = "";
    String preEnd   = "";


    public AutoAddressesFunctionsAction(String name, String owner) {
        super(name, owner);
        this.gptService = ComponentContainer.getGptService();
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        ProgramLocation programLocation = ComponentContainer.getCodeViewerService().getCurrentLocation();
        Program program = programLocation.getProgram();
        AddressRangeDialog dlg = new AddressRangeDialog(
                program,
                "Choose Address Range",
                preStart,
                preEnd,
                (start, end) -> {
                    preEnd = end.toString();
                    preStart = start.toString();
                    gptService.autoMode(start, end);
                    ComponentContainer.getComponentStateService().disableProcessingFunctions();
                    ComponentContainer.getComponentStateService().enableStopFunction();
                });

        ComponentContainer.getDockingTool().showDialog(dlg);
    }

    @Override
    public void setUp() {
        this.setDescription(DESCRIPTION);
        this.setMenuBarData(new MenuData(new String[]{
                ToolConstants.MENU_TOOLS, ROOT_MENU_NAME, AUTO_MODE, MENU_NAME}));
        ComponentContainer.getDockingTool().addAction(this);
    }
}
