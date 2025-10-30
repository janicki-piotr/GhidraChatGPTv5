package ghidrachatgpt.ui.action;

import docking.Tool;
import docking.action.DockingAction;

public abstract class DockingActionExtended extends DockingAction {
    public DockingActionExtended(String name, String owner) {
        super(name, owner);
    }

    public abstract void setUp();
}
