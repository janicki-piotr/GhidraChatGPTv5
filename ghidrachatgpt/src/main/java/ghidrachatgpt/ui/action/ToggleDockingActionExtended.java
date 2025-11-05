package ghidrachatgpt.ui.action;

import docking.action.DockingAction;
import docking.action.ToggleDockingAction;

public abstract class ToggleDockingActionExtended extends ToggleDockingAction {
    public ToggleDockingActionExtended(String name, String owner) {
        super(name, owner);
    }

    public abstract void setUp();
}
