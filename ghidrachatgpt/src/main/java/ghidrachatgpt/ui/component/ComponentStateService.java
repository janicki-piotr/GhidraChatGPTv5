package ghidrachatgpt.ui.component;

import docking.action.DockingAction;

import java.util.List;

public class ComponentStateService {
    private final List<DockingAction> processingFunctions;
    private final DockingAction stopFunction;

    public ComponentStateService(List<DockingAction> processingFunctions, DockingAction stopFunction) {
        this.processingFunctions = processingFunctions;
        this.stopFunction = stopFunction;
    }

    public void disableProcessingFunctions() {
        processingFunctions.forEach(x -> x.setEnabled(false));
    }

    public void enableProcessingFunctions() {
        processingFunctions.forEach(x -> x.setEnabled(true));
    }

    public void disableStopFunction() {
        stopFunction.setEnabled(false);
    }

    public void enableStopFunction() {
        stopFunction.setEnabled(true);
    }
}
