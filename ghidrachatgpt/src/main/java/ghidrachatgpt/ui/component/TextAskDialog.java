package ghidrachatgpt.ui.component;

import ghidra.app.script.AskDialog;

public class TextAskDialog {
    public static String open(String dialogTitle, String message, int type, String defaultValue) {
        AskDialog<String> dialog = new AskDialog<>(dialogTitle, message, type, defaultValue);
        if (dialog.isCanceled()) {
            return null;
        }
        return dialog.getValueAsString();
    }
}
