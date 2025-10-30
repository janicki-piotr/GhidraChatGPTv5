package ghidrachatgpt.log;

import java.util.Arrays;
import java.util.Optional;

public enum LogType {
    DEBUG(10, "DEBUG"),
    INFO(20, "INFO"),
    OK(30, "OK"),
    ERROR(40, "ERROR");

    private final int severity;
    private final String label;

    LogType(int severity, String label) {
        this.severity = severity;
        this.label = label;
    }

    public int severity() {
        return severity;
    }

    public String label() {
        return label;
    }

    public static Optional<LogType> getLogType(String name) {
        return Arrays.stream(values())
                .filter(logType -> logType.label.equalsIgnoreCase(name))
                .findFirst();
    }
}
