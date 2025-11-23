package ghidrachatgpt.log;

import ghidra.app.services.ConsoleService;
import ghidrachatgpt.config.ComponentContainer;
import ghidrachatgpt.config.GlobalSettings;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.function.Supplier;

public final class Logger {
    private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

    private final String loggerName;
    private static volatile LogType level = LogType.INFO;


    public Logger(Class<?> owner) {
        this.loggerName = owner.getSimpleName();
    }

    public static void setLevel(LogType level) {
        if (level == null) {
            throw new IllegalArgumentException("level cannot be null");
        }
        Logger.level = level;
        GlobalSettings.persist();
    }

    public static LogType getLogType() {
        return Logger.level;
    }

    public LogType getLevel() {
        return level;
    }

    public void log(LogType type, String message) {
        if (disableLog(type)) {
            return;
        }
        ConsoleService consoleService = ComponentContainer.getConsoleService();
        if(consoleService == null) {
            return;
        }
        consoleService.println(formatLine(type, message));
    }

    public void log(LogType type, String format, Object... args) {
        log(type, String.format(format, args));
    }

    public void log(LogType type, Supplier<String> messageSupplier) {
        log(type, messageSupplier.get());
    }

    public void debug(String msg) {
        log(LogType.DEBUG, msg);
    }

    public void debug(String fmt, Object... a) {
        log(LogType.DEBUG, fmt, a);
    }

    public void debug(Supplier<String> s) {
        log(LogType.DEBUG, s);
    }

    public void info(String msg) {
        log(LogType.INFO, msg);
    }

    public void info(String fmt, Object... a) {
        log(LogType.INFO, fmt, a);
    }

    public void ok(String msg) {
        log(LogType.OK, msg);
    }

    public void ok(String fmt, Object... a) {
        log(LogType.OK, fmt, a);
    }

    public void error(String msg) {
        log(LogType.ERROR, msg);
    }

    public void error(String fmt, Object... a) {
        log(LogType.ERROR, fmt, a);
    }

    private boolean disableLog(LogType type) {
        return type.severity() < level.severity();
    }

    private String formatLine(LogType type, String message) {
        String ts = LocalTime.now().format(TS);
        String lvl = padRight(type.label(), 5);
        return ts + "[GCGPT] [" + loggerName + "] " + lvl + " " + message;
    }
    private static String padRight(String s, int width) {
        if (s.length() >= width) {
            return s;
        }
        StringBuilder sb = new StringBuilder(width).append(s);
        while (sb.length() < width) {
            sb.append(' ');
        }
        return sb.toString();
    }
}
