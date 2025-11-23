package ghidrachatgpt.config;

import ghidra.framework.Application;
import ghidrachatgpt.log.LogType;
import ghidrachatgpt.log.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;

public final class GlobalSettings {
    private final static Logger LOGGER = new Logger(GlobalSettings.class);

    private static final String CONFIG_DIR_NAME = "ghidrachatgptcfg";
    private static final String CONFIG_FILE_NAME = "settings.properties";
    private static final Object FILE_LOCK = new Object();

    private static volatile String accessToken = "";
    private static volatile String openAiModel = "gpt-5-pro";
    private static volatile String instructions = """
            You are an assistant helping out with reverse engineering and vulnerability research.\s
            """;
    private static volatile boolean attachCCode = true;
    private static volatile boolean attachAsmCode = true;

    private static volatile long requestTimeout = 1800;

    private static volatile boolean skipProcessed = false;
    private static volatile Long skipByCommentChars = 200L;
    private static volatile Long limitFunctions = 0L;
    private static volatile boolean enableIdentifyFunctionInAuto = true;
    private static volatile boolean enableBeautifyFunctionInAuto = false;
    private static volatile boolean enableFindVulnerabilitiesInAuto = false;
    private static volatile boolean autoModeIncludeExternals = true;
    private static volatile boolean autoModeIncludeThunks = true;
    private static volatile short autoModeThreads = 3;

    public static String getAccessToken() {
        return accessToken;
    }

    public static boolean setAccessToken(String accessToken) {
        if (accessToken == null || accessToken.isEmpty()) {
            return false;
        }
        GlobalSettings.accessToken = accessToken;
        return true;
    }

    public static String getOpenAiModel() {
        return openAiModel;
    }

    public static void setOpenAiModel(String openAiModel) {
        GlobalSettings.openAiModel = openAiModel;
        persist();
    }

    public static String getInstructions() {
        return instructions;
    }

    public static boolean setInstructions(String instructions) {
        if (instructions == null) {
            return false;
        } else if (instructions.isEmpty()) {
            GlobalSettings.instructions = null;
            persist();
            return true;
        } else {
            GlobalSettings.instructions = instructions;
            persist();
            return true;
        }
    }

    public static boolean isAttachCCode() {
        return attachCCode;
    }

    public static void setAttachCCode(boolean attachCCode) {
        GlobalSettings.attachCCode = attachCCode;
        persist();
    }

    public static boolean isAttachAsmCode() {
        return attachAsmCode;
    }

    public static void setAttachAsmCode(boolean attachAsmCode) {
        GlobalSettings.attachAsmCode = attachAsmCode;
        persist();
    }

    public static long getRequestTimeout() {
        return requestTimeout;
    }

    public static boolean setRequestTimeout(String requestTimeout) {
        if (requestTimeout == null || requestTimeout.isEmpty()) {
            return false;
        }
        try {
            GlobalSettings.requestTimeout = Long.parseLong(requestTimeout);
            persist();
        } catch (Exception exception) {
            LOGGER.error("Error during setting request timeout", exception);
            return false;
        }
        return true;
    }

    public static boolean isSkipProcessed() {
        return skipProcessed;
    }

    public static void setSkipProcessed(boolean skipProcessed) {
        GlobalSettings.skipProcessed = skipProcessed;
        persist();
    }

    public static Long getLimitFunctions() {
        return limitFunctions;
    }

    public static boolean setLimitFunctions(String limitFunctions) {
        if (limitFunctions == null || limitFunctions.isEmpty()) {
            return false;
        }
        try {
            GlobalSettings.limitFunctions = Long.parseLong(limitFunctions);
            persist();
        } catch (Exception exception) {
            LOGGER.error("Error during setting limit functions", exception);
            return false;
        }
        return true;
    }

    public static boolean isEnableIdentifyFunctionInAuto() {
        return enableIdentifyFunctionInAuto;
    }

    public static void setEnableIdentifyFunctionInAuto(boolean enableIdentifyFunctionInAuto) {
        GlobalSettings.enableIdentifyFunctionInAuto = enableIdentifyFunctionInAuto;
        persist();
    }

    public static boolean isEnableBeautifyFunctionInAuto() {
        return enableBeautifyFunctionInAuto;
    }

    public static void setEnableBeautifyFunctionInAuto(boolean enableBeautifyFunctionInAuto) {
        GlobalSettings.enableBeautifyFunctionInAuto = enableBeautifyFunctionInAuto;
        persist();
    }

    public static boolean isEnableFindVulnerabilitiesInAuto() {
        return enableFindVulnerabilitiesInAuto;
    }

    public static void setEnableFindVulnerabilitiesInAuto(boolean enableFindVulnerabilitiesInAuto) {
        GlobalSettings.enableFindVulnerabilitiesInAuto = enableFindVulnerabilitiesInAuto;
        persist();
    }

    public static boolean isAutoModeIncludeExternals() {
        return autoModeIncludeExternals;
    }

    public static void setAutoModeIncludeExternals(boolean autoModeIncludeExternals) {
        GlobalSettings.autoModeIncludeExternals = autoModeIncludeExternals;
        persist();
    }

    public static boolean isAutoModeIncludeThunks() {
        return autoModeIncludeThunks;
    }

    public static void setAutoModeIncludeThunks(boolean autoModeIncludeThunks) {
        GlobalSettings.autoModeIncludeThunks = autoModeIncludeThunks;
        persist();
    }

    public static Long getSkipByCommentChars() {
        return skipByCommentChars;
    }

    public static boolean setSkipByCommentChars(String skipByCommentChars) {
        if (skipByCommentChars == null || skipByCommentChars.isEmpty()) {
            return false;
        }
        try {
            GlobalSettings.skipByCommentChars = Long.parseLong(skipByCommentChars);
            persist();
        } catch (Exception exception) {
            LOGGER.error("Error during setting skipping by character amount in comment", exception);
            return false;
        }
        return true;
    }

    public static short getAutoModeThreads() {
        return autoModeThreads;
    }

    public static boolean setAutoModeThreads(String autoModeThreads) {
        if (autoModeThreads == null || autoModeThreads.isEmpty()) {
            return false;
        }
        try {
            GlobalSettings.autoModeThreads = Short.parseShort(autoModeThreads);
            persist();
        } catch (Exception exception) {
            LOGGER.error("Error during setting thread amount", exception);
            return false;
        }
        return true;
    }

    public static void loadFromDisk() {
        synchronized (FILE_LOCK) {
            File configFile = getConfigFile();
            if (!configFile.exists()) {
                persist();
                return;
            }

            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(configFile)) {
                props.load(fis);
            } catch (IOException e) {
                LOGGER.error("Error while loading settings from file", e);
                return;
            }

            String value;
            value = props.getProperty("openAiModel");
            if (value != null && !value.isEmpty()) {
                openAiModel = value;
            }

            value = props.getProperty("instructions");
            if (value != null) {
                instructions = value.isEmpty() ? null : value;
            }

            value = props.getProperty("attachCCode");
            if (value != null) {
                attachCCode = Boolean.parseBoolean(value);
            }

            value = props.getProperty("attachAsmCode");
            if (value != null) {
                attachAsmCode = Boolean.parseBoolean(value);
            }

            value = props.getProperty("requestTimeout");
            if (value != null) {
                try {
                    requestTimeout = Long.parseLong(value);
                } catch (NumberFormatException ignored) {
                }
            }

            value = props.getProperty("skipProcessed");
            if (value != null) {
                skipProcessed = Boolean.parseBoolean(value);
            }

            value = props.getProperty("skipByCommentChars");
            if (value != null) {
                try {
                    skipByCommentChars = Long.parseLong(value);
                } catch (NumberFormatException ignored) {
                }
            }

            value = props.getProperty("limitFunctions");
            if (value != null) {
                try {
                    limitFunctions = Long.parseLong(value);
                } catch (NumberFormatException ignored) {
                }
            }

            value = props.getProperty("enableIdentifyFunctionInAuto");
            if (value != null) {
                enableIdentifyFunctionInAuto = Boolean.parseBoolean(value);
            }

            value = props.getProperty("enableBeautifyFunctionInAuto");
            if (value != null) {
                enableBeautifyFunctionInAuto = Boolean.parseBoolean(value);
            }

            value = props.getProperty("enableFindVulnerabilitiesInAuto");
            if (value != null) {
                enableFindVulnerabilitiesInAuto = Boolean.parseBoolean(value);
            }

            value = props.getProperty("autoModeIncludeExternals");
            if (value != null) {
                autoModeIncludeExternals = Boolean.parseBoolean(value);
            }

            value = props.getProperty("autoModeIncludeThunks");
            if (value != null) {
                autoModeIncludeThunks = Boolean.parseBoolean(value);
            }

            value = props.getProperty("autoModeThreads");
            if (value != null) {
                try {
                    autoModeThreads = Short.parseShort(value);
                } catch (NumberFormatException ignored) {
                }
            }

            value = props.getProperty("loggerLevel");
            if (value != null) {
                try {
                    Logger.setLevel(LogType.valueOf(value));
                } catch (NumberFormatException ignored) {
                }
            }
        }
    }

    public static void persist() {
        synchronized (FILE_LOCK) {
            File configFile = getConfigFile();
            File parent = configFile.getParentFile();
            if (!parent.exists() && !parent.mkdirs()) {
                LOGGER.error("Unable to create settings directory: " + parent.getAbsolutePath());
                return;
            }

            Properties props = new Properties();

            props.setProperty("openAiModel", openAiModel != null ? openAiModel : "");
            props.setProperty("instructions", instructions != null ? instructions : "");
            props.setProperty("attachCCode", Boolean.toString(attachCCode));
            props.setProperty("attachAsmCode", Boolean.toString(attachAsmCode));
            props.setProperty("requestTimeout", Long.toString(requestTimeout));
            props.setProperty("skipProcessed", Boolean.toString(skipProcessed));
            props.setProperty("skipByCommentChars", skipByCommentChars != null ? skipByCommentChars.toString() : "0");
            props.setProperty("limitFunctions", limitFunctions != null ? limitFunctions.toString() : "0");
            props.setProperty("enableIdentifyFunctionInAuto", Boolean.toString(enableIdentifyFunctionInAuto));
            props.setProperty("enableBeautifyFunctionInAuto", Boolean.toString(enableBeautifyFunctionInAuto));
            props.setProperty("enableFindVulnerabilitiesInAuto", Boolean.toString(enableFindVulnerabilitiesInAuto));
            props.setProperty("autoModeIncludeExternals", Boolean.toString(autoModeIncludeExternals));
            props.setProperty("autoModeIncludeThunks", Boolean.toString(autoModeIncludeThunks));
            props.setProperty("autoModeThreads", Short.toString(autoModeThreads));
            props.setProperty("loggerLevel", Logger.getLogType().toString());

            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                props.store(fos, "ghidrachatgpt plugin settings");
            } catch (IOException e) {
                LOGGER.error("Error while saving settings to file", e);
            }
        }
    }

    private static File getConfigFile() {
        File userSettingsDir = Application.getUserSettingsDirectory();
        File pluginDir = new File(userSettingsDir, CONFIG_DIR_NAME);
        return new File(pluginDir, CONFIG_FILE_NAME);
    }

    public static File getPluginConfigDirectory() {
        File userSettingsDir = Application.getUserSettingsDirectory();
        return new File(userSettingsDir, CONFIG_DIR_NAME);
    }
}
