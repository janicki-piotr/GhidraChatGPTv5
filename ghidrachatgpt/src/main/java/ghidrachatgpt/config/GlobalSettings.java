package ghidrachatgpt.config;

import ghidrachatgpt.log.Logger;

public final class GlobalSettings {
    private final static Logger LOGGER = new Logger(GlobalSettings.class);

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
    }

    public static String getInstructions() {
        return instructions;
    }

    public static boolean setInstructions(String instructions) {
        if (instructions == null) {
            return false;
        } else if (instructions.isEmpty()) {
            instructions = null;
            return true;
        } else {
            GlobalSettings.instructions = instructions;
            return true;
        }
    }

    public static boolean isAttachCCode() {
        return attachCCode;
    }

    public static void setAttachCCode(boolean attachCCode) {
        GlobalSettings.attachCCode = attachCCode;
    }

    public static boolean isAttachAsmCode() {
        return attachAsmCode;
    }

    public static void setAttachAsmCode(boolean attachAsmCode) {
        GlobalSettings.attachAsmCode = attachAsmCode;
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
    }

    public static boolean isEnableBeautifyFunctionInAuto() {
        return enableBeautifyFunctionInAuto;
    }

    public static void setEnableBeautifyFunctionInAuto(boolean enableBeautifyFunctionInAuto) {
        GlobalSettings.enableBeautifyFunctionInAuto = enableBeautifyFunctionInAuto;
    }

    public static boolean isEnableFindVulnerabilitiesInAuto() {
        return enableFindVulnerabilitiesInAuto;
    }

    public static void setEnableFindVulnerabilitiesInAuto(boolean enableFindVulnerabilitiesInAuto) {
        GlobalSettings.enableFindVulnerabilitiesInAuto = enableFindVulnerabilitiesInAuto;
    }

    public static boolean isAutoModeIncludeExternals() {
        return autoModeIncludeExternals;
    }

    public static void setAutoModeIncludeExternals(boolean autoModeIncludeExternals) {
        GlobalSettings.autoModeIncludeExternals = autoModeIncludeExternals;
    }

    public static boolean isAutoModeIncludeThunks() {
        return autoModeIncludeThunks;
    }

    public static void setAutoModeIncludeThunks(boolean autoModeIncludeThunks) {
        GlobalSettings.autoModeIncludeThunks = autoModeIncludeThunks;
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
        } catch (Exception exception) {
            LOGGER.error("Error during setting thread amount", exception);
            return false;
        }
        return true;
    }
}
