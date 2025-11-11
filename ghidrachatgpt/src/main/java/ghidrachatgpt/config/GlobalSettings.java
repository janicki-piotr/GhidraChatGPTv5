package ghidrachatgpt.config;

import ghidrachatgpt.log.Logger;

public final class GlobalSettings {
    private final static Logger LOGGER = new Logger(GlobalSettings.class);

    private static String accessToken = "";
    private static String openAiModel = "gpt-5-pro";
    private static String instructions = """
            You are an assistant helping out with reverse engineering and vulnerability research.\s
            """;
    private static boolean attachCCode = true;
    private static boolean attachAsmCode = true;

    private static long requestTimeout = 1800;

    private static boolean skipProcessed = true;
    private static Long limitFunctions = 0L;
    private static boolean enableIdentifyFunctionInAuto = true;
    private static boolean enableBeautifyFunctionInAuto = false;
    private static boolean enableFindVulnerabilitiesInAuto = false;
    private static boolean autoModeIncludeExternals = true;
    private static boolean autoModeIncludeThunks = true;

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
            LOGGER.error("Error during setting request timeout",exception);
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
            LOGGER.error("Error during setting limit functions",exception);
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
}
