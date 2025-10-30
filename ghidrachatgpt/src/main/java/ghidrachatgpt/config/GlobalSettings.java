package ghidrachatgpt.config;

public final class GlobalSettings {
    private static String accessToken = "";
    private static String openAiModel = "gpt-5";
    private static String instructions = """
            You are an assistant helping out with reverse engineering and vulnerability research.\s
            """;

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
}
