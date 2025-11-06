package ghidrachatgpt.config;

public class PromptConstraints {
    private static String GCG_IDENTIFY_STRING =
            "Describe the function with as much detail as possible and include a link to an open source version if there is one\n %s";
    private static String GCG_VULNERABILITY_STRING =
            "Describe all vulnerabilities in this function with as much detail as possible\n %s";
    private static String GCG_BEAUTIFY_STRING =
            "Analyze the decompiled C function and suggest function and variable names in a json format where the key is the previous name and the value is the suggested name\n %s";

    public static String getGcgIdentifyString() {
        return GCG_IDENTIFY_STRING;
    }

    public static void setGcgIdentifyString(String gcgIdentifyString) {
        GCG_IDENTIFY_STRING = gcgIdentifyString;
    }

    public static String getGcgVulnerabilityString() {
        return GCG_VULNERABILITY_STRING;
    }

    public static void setGcgVulnerabilityString(String gcgVulnerabilityString) {
        GCG_VULNERABILITY_STRING = gcgVulnerabilityString;
    }

    public static String getGcgBeautifyString() {
        return GCG_BEAUTIFY_STRING;
    }

    public static void setGcgBeautifyString(String gcgBeautifyString) {
        GCG_BEAUTIFY_STRING = gcgBeautifyString;
    }
}
