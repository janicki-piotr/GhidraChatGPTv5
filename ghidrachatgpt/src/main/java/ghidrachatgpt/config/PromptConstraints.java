package ghidrachatgpt.config;

public class PromptConstraints {
    private static String GCG_IDENTIFY_STRING =
            "Describe the function with as much detail as possible and include a link to an open source version if there is one. Always prepare a likely C signature and struct layout\n %s";
    private static String GCG_VULNERABILITY_STRING =
            "Describe all vulnerabilities in this function with as much detail as possible\n %s";
    private static String GCG_BEAUTIFY_STRING =
            "Analyze the decompiled C function and output ONLY valid JSON of the form \"types\": { \"old_variable_or_param_name\": \"new_type\", ... }, {\"names\": {\"old\": \"new\", ...}, \"returnType\": \"C_type\"}. The \"names\" object maps old identifiers to suggested names (add here all you can: function name, function parameters and all local variables). The \"types\" should map variable types to better, more suitable (both for function parameters and local variables). Set \"returnType\" to the function's return type, and OMIT the \"returnType\" field if the function returns void\n %s";

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
