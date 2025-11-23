package ghidrachatgpt.openai;

import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;

public final class GPTRequestLogger {

    private static final Logger LOGGER = new Logger(GPTRequestLogger.class);
    private static final String LOG_FILE_NAME = "requests.log";
    private static final Object FILE_LOCK = new Object();

    private GPTRequestLogger() {
    }

    public static void log(
            String prompt,
            String instructions,
            String response,
            String functionName,
            String functionBody
    ) {
        File dir = GlobalSettings.getPluginConfigDirectory();
        if (!dir.exists() && !dir.mkdirs()) {
            LOGGER.error("Unable to create plugin config directory for log: " + dir.getAbsolutePath());
            return;
        }

        File logFile = new File(dir, LOG_FILE_NAME);

        String json = buildJson(prompt, instructions, response, functionName, functionBody);

        synchronized (FILE_LOCK) {
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(logFile, true))) {
                writer.write(json);
                writer.newLine();
            } catch (IOException e) {
                LOGGER.error("Error while writing ChatGPT request log", e);
            }
        }
    }

    private static String buildJson(
            String prompt,
            String instructions,
            String response,
            String functionName,
            String functionBody
    ) {
        return "{" +
                "\"input\":\"" + escapeJson(prompt) + "\"," +
                "\"instructions\":\"" + escapeJson(instructions) + "\"," +
                "\"response\":\"" + escapeJson(response) + "\"," +
                "\"functionName\":\"" + escapeJson(functionName) + "\"," +
                "\"function\":\"" + escapeJson(functionBody) + "\"," +
                "\"creationDate\":\"" + escapeJson(LocalDateTime.now().toString()) + "\"" +
                "},";
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
