package ghidrachatgpt.openai;

import com.openai.client.OpenAIClient;
import com.openai.client.okhttp.OpenAIOkHttpClient;
import com.openai.models.responses.Response;
import com.openai.models.responses.ResponseCreateParams;
import com.openai.models.responses.ResponseRetrieveParams;
import com.openai.models.responses.ResponseStatus;
import ghidrachatgpt.config.GlobalSettings;
import ghidrachatgpt.log.Logger;

import java.time.Duration;

public class GPTClient {
    private final Logger logger;

    public GPTClient() {
        logger = new Logger(this.getClass());
    }

    public String sendOpenAIRequestAsync(String prompt, String instructions) {
        OpenAIClient client = OpenAIOkHttpClient.builder()
                .apiKey(GlobalSettings.getAccessToken())
                .checkJacksonVersionCompatibility(false)
                .build();
        return getResponseIdViaResponseApi(prompt, instructions, client);
    }

    private String getResponseIdViaResponseApi(String prompt, String instructions, OpenAIClient client) {
        ResponseCreateParams params = ResponseCreateParams.builder()
                .instructions(instructions)
                .input(prompt)
                .model(GlobalSettings.getOpenAiModel())
                .background(true)
                .build();

        logger.debug("Request: " + params);
        try {
            Response request = client.responses().create(params);
            String requestId = request.id();

            logger.debug("RequestId:" + requestId);
            return requestId;
        } catch (Exception e) {
            logger.error(String.format("Asking ChatGPT failed with the error %s", e));
            return null;
        }
    }

    public String checkAndGetOpenAIResponseAsync(String responseId) {
        OpenAIClient client = OpenAIOkHttpClient.builder()
                .apiKey(GlobalSettings.getAccessToken())
                .checkJacksonVersionCompatibility(false)
                .build();

        return checkAndGetResponseViaResponseApi(responseId, client);
    }

    private String checkAndGetResponseViaResponseApi(String responseId, OpenAIClient client) {
        ResponseRetrieveParams params = ResponseRetrieveParams.builder()
                .responseId(responseId)
                .build();

        logger.debug("Request: " + params);
        try {
            Response response = client.responses().retrieve(params);
            logger.debug("Response: " + response);

            var responseStatus = response.status().orElse(ResponseStatus.IN_PROGRESS);
            logger.debug("Response status: " + responseStatus.asString());
            if (!"completed".equals(responseStatus.asString())) {
                return null;
            }

            StringBuilder builder = new StringBuilder();
             response.output().stream()
                    .peek(x -> logger.debug("Got response part: " + x.toString()))
                    .flatMap(item -> item.message().stream())
                    .flatMap(message -> message.content().stream())
                    .flatMap(content -> content.outputText().stream())
                    .forEach(outputText -> builder.append(outputText.text()).append("\n"));

            String builtResponse = builder.toString();
            logger.debug("Built response: " + response);
            return builtResponse;
        } catch (Exception e) {
            logger.error(String.format("Asking ChatGPT failed with the error %s", e));
            return null;
        }
    }
}
