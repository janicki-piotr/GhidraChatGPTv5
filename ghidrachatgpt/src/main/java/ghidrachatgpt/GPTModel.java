package ghidrachatgpt;


import com.openai.models.AllModels;
import com.openai.models.ChatModel;

import java.util.Arrays;
import java.util.Optional;

public enum GPTModel  {
    GPT_5("gpt-5", ChatModel.GPT_5),
    GPT_5_MINI("gpt-5-mini", ChatModel.GPT_5_MINI),
    GPT_4_TURBO("gpt-4-turbo", ChatModel.GPT_4_TURBO),
    GPT_4O("gpt-4o", ChatModel.GPT_4O),
    GPT_4O_MINI("gpt-4o-mini", ChatModel.GPT_4O_MINI),
    GPT_3_5_TURBO("gpt-3.5-turbo", ChatModel.GPT_3_5_TURBO);

    private final String name;
    private final ChatModel model;

    GPTModel(String name, ChatModel model) {
        this.name = name;
        this.model = model;
    }

    public ChatModel getModel() {
        return model;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }

    public static Optional<ChatModel> getModelByName(String modelName) {
        return Arrays.stream(values())
                .filter(model -> model.name.equalsIgnoreCase(modelName))
                .findFirst().map(model -> model.model);
    }
}
