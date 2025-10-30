package ghidrachatgpt.openai;


import java.util.Arrays;
import java.util.Optional;

public enum GPTModel  {
    GPT_5_PRO("gpt-5-pro", false),
    GPT_5("gpt-5", true),
    GPT_5_MINI("gpt-5-mini", true),
    GPT_4_PRO("gpt-4-pro", false),
    GPT_4_TURBO("gpt-4-turbo", true),
    GPT_4O("gpt-4o", true),
    GPT_4O_MINI("gpt-4o-mini", true),
    GPT_3_5_TURBO("gpt-3.5-turbo", true);

    private final String name;
    private final boolean isChatModel;

    GPTModel(String name, boolean isChatModel) {
        this.name = name;
        this.isChatModel = isChatModel;
    }

    public boolean isChatModel() {
        return isChatModel;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }

    public static Optional<Boolean> isChatModel(String modelName) {
        return Arrays.stream(values())
                .filter(model -> model.name.equalsIgnoreCase(modelName))
                .findFirst().map(model -> model.isChatModel);
    }
}
