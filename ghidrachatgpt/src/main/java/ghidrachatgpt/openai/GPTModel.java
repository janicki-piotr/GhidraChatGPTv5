package ghidrachatgpt.openai;



public enum GPTModel  {
    GPT_5_1_PRO("gpt-5.1-pro"),
    GPT_5_1("gpt-5.1"),
    GPT_5_PRO("gpt-5-pro"),
    GPT_5("gpt-5"),
    GPT_5_MINI("gpt-5-mini"),
    GPT_4_PRO("gpt-4-pro"),
    GPT_4_TURBO("gpt-4-turbo"),
    GPT_4O("gpt-4o"),
    GPT_4O_MINI("gpt-4o-mini"),
    GPT_3_5_TURBO("gpt-3.5-turbo");

    private final String name;

    GPTModel(String name) {
        this.name = name;
    }


    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }
}
