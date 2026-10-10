use async_openai::{
    Client,
    config::OpenAIConfig,
    types::{
        ChatCompletionRequestSystemMessageArgs, ChatCompletionRequestUserMessageArgs,
        CreateChatCompletionRequestArgs,
    },
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OpenAIConfig::new()
        .with_api_base("http://localhost:11434/v1")
        .with_api_key("ollama");

    let client = Client::with_config(config);

    let request = CreateChatCompletionRequestArgs::default()
        .model("qwen2.5:1.5b")
        .temperature(0.2_f32)
        .messages([
            ChatCompletionRequestSystemMessageArgs::default()
                .content("You are a precise technical tutor. Respond in 2 sentences maximum.")
                .build()?
                .into(),
            ChatCompletionRequestUserMessageArgs::default()
                .content("What is the primary difference between a process and a thread?")
                .build()?
                .into(),
        ])
        .build()?;

    let response = client.chat().create(request).await?;

    if let Some(choice) = response.choices.first() {
        if let Some(content) = &choice.message.content {
            println!("Model Output:\n\n{}", content)
        }
    }

    if let Some(usage) = response.usage {
        println!("\n---");
        println!(
            "Usage: {} prompt tokens, {} completion tokens.",
            usage.prompt_tokens, usage.completion_tokens
        );
    }

    return Ok(());
}
