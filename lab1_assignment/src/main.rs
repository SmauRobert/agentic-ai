use async_openai::{
    Client,
    config::OpenAIConfig,
    types::{
        ChatCompletionRequestAssistantMessageArgs, ChatCompletionRequestSystemMessageArgs,
        ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
    },
};
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OpenAIConfig::new()
        .with_api_base("http://localhost:11434/v1")
        .with_api_key("ollama");

    let client = Client::with_config(config);
    let mut messages = Vec::from([
        ChatCompletionRequestSystemMessageArgs::default().content("You are a university proffesor proficient in Neural Networks and Deep Learning. You answer shortly and offer topics for further study.").build()?.into(),
    ]);

    println!("Welcome to this chatbot. To exit the session please use '\\q'");

    loop {
        print!("User: ");
        io::stdout().flush().unwrap();
        let mut raw = String::new();
        let byte_count = io::stdin().read_line(&mut raw)?;

        if byte_count == 0 || raw.trim() == "\\q" {
            break;
        }

        let current_message = raw.trim();

        messages.push(
            ChatCompletionRequestUserMessageArgs::default()
                .content(current_message)
                .build()?
                .into(),
        );

        let request = CreateChatCompletionRequestArgs::default()
            .model("qwen2.5:1.5b")
            .temperature(0.2_f32)
            .messages(messages.clone())
            .build()?;

        let response = client.chat().create(request).await?;

        if let Some(choice) = response.choices.first() {
            if let Some(content) = &choice.message.content {
                messages.push(
                    ChatCompletionRequestAssistantMessageArgs::default()
                        .content(content.clone())
                        .build()?
                        .into(),
                );
                println!("Assistant: {}", content);
            }
        }
    }
    return Ok(());
}
