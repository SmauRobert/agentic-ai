use genai::Client;
use genai::chat::{ChatMessage, ChatRequest};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env file into the process environment
    dotenvy::dotenv().ok();
    assert!(
        env::var("GEMINI_API_KEY").is_ok(),
        "ERROR: GEMINI_API_KEY not found. Check your .env file!"
    );

    // Client::default() automatically picks up GEMINI_API_KEY for gemini-* models
    let client = Client::default();

    let chat_req = ChatRequest::new(vec![ChatMessage::user(
        "Reply with the exact phrase: 'Telemetry online.'",
    )]);

    let chat_res = client
        .exec_chat("gemini-3.5-flash-lite", chat_req, None)
        .await?;
    println!("{}", chat_res.first_text().unwrap_or("No response"));

    Ok(())
}
