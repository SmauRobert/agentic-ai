use genai::Client;
use genai::chat::{ChatMessage, ChatOptions, ChatRequest, Tool, ToolResponse};
use serde_json::json;

// 1. Deterministic local Rust function
fn lookup_cve_details(cve_id: &str) -> String {
    match cve_id.to_uppercase().as_str() {
        "CVE-2024-3094" => json!({
            "cvss": 10.0,
            "affected": "xz-utils 5.6.0 and 5.6.1",
            "summary": "Malicious backdoor injected into liblzma build process hooking RSA_public_decrypt in sshd."
        }).to_string(),
        "CVE-2021-44228" => json!({
            "cvss": 10.0,
            "affected": "Apache Log4j2 2.0-beta9 to 2.14.1",
            "summary": "Unauthenticated remote code execution via JNDI lookup in logged messages (Log4Shell)."
        }).to_string(),
        _ => json!({ "error": format!("No record found for {cve_id}") }).to_string(),
    }
}

fn get_installed_packages(hostname: &str) -> String {
    match hostname.to_uppercase().as_str() {
        "DB-PROD-01" => json!(["openssh-sever 9.6", "xz-utils 5.6.1", "postgresql 16"]).to_string(),
        _ => json!({ "error": format!("No package list found for {hostname}") }).to_string(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let client = Client::default();

    // Step 1: Define the Tool schema for the LLM
    let cve_tool = Tool::new("lookup_cve_details")
        .with_description(
            "Look up the CVSS severity score and technical summary for a given CVE identifier.",
        )
        .with_schema(json!({
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "The official CVE string, e.g., 'CVE-2024-3094'"
                }
            },
            "required": ["cve_id"]
        }));

    let installed_packages_tool = Tool::new("get_installed_packages")
        .with_description(
            "Retrieve a list of installed packages and their versions for a given hostname.",
        )
        .with_schema(json!({
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "The hostname of the server to query."
                }
            },
            "required": ["hostname"]
        }));

    // let user_prompt = "What is CVE-2024-3094, what versions are affected, and how severe is it?";
    let bonus_prompt = "Compare CVE-2024-3094 and CVE-2021-44228, and check if host db-prod-01 is running either affected package";

    let mut chat_req = ChatRequest::new(vec![
        ChatMessage::system(
            // I force the LLM to only call 2 tools to check the loop works properly as the LLM could call all 3 at once.
            "You are a cybersecurity assistant. Always use tools to verify CVE data. You may only at most 2 tools at a time, never more.",
        ),
        ChatMessage::user(bonus_prompt),
    ])
    .append_tool(cve_tool)
    .append_tool(installed_packages_tool);

    let options = ChatOptions::default().with_temperature(0.0);

    // Step 2: Send initial request and inspect tool calls emitted by the model
    let chat_res = client
        .exec_chat("gemini-3.5-flash-lite", chat_req.clone(), Some(&options))
        .await?;
    let mut tool_calls = chat_res.into_tool_calls();

    let mut max_iterations = 5;
    while !tool_calls.is_empty() {
        let mut tool_responses = Vec::new();
        for call in &tool_calls {
            println!(
                "[LLM Requested Tool] Name: {} | Args: {}",
                call.fn_name, call.fn_arguments
            );

            let tool_output = match call.fn_name.as_str() {
                "lookup_cve_details" => {
                    let cve_id = call.fn_arguments["cve_id"].as_str().unwrap_or("");
                    lookup_cve_details(cve_id)
                }
                "get_installed_packages" => {
                    let hostname = call.fn_arguments["hostname"].as_str().unwrap_or("");
                    get_installed_packages(hostname)
                }
                _ => json!({ "error": "Unknown tool requested" }).to_string(),
            };

            tool_responses.push(ToolResponse::new(call.call_id.clone(), tool_output));
        }

        chat_req = chat_req
            .append_message(tool_calls)
            .append_message(tool_responses);

        let final_res = client
            .exec_chat("gemini-3.5-flash-lite", chat_req.clone(), Some(&options))
            .await?;
        println!(
            "[Final LLM Response] {}",
            final_res.first_text().unwrap_or("")
        );
        tool_calls = final_res.into_tool_calls();

        max_iterations = max_iterations - 1;
        if max_iterations == 0 {
            break;
        }
    }

    Ok(())
}
