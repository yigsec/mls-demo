use clap::{Parser, Subcommand};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use tracing::error;
use uuid::Uuid;

mod types;

mod client_persistence;
mod mls_client;

use mls_client::MlsClient;

#[derive(Parser)]
#[clap(name = "openmls-client")]
#[clap(about = "OpenMLS Client CLI")]
struct Cli {
    #[clap(subcommand)]
    command: Option<Commands>,

    #[clap(long, default_value = "http://127.0.0.1:8080")]
    server_url: String,

    #[clap(long)]
    client_id: Option<String>,

    /// Data directory for persistent storage
    #[clap(long, default_value = "./data")]
    data_dir: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive mode
    Interactive,
    /// Create a new group
    CreateGroup { name: String },
    /// List all groups
    ListGroups,
    /// Join a group
    JoinGroup { group_name: String },
    /// Leave a group
    LeaveGroup { group_name: String },
    /// Send a message to a group
    SendMessage { group_name: String, message: String },
    /// Get messages from a group
    GetMessages { group_name: String },
    /// Generate and upload key package
    UploadKeyPackage,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let client_id = cli
        .client_id
        .unwrap_or_else(|| format!("client_{}", Uuid::new_v4()));

    let mut mls_client = MlsClient::new(cli.server_url, client_id.clone(), &cli.data_dir).await?;

    match cli.command {
        Some(Commands::Interactive) | None => {
            interactive_mode(&mut mls_client).await?;
        }
        Some(Commands::CreateGroup { name }) => {
            let group = mls_client.create_group(&name).await?;
            println!("Created group: {} ({})", group.name, group.id);
        }
        Some(Commands::ListGroups) => {
            let groups = mls_client.list_groups().await?;
            if groups.is_empty() {
                println!("No groups found");
            } else {
                println!("Groups:");
                for group in groups {
                    println!("  '{}' ({} members)", group.name, group.members.len());
                }
            }
        }
        Some(Commands::JoinGroup { group_name }) => {
            let group = mls_client.join_group_name(&group_name).await?;
            println!("Joined group: {}", group.name);
        }
        Some(Commands::LeaveGroup { group_name }) => {
            mls_client.leave_group_name(&group_name).await?;
            println!("Left group: {}", group_name);
        }
        Some(Commands::SendMessage {
            group_name,
            message,
        }) => {
            mls_client.send_message_name(&group_name, &message).await?;
            println!("Message sent to group: {}", group_name);
        }
        Some(Commands::GetMessages { group_name }) => {
            let messages = mls_client.get_messages_name(&group_name).await?;
            if messages.is_empty() {
                println!("No messages in group: {}", group_name);
            } else {
                println!("Messages in group {}:", group_name);
                for msg in messages {
                    println!(
                        "  [{}] {}: {}",
                        msg.timestamp.format("%H:%M:%S"),
                        msg.sender,
                        msg.content
                    );
                }
            }
        }
        Some(Commands::UploadKeyPackage) => {
            mls_client.upload_key_package().await?;
            println!("Key package uploaded");
        }
    }

    Ok(())
}

async fn interactive_mode(mls_client: &mut MlsClient) -> anyhow::Result<()> {
    let mut rl = DefaultEditor::new()?;

    println!("OpenMLS Client Interactive Mode");
    println!("Client ID: {}", mls_client.client_id());
    println!("Server: {}", mls_client.server_url());
    println!("Type 'help' for available commands or 'quit' to exit\n");

    loop {
        let readline = rl.readline("openmls> ");
        match readline {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                rl.add_history_entry(line)?;

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                match handle_interactive_command(mls_client, &parts).await {
                    Ok(should_quit) => {
                        if should_quit {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error: {}", e);
                    }
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                break;
            }
            Err(err) => {
                error!("Error reading input: {}", err);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_interactive_command(
    mls_client: &mut MlsClient,
    parts: &[&str],
) -> anyhow::Result<bool> {
    match parts[0] {
        "help" | "h" => {
            println!("Available commands:");
            println!("  help                     - Show this help");
            println!("  create <name>            - Create a new group");
            println!("  list                     - List all groups");
            println!("  join <group_name>        - Join a group");
            println!("  leave <group_name>       - Leave a group");
            println!(
                "  add <group_name> <user>  - Add a member to a group (requires Welcome workflow)"
            );
            println!("  send <group_name> <msg>  - Send a message to a group");
            println!("  messages <group_name>    - Get messages from a group");
            println!("  reset <group_name>       - Reset group state (fix compatibility issues)");
            println!(
                "  epochs                   - Show stored epoch keys for historical decryption"
            );
            println!(
                "  decryption-stats         - Show comprehensive decryption capability statistics"
            );
            println!("  upload-key               - Upload key package");
            println!("  quit                     - Exit the client");
        }
        "create" | "c" => {
            if parts.len() < 2 {
                println!("Usage: create <group_name>");
                return Ok(false);
            }
            let name = parts[1..].join(" ");
            let group = mls_client.create_group(&name).await?;
            println!("Created group: {} ({})", group.name, group.id);
        }
        "list" | "l" => {
            let groups = mls_client.list_groups().await?;
            if groups.is_empty() {
                println!("No groups found");
            } else {
                println!("Groups:");
                for group in groups {
                    println!("  '{}' ({} members)", group.name, group.members.len());
                }
            }
        }
        "join" | "j" => {
            if parts.len() < 2 {
                println!("Usage: join <group_name>");
                return Ok(false);
            }
            let group = mls_client.join_group_name(parts[1]).await?;
            println!("Joined group: {}", group.name);
        }
        "leave" => {
            if parts.len() < 2 {
                println!("Usage: leave <group_name>");
                return Ok(false);
            }
            mls_client.leave_group_name(parts[1]).await?;
            println!("Left group: {}", parts[1]);
        }
        "add" => {
            if parts.len() < 3 {
                println!("Usage: add <group_name> <user_id>");
                return Ok(false);
            }
            let group_uuid = mls_client.resolve_group_name(parts[1]).await?;
            mls_client.add_member_to_group(group_uuid, parts[2]).await?;
            println!("Added member {} to group: {}", parts[2], parts[1]);
        }
        "send" | "s" => {
            if parts.len() < 3 {
                println!("Usage: send <group_name> <message>");
                return Ok(false);
            }
            let message = parts[2..].join(" ");
            mls_client.send_message_name(parts[1], &message).await?;
            println!("Message sent to group: {}", parts[1]);
        }
        "messages" | "m" => {
            if parts.len() < 2 {
                println!("Usage: messages <group_name>");
                return Ok(false);
            }
            let messages = mls_client.get_messages_name(parts[1]).await?;
            if messages.is_empty() {
                println!("No messages in group: {}", parts[1]);
            } else {
                println!("Messages in group {}:", parts[1]);

                // Count successfully decrypted historical messages
                let historical_messages = messages
                    .iter()
                    .filter(|msg| {
                        msg.content
                            .contains("Successfully decrypted message from previous epoch")
                            || msg.content.contains("Comprehensive decryption successful")
                    })
                    .count();

                if historical_messages > 0 {
                    println!(
                        "  ✓ {} message(s) successfully decrypted using stored epoch keys",
                        historical_messages
                    );
                    println!("");
                }

                for msg in messages {
                    println!(
                        "  [{}] {}: {}",
                        msg.timestamp.format("%H:%M:%S"),
                        msg.sender,
                        msg.content
                    );
                }
            }
        }
        "reset" | "r" => {
            if parts.len() < 2 {
                println!("Usage: reset <group_name>");
                return Ok(false);
            }
            mls_client.reset_group_state(parts[1]).await?;
            println!("Reset group state for: {}", parts[1]);
        }
        "epochs" | "e" => {
            mls_client.show_epoch_keys().await?;
        }
        "decryption-stats" | "ds" => {
            mls_client.get_decryption_stats().await?;
        }
        "upload-key" | "uk" => {
            mls_client.upload_key_package().await?;
            println!("Key package uploaded");
        }
        "quit" | "q" | "exit" => {
            println!("Goodbye!");
            return Ok(true);
        }
        _ => {
            println!(
                "Unknown command: {}. Type 'help' for available commands.",
                parts[0]
            );
        }
    }

    Ok(false)
}
