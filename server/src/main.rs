use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tower_http::cors::CorsLayer;
use tracing::info;
use uuid::Uuid;

mod types;
use types::*;

mod mls_manager;
use mls_manager::MlsManager;

mod persistence;
use persistence::PersistenceManager;

#[derive(Parser)]
#[command(name = "openmls-server")]
#[command(about = "OpenMLS Server - Secure group messaging server using MLS protocol")]
struct Args {
    /// Server host address
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Server port
    #[arg(long, default_value = "8080")]
    port: u16,

    /// Data directory for persistent storage
    #[arg(long, default_value = "./data/server")]
    data_dir: String,
}

#[derive(Clone)]
pub struct AppState {
    mls_manager: Arc<Mutex<MlsManager>>,
    groups: Arc<Mutex<HashMap<Uuid, GroupInfo>>>,
    messages: Arc<Mutex<HashMap<Uuid, Vec<MlsMessage>>>>,
    welcome_messages: Arc<Mutex<HashMap<String, Vec<u8>>>>, // client_id -> welcome_message
    ratchet_trees: Arc<Mutex<HashMap<(String, Uuid), Vec<u8>>>>, // (client_id, group_id) -> ratchet_tree
    persistence: Arc<PersistenceManager>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupInfo {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SendWelcomeRequest {
    pub client_id: String,
    pub welcome_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetWelcomeResponse {
    pub welcome_message: Vec<u8>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt::init();

    // Initialize persistence manager
    let persistence = Arc::new(PersistenceManager::new(&args.data_dir)?);

    // Load existing state
    let groups = Arc::new(Mutex::new(persistence.load_groups().await?));
    let messages = Arc::new(Mutex::new(persistence.load_all_messages().await?));

    // Initialize MLS manager (no longer loads key packages from disk)
    let mls_manager = MlsManager::new();

    let state = AppState {
        mls_manager: Arc::new(Mutex::new(mls_manager)),
        groups: groups.clone(),
        messages: messages.clone(),
        welcome_messages: Arc::new(Mutex::new(HashMap::new())),
        ratchet_trees: Arc::new(Mutex::new(HashMap::new())),
        persistence: persistence.clone(),
    };

    // Setup auto-save task for persistence
    let persistence_clone = persistence.clone();
    let groups_clone = groups.clone();
    let messages_clone = messages.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;

            // Auto-save groups
            let groups_data = {
                if let Ok(guard) = groups_clone.lock() {
                    guard.clone()
                } else {
                    continue;
                }
            };
            if let Err(e) = persistence_clone.save_groups(&groups_data).await {
                tracing::warn!("Auto-save groups failed: {}", e);
            }

            // Auto-save messages
            let messages_data = {
                if let Ok(guard) = messages_clone.lock() {
                    guard.clone()
                } else {
                    continue;
                }
            };
            if let Err(e) = persistence_clone.auto_save_messages(&messages_data).await {
                tracing::warn!("Auto-save messages failed: {}", e);
            }
        }
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/{group_id}", get(get_group))
        .route("/groups/{group_id}/join", post(join_group))
        .route("/groups/{group_id}/leave", post(leave_group))
        .route(
            "/groups/{group_id}/messages",
            get(get_messages).post(send_message),
        )
        .route("/key_packages", post(upload_key_package))
        .route("/key_packages/{client_id}", get(get_key_package))
        .route("/welcome", post(send_welcome_message))
        .route("/welcome/{client_id}", get(get_welcome_message))
        .route("/ratchet-tree", post(send_ratchet_tree))
        .route(
            "/ratchet-tree/{client_id}/{group_id}",
            get(get_ratchet_tree),
        )
        .layer(CorsLayer::permissive())
        .with_state(state);

    let bind_address = format!("{}:{}", args.host, args.port);
    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    info!("Server running on http://{}", bind_address);
    info!("Data directory: {}", args.data_dir);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status": "ok"}))
}

async fn list_groups(State(state): State<AppState>) -> Json<Vec<GroupInfo>> {
    let groups = state.groups.lock().unwrap();
    Json(groups.values().cloned().collect())
}

async fn create_group(
    State(state): State<AppState>,
    Json(request): Json<CreateGroupRequest>,
) -> Result<Json<GroupInfo>, StatusCode> {
    let group_id = Uuid::new_v4();
    let group_info = GroupInfo {
        id: group_id,
        name: request.name,
        members: vec![request.creator],
        created_at: chrono::Utc::now(),
    };

    state
        .groups
        .lock()
        .unwrap()
        .insert(group_id, group_info.clone());
    state.messages.lock().unwrap().insert(group_id, Vec::new());

    info!("Created group: {} ({})", group_info.name, group_id);
    Ok(Json(group_info))
}

async fn get_group(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupInfo>, StatusCode> {
    let groups = state.groups.lock().unwrap();
    match groups.get(&group_id) {
        Some(group) => Ok(Json(group.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn join_group(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(request): Json<JoinGroupRequest>,
) -> Result<Json<GroupInfo>, StatusCode> {
    let mut groups = state.groups.lock().unwrap();
    match groups.get_mut(&group_id) {
        Some(group) => {
            if !group.members.contains(&request.client_id) {
                group.members.push(request.client_id.clone());
                info!("Client {} joined group {}", request.client_id, group_id);
            }
            Ok(Json(group.clone()))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn leave_group(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(request): Json<LeaveGroupRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut groups = state.groups.lock().unwrap();
    match groups.get_mut(&group_id) {
        Some(group) => {
            group.members.retain(|m| m != &request.client_id);
            info!("Client {} left group {}", request.client_id, group_id);

            // Clean up welcome message for this client
            {
                let mut welcome_msgs = state.welcome_messages.lock().unwrap();
                welcome_msgs.remove(&request.client_id);
            }

            Ok(Json(serde_json::json!({"status": "left"})))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_messages(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<MlsMessage>>, StatusCode> {
    let messages = state.messages.lock().unwrap();
    match messages.get(&group_id) {
        Some(msgs) => Ok(Json(msgs.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn send_message(
    State(state): State<AppState>,
    Path(group_id): Path<Uuid>,
    Json(request): Json<SendMessageRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let message = MlsMessage::new_encrypted(group_id, request.sender, request.encrypted_content);

    // Update in-memory state
    let updated_messages = {
        let mut messages = state.messages.lock().unwrap();
        match messages.get_mut(&group_id) {
            Some(msgs) => {
                msgs.push(message);
                msgs.clone()
            }
            None => return Err(StatusCode::NOT_FOUND),
        }
    };

    // Save to disk asynchronously
    if let Err(e) = state
        .persistence
        .save_messages(group_id, &updated_messages)
        .await
    {
        tracing::warn!("Failed to save message: {}", e);
    }

    info!("Encrypted message sent to group {}", group_id);
    Ok(Json(serde_json::json!({"status": "sent"})))
}

async fn upload_key_package(
    State(state): State<AppState>,
    Json(request): Json<UploadKeyPackageRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    {
        let mut mls_manager = state.mls_manager.lock().unwrap();
        mls_manager.store_key_package(request.client_id.clone(), request.key_package.clone());
    }

    info!("Key package uploaded for client: {}", request.client_id);
    Ok(Json(serde_json::json!({"status": "uploaded"})))
}

async fn get_key_package(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<Json<KeyPackageResponse>, StatusCode> {
    let mls_manager = state.mls_manager.lock().unwrap();
    match mls_manager.get_key_package(&client_id) {
        Some(key_package) => Ok(Json(KeyPackageResponse { key_package })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn send_welcome_message(
    State(state): State<AppState>,
    Json(request): Json<SendWelcomeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    {
        let mut welcome_msgs = state.welcome_messages.lock().unwrap();
        welcome_msgs.insert(request.client_id.clone(), request.welcome_message);
    }

    info!("Welcome message stored for client: {}", request.client_id);
    Ok(Json(serde_json::json!({"status": "stored"})))
}

async fn get_welcome_message(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<Json<GetWelcomeResponse>, StatusCode> {
    let welcome_msgs = state.welcome_messages.lock().unwrap();
    match welcome_msgs.get(&client_id) {
        Some(welcome_message) => {
            info!("Retrieved welcome message for client: {}", client_id);
            Ok(Json(GetWelcomeResponse {
                welcome_message: welcome_message.clone(),
            }))
        }
        None => {
            info!("No welcome message found for client: {}", client_id);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn send_ratchet_tree(
    State(state): State<AppState>,
    Json(request): Json<SendRatchetTreeRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    {
        let mut ratchet_trees = state.ratchet_trees.lock().unwrap();
        ratchet_trees.insert(
            (request.client_id.clone(), request.group_id),
            request.ratchet_tree,
        );
    }

    info!(
        "Ratchet tree stored for client {} and group {}",
        request.client_id, request.group_id
    );
    Ok(Json(serde_json::json!({"status": "stored"})))
}

async fn get_ratchet_tree(
    State(state): State<AppState>,
    Path((client_id, group_id)): Path<(String, Uuid)>,
) -> Result<Json<GetRatchetTreeResponse>, StatusCode> {
    let ratchet_trees = state.ratchet_trees.lock().unwrap();
    match ratchet_trees.get(&(client_id.clone(), group_id)) {
        Some(ratchet_tree) => {
            info!(
                "Retrieved ratchet tree for client {} and group {}",
                client_id, group_id
            );
            Ok(Json(GetRatchetTreeResponse {
                ratchet_tree: ratchet_tree.clone(),
            }))
        }
        None => {
            info!(
                "No ratchet tree found for client {} and group {}",
                client_id, group_id
            );
            Err(StatusCode::NOT_FOUND)
        }
    }
}
