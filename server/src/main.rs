use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
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

#[derive(Clone)]
pub struct AppState {
    mls_manager: Arc<Mutex<MlsManager>>,
    groups: Arc<Mutex<HashMap<Uuid, GroupInfo>>>,
    messages: Arc<Mutex<HashMap<Uuid, Vec<MlsMessage>>>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupInfo {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let state = AppState {
        mls_manager: Arc::new(Mutex::new(MlsManager::new())),
        groups: Arc::new(Mutex::new(HashMap::new())),
        messages: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/:group_id", get(get_group))
        .route("/groups/:group_id/join", post(join_group))
        .route("/groups/:group_id/leave", post(leave_group))
        .route("/groups/:group_id/messages", get(get_messages).post(send_message))
        .route("/key_packages", post(upload_key_package))
        .route("/key_packages/:client_id", get(get_key_package))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    info!("Server running on http://127.0.0.1:8080");

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

    state.groups.lock().unwrap().insert(group_id, group_info.clone());
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
    let mut messages = state.messages.lock().unwrap();
    match messages.get_mut(&group_id) {
        Some(msgs) => {
            let message = MlsMessage {
                id: Uuid::new_v4(),
                group_id,
                sender: request.sender,
                content: request.content,
                timestamp: chrono::Utc::now(),
            };
            msgs.push(message);
            info!("Message sent to group {}", group_id);
            Ok(Json(serde_json::json!({"status": "sent"})))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn upload_key_package(
    State(state): State<AppState>,
    Json(request): Json<UploadKeyPackageRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut mls_manager = state.mls_manager.lock().unwrap();
    mls_manager.store_key_package(request.client_id, request.key_package);
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