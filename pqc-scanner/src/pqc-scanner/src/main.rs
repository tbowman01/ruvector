//! PQC Scanner MCP Server
//!
//! Post-Quantum Cryptography vulnerability scanner exposed via MCP protocol.
//! Integrates with Open WebUI through MCP Context Forge.

mod mcp;
mod patterns;
mod scanner;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use mcp::{McpHandler, McpRequest, McpResponse};
use serde_json::json;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{info, Level};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Application state
struct AppState {
    handler: McpHandler,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("Starting PQC Scanner MCP Server v{}", env!("CARGO_PKG_VERSION"));

    // Create handler
    let handler = McpHandler::new();
    let state = Arc::new(AppState { handler });

    // CORS configuration for MCP Context Forge
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/mcp", post(handle_mcp))
        .route("/sse", get(handle_sse))
        .with_state(state)
        .layer(cors);

    // Get port from environment or default to 8001
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8001".to_string())
        .parse::<u16>()
        .unwrap_or(8001);

    let addr = format!("0.0.0.0:{}", port);
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Root endpoint
async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "name": "pqc-scanner",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Post-Quantum Cryptography vulnerability scanner MCP server",
        "capabilities": ["tools", "resources", "prompts"],
        "endpoints": {
            "mcp": "/mcp",
            "health": "/health",
            "sse": "/sse"
        }
    }))
}

/// Health check endpoint
async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "pqc-scanner",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Handle MCP JSON-RPC requests
async fn handle_mcp(
    State(state): State<Arc<AppState>>,
    Json(request): Json<McpRequest>,
) -> Json<McpResponse> {
    let response = state.handler.handle_request(request).await;
    Json(response)
}

/// SSE endpoint for streaming (placeholder for future implementation)
async fn handle_sse() -> (StatusCode, &'static str) {
    (StatusCode::NOT_IMPLEMENTED, "SSE not yet implemented")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn create_app() -> Router {
        let handler = McpHandler::new();
        let state = Arc::new(AppState { handler });

        Router::new()
            .route("/", get(root))
            .route("/health", get(health))
            .route("/mcp", post(handle_mcp))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_root() {
        let app = create_app();
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health() {
        let app = create_app();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_mcp_initialize() {
        let app = create_app();
        let request_body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
