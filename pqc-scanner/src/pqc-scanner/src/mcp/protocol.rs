//! MCP protocol types for PQC Scanner
//!
//! Implements the Model Context Protocol (MCP) for integration with
//! Open WebUI via MCP Context Forge.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// MCP JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// MCP JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpError>,
}

/// MCP error object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl McpError {
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

/// Standard JSON-RPC error codes
pub mod error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

impl McpResponse {
    /// Create a success response
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: Option<Value>, error: McpError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// MCP Tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// MCP Resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

/// MCP Prompt definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPrompt {
    pub name: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    pub description: String,
    pub required: bool,
}

// ============== Tool Parameters ==============

/// Parameters for scan_code tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCodeParams {
    /// Source code to scan
    pub code: String,
    /// Optional language hint (python, javascript, java, go, rust)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Include detailed report (default: true)
    #[serde(default = "default_true")]
    pub include_report: bool,
}

fn default_true() -> bool {
    true
}

/// Parameters for scan_file tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFileParams {
    /// File path to scan
    pub path: String,
    /// Optional language override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

/// Parameters for get_recommendations tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetRecommendationsParams {
    /// Algorithm name (e.g., "RSA", "ECDSA", "MD5")
    pub algorithm: String,
}

/// Parameters for check_compliance tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckComplianceParams {
    /// Source code to check
    pub code: String,
    /// Compliance standard (default: "cnsa2.0")
    #[serde(default = "default_compliance")]
    pub standard: String,
}

fn default_compliance() -> String {
    "cnsa2.0".to_string()
}

/// Parameters for list_algorithms tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListAlgorithmsParams {
    /// Filter by risk level (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_level: Option<String>,
    /// Include alternatives (default: true)
    #[serde(default = "default_true")]
    pub include_alternatives: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mcp_request_parse() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        }"#;
        let request: McpRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.method, "tools/list");
    }

    #[test]
    fn test_mcp_response_success() {
        let response = McpResponse::success(
            Some(serde_json::json!(1)),
            serde_json::json!({"status": "ok"}),
        );
        assert!(response.error.is_none());
        assert!(response.result.is_some());
    }

    #[test]
    fn test_scan_code_params() {
        let json = r#"{
            "code": "from Crypto.PublicKey import RSA",
            "language": "python"
        }"#;
        let params: ScanCodeParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.language, Some("python".to_string()));
        assert!(params.include_report); // default value
    }
}
