//! MCP request handlers for PQC Scanner
//!
//! Handles MCP protocol requests and dispatches to appropriate scanner functionality.

use super::protocol::*;
use crate::patterns::{get_algorithms_by_risk, get_all_algorithms, RiskLevel};
use crate::scanner::Scanner;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

/// MCP Handler for PQC Scanner
pub struct McpHandler {
    scanner: Arc<RwLock<Scanner>>,
}

impl Default for McpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl McpHandler {
    pub fn new() -> Self {
        Self {
            scanner: Arc::new(RwLock::new(Scanner::new())),
        }
    }

    /// Handle an incoming MCP request
    pub async fn handle_request(&self, request: McpRequest) -> McpResponse {
        info!("Handling MCP request: {}", request.method);

        match request.method.as_str() {
            "initialize" => self.handle_initialize(request.id).await,
            "initialized" => self.handle_initialized(request.id).await,
            "tools/list" => self.handle_tools_list(request.id).await,
            "tools/call" => self.handle_tools_call(request.id, request.params).await,
            "resources/list" => self.handle_resources_list(request.id).await,
            "resources/read" => self.handle_resources_read(request.id, request.params).await,
            "prompts/list" => self.handle_prompts_list(request.id).await,
            "prompts/get" => self.handle_prompts_get(request.id, request.params).await,
            "ping" => self.handle_ping(request.id).await,
            _ => {
                error!("Unknown method: {}", request.method);
                McpResponse::error(
                    request.id,
                    McpError::new(error_codes::METHOD_NOT_FOUND, format!("Method not found: {}", request.method)),
                )
            }
        }
    }

    /// Handle initialize request
    async fn handle_initialize(&self, id: Option<Value>) -> McpResponse {
        McpResponse::success(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                },
                "serverInfo": {
                    "name": "pqc-scanner",
                    "version": env!("CARGO_PKG_VERSION"),
                    "description": "Post-Quantum Cryptography vulnerability scanner"
                }
            }),
        )
    }

    /// Handle initialized notification
    async fn handle_initialized(&self, id: Option<Value>) -> McpResponse {
        McpResponse::success(id, json!({}))
    }

    /// Handle ping request
    async fn handle_ping(&self, id: Option<Value>) -> McpResponse {
        McpResponse::success(id, json!({}))
    }

    /// List available tools
    async fn handle_tools_list(&self, id: Option<Value>) -> McpResponse {
        let tools = vec![
            McpTool {
                name: "scan_code".to_string(),
                description: "Scan source code for quantum-vulnerable cryptographic algorithms. Returns vulnerabilities found with risk levels and PQC migration recommendations.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Source code to scan for vulnerabilities"
                        },
                        "language": {
                            "type": "string",
                            "description": "Programming language hint (python, javascript, java, go, rust)",
                            "enum": ["python", "javascript", "java", "go", "rust"]
                        },
                        "include_report": {
                            "type": "boolean",
                            "description": "Include detailed human-readable report",
                            "default": true
                        }
                    },
                    "required": ["code"]
                }),
            },
            McpTool {
                name: "get_recommendations".to_string(),
                description: "Get post-quantum cryptography migration recommendations for a specific vulnerable algorithm.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "algorithm": {
                            "type": "string",
                            "description": "Algorithm name (e.g., RSA, ECDSA, MD5, SHA-1, DES)"
                        }
                    },
                    "required": ["algorithm"]
                }),
            },
            McpTool {
                name: "list_algorithms".to_string(),
                description: "List all quantum-vulnerable algorithms that can be detected, optionally filtered by risk level.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "risk_level": {
                            "type": "string",
                            "description": "Filter by risk level",
                            "enum": ["critical", "high", "medium", "low"]
                        },
                        "include_alternatives": {
                            "type": "boolean",
                            "description": "Include PQC alternative recommendations",
                            "default": true
                        }
                    }
                }),
            },
            McpTool {
                name: "check_compliance".to_string(),
                description: "Check if code is compliant with CNSA 2.0 post-quantum cryptography requirements.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": "Source code to check for compliance"
                        },
                        "standard": {
                            "type": "string",
                            "description": "Compliance standard to check against",
                            "enum": ["cnsa2.0"],
                            "default": "cnsa2.0"
                        }
                    },
                    "required": ["code"]
                }),
            },
        ];

        McpResponse::success(id, json!({ "tools": tools }))
    }

    /// Handle tool calls
    async fn handle_tools_call(&self, id: Option<Value>, params: Option<Value>) -> McpResponse {
        let params = match params {
            Some(p) => p,
            None => {
                return McpResponse::error(
                    id,
                    McpError::new(error_codes::INVALID_PARAMS, "Missing params"),
                )
            }
        };

        let tool_name = params["name"].as_str().unwrap_or("");
        let arguments = &params["arguments"];

        let result = match tool_name {
            "scan_code" => self.tool_scan_code(arguments).await,
            "get_recommendations" => self.tool_get_recommendations(arguments).await,
            "list_algorithms" => self.tool_list_algorithms(arguments).await,
            "check_compliance" => self.tool_check_compliance(arguments).await,
            _ => Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
        };

        match result {
            Ok(value) => McpResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": value
                    }]
                }),
            ),
            Err(e) => {
                error!("Tool error: {}", e);
                McpResponse::error(
                    id,
                    McpError::new(error_codes::INTERNAL_ERROR, e.to_string()),
                )
            }
        }
    }

    /// Scan code for vulnerabilities
    async fn tool_scan_code(&self, args: &Value) -> Result<String> {
        let params: ScanCodeParams =
            serde_json::from_value(args.clone()).context("Invalid parameters for scan_code")?;

        let scanner = if let Some(ref lang) = params.language {
            Scanner::new().with_language_hint(lang)
        } else {
            Scanner::new()
        };

        let result = scanner.scan(&params.code);

        if params.include_report {
            let report = Scanner::format_report(&result);
            let json_result = serde_json::to_string_pretty(&result)?;
            Ok(format!("{}\n\n--- JSON Data ---\n{}", report, json_result))
        } else {
            serde_json::to_string_pretty(&result).context("Failed to serialize scan result")
        }
    }

    /// Get recommendations for a specific algorithm
    async fn tool_get_recommendations(&self, args: &Value) -> Result<String> {
        let params: GetRecommendationsParams = serde_json::from_value(args.clone())
            .context("Invalid parameters for get_recommendations")?;

        let algorithms = get_all_algorithms();
        let algorithm = algorithms
            .iter()
            .find(|a| a.name.to_lowercase() == params.algorithm.to_lowercase())
            .ok_or_else(|| anyhow::anyhow!("Unknown algorithm: {}", params.algorithm))?;

        let mut output = String::new();
        output.push_str(&format!("# Migration Recommendations for {}\n\n", algorithm.name));
        output.push_str(&format!("**Risk Level:** {}\n", algorithm.risk_level));
        output.push_str(&format!("**Category:** {}\n", algorithm.category));
        output.push_str(&format!("**CNSA 2.0 Deadline:** {}\n\n", algorithm.cnsa_deadline));
        output.push_str(&format!("## Why is {} vulnerable?\n\n", algorithm.name));
        output.push_str(&format!("{}\n\n", algorithm.description));
        output.push_str("## Recommended PQC Alternatives\n\n");

        for alt in &algorithm.pqc_alternatives {
            output.push_str(&format!("### {} ({})\n\n", alt.name, alt.nist_name));
            output.push_str(&format!("- **Description:** {}\n", alt.description));
            output.push_str(&format!("- **Use Case:** {}\n\n", alt.use_case));
        }

        output.push_str("## Migration Steps\n\n");
        output.push_str("1. Inventory all uses of this algorithm in your codebase\n");
        output.push_str("2. Assess dependencies that may also use vulnerable crypto\n");
        output.push_str("3. Select appropriate PQC alternative based on use case\n");
        output.push_str("4. Implement hybrid approach during transition (classical + PQC)\n");
        output.push_str("5. Test thoroughly with new algorithms\n");
        output.push_str("6. Plan key rotation and certificate updates\n");

        Ok(output)
    }

    /// List all detectable algorithms
    async fn tool_list_algorithms(&self, args: &Value) -> Result<String> {
        let params: ListAlgorithmsParams = serde_json::from_value(args.clone()).unwrap_or(ListAlgorithmsParams {
            risk_level: None,
            include_alternatives: true,
        });

        let algorithms = if let Some(ref risk) = params.risk_level {
            let risk_level = match risk.to_lowercase().as_str() {
                "critical" => RiskLevel::Critical,
                "high" => RiskLevel::High,
                "medium" => RiskLevel::Medium,
                "low" => RiskLevel::Low,
                _ => return Err(anyhow::anyhow!("Invalid risk level: {}", risk)),
            };
            get_algorithms_by_risk(risk_level)
        } else {
            get_all_algorithms()
        };

        let mut output = String::new();
        output.push_str("# Detectable Quantum-Vulnerable Algorithms\n\n");

        if let Some(ref risk) = params.risk_level {
            output.push_str(&format!("Filtered by risk level: {}\n\n", risk.to_uppercase()));
        }

        output.push_str("| Algorithm | Category | Risk | CNSA Deadline |\n");
        output.push_str("|-----------|----------|------|---------------|\n");

        for algo in &algorithms {
            output.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                algo.name, algo.category, algo.risk_level, algo.cnsa_deadline
            ));
        }

        if params.include_alternatives {
            output.push_str("\n## PQC Alternatives Summary\n\n");
            output.push_str("| Vulnerable | Alternative | NIST Standard | Use Case |\n");
            output.push_str("|------------|-------------|---------------|----------|\n");

            for algo in &algorithms {
                for alt in &algo.pqc_alternatives {
                    output.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        algo.name, alt.name, alt.nist_name, alt.use_case
                    ));
                }
            }
        }

        Ok(output)
    }

    /// Check CNSA 2.0 compliance
    async fn tool_check_compliance(&self, args: &Value) -> Result<String> {
        let params: CheckComplianceParams =
            serde_json::from_value(args.clone()).context("Invalid parameters for check_compliance")?;

        let scanner = Scanner::new();
        let result = scanner.scan(&params.code);

        let mut output = String::new();
        output.push_str(&format!("# {} Compliance Check\n\n", params.standard.to_uppercase()));

        if result.cnsa_compliant {
            output.push_str("## ✅ COMPLIANT\n\n");
            output.push_str("No quantum-vulnerable cryptographic algorithms were detected.\n\n");
        } else {
            output.push_str("## ❌ NOT COMPLIANT\n\n");
            output.push_str("The following issues must be addressed:\n\n");

            if result.summary.critical > 0 {
                output.push_str(&format!(
                    "- **{} CRITICAL** vulnerabilities (must migrate by 2030)\n",
                    result.summary.critical
                ));
            }
            if result.summary.high > 0 {
                output.push_str(&format!(
                    "- **{} HIGH** risk issues (immediate migration recommended)\n",
                    result.summary.high
                ));
            }
            if result.summary.medium > 0 {
                output.push_str(&format!(
                    "- **{} MEDIUM** risk issues (migration recommended)\n",
                    result.summary.medium
                ));
            }
            if result.summary.low > 0 {
                output.push_str(&format!(
                    "- **{} LOW** risk issues (consider migration)\n",
                    result.summary.low
                ));
            }

            output.push_str("\n### Detailed Findings\n\n");
            for vuln in &result.vulnerabilities {
                output.push_str(&format!(
                    "- Line {}: **{}** [{}] - {}\n",
                    vuln.line_number, vuln.algorithm, vuln.risk_level, vuln.context
                ));
            }
        }

        output.push_str("\n## CNSA 2.0 Timeline Requirements\n\n");
        output.push_str("- **2025:** Transition planning complete\n");
        output.push_str("- **2030:** All public-key algorithms must be quantum-resistant\n");
        output.push_str("- **2035:** Full post-quantum cryptography deployment\n");

        Ok(output)
    }

    /// List available resources
    async fn handle_resources_list(&self, id: Option<Value>) -> McpResponse {
        McpResponse::success(
            id,
            json!({
                "resources": [
                    {
                        "uri": "pqc://algorithms/all",
                        "name": "All Vulnerable Algorithms",
                        "description": "List of all quantum-vulnerable algorithms",
                        "mimeType": "application/json"
                    },
                    {
                        "uri": "pqc://nist/standards",
                        "name": "NIST PQC Standards",
                        "description": "NIST Post-Quantum Cryptography standards reference",
                        "mimeType": "application/json"
                    }
                ]
            }),
        )
    }

    /// Read a resource
    async fn handle_resources_read(&self, id: Option<Value>, params: Option<Value>) -> McpResponse {
        let uri = params
            .as_ref()
            .and_then(|p| p["uri"].as_str())
            .unwrap_or("");

        let content = match uri {
            "pqc://algorithms/all" => {
                let algorithms = get_all_algorithms();
                serde_json::to_string_pretty(&algorithms).unwrap_or_default()
            }
            "pqc://nist/standards" => {
                json!({
                    "ML-KEM": {
                        "nist_name": "FIPS 203",
                        "description": "Module-Lattice-Based Key-Encapsulation Mechanism",
                        "status": "Published August 2024"
                    },
                    "ML-DSA": {
                        "nist_name": "FIPS 204",
                        "description": "Module-Lattice-Based Digital Signature Algorithm",
                        "status": "Published August 2024"
                    },
                    "SLH-DSA": {
                        "nist_name": "FIPS 205",
                        "description": "Stateless Hash-Based Digital Signature Algorithm",
                        "status": "Published August 2024"
                    }
                })
                .to_string()
            }
            _ => return McpResponse::error(
                id,
                McpError::new(error_codes::INVALID_PARAMS, format!("Unknown resource: {}", uri)),
            ),
        };

        McpResponse::success(
            id,
            json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": content
                }]
            }),
        )
    }

    /// List available prompts
    async fn handle_prompts_list(&self, id: Option<Value>) -> McpResponse {
        McpResponse::success(
            id,
            json!({
                "prompts": [
                    {
                        "name": "scan-for-vulnerabilities",
                        "description": "Scan code for quantum-vulnerable cryptography",
                        "arguments": [
                            {
                                "name": "code",
                                "description": "Source code to scan",
                                "required": true
                            }
                        ]
                    },
                    {
                        "name": "migration-guide",
                        "description": "Get migration guide for vulnerable algorithm",
                        "arguments": [
                            {
                                "name": "algorithm",
                                "description": "Algorithm to migrate from (e.g., RSA, ECDSA)",
                                "required": true
                            }
                        ]
                    }
                ]
            }),
        )
    }

    /// Get a prompt
    async fn handle_prompts_get(&self, id: Option<Value>, params: Option<Value>) -> McpResponse {
        let name = params
            .as_ref()
            .and_then(|p| p["name"].as_str())
            .unwrap_or("");

        let prompt = match name {
            "scan-for-vulnerabilities" => json!({
                "description": "Scan code for quantum-vulnerable cryptography",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": "Please scan the following code for quantum-vulnerable cryptographic algorithms and provide recommendations:\n\n{{code}}"
                        }
                    }
                ]
            }),
            "migration-guide" => json!({
                "description": "Get migration guide for vulnerable algorithm",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": "Please provide a detailed migration guide for replacing {{algorithm}} with post-quantum alternatives."
                        }
                    }
                ]
            }),
            _ => return McpResponse::error(
                id,
                McpError::new(error_codes::INVALID_PARAMS, format!("Unknown prompt: {}", name)),
            ),
        };

        McpResponse::success(id, prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_handle_initialize() {
        let handler = McpHandler::new();
        let request = McpRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: None,
        };
        let response = handler.handle_request(request).await;
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_handle_tools_list() {
        let handler = McpHandler::new();
        let request = McpRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/list".to_string(),
            params: None,
        };
        let response = handler.handle_request(request).await;
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
    }

    #[tokio::test]
    async fn test_scan_code_tool() {
        let handler = McpHandler::new();
        let request = McpRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "scan_code",
                "arguments": {
                    "code": "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)",
                    "language": "python"
                }
            })),
        };
        let response = handler.handle_request(request).await;
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let content = result["content"][0]["text"].as_str().unwrap();
        assert!(content.contains("RSA"));
        assert!(content.contains("CRITICAL"));
    }
}
