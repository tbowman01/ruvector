//! MCP request handlers for PQC Scanner
//!
//! Handles MCP protocol requests and dispatches to appropriate scanner functionality.

use super::protocol::*;
use crate::github::GitHubClient;
use crate::patterns::{get_algorithms_by_risk, get_all_algorithms, RiskLevel};
use crate::scanner::Scanner;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// MCP Handler for PQC Scanner
pub struct McpHandler {
    scanner: Arc<RwLock<Scanner>>,
    github_client: Arc<GitHubClient>,
}

impl Default for McpHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl McpHandler {
    pub fn new() -> Self {
        // Get GitHub token from environment
        let github_token = std::env::var("GITHUB_TOKEN").ok();

        Self {
            scanner: Arc::new(RwLock::new(Scanner::new())),
            github_client: Arc::new(GitHubClient::new(github_token)),
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
        let github_auth = if self.github_client.is_authenticated() {
            "authenticated"
        } else {
            "unauthenticated (set GITHUB_TOKEN for private repos)"
        };

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
                    "description": "Post-Quantum Cryptography vulnerability scanner with GitHub organization support",
                    "github_status": github_auth
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
        let mut tools = vec![
            // Existing code scanning tools
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
            // GitHub organization scanning tools
            McpTool {
                name: "scan_github_org".to_string(),
                description: "Scan all repositories in a GitHub organization for quantum-vulnerable cryptographic algorithms. Requires GITHUB_TOKEN for private repos.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "org": {
                            "type": "string",
                            "description": "GitHub organization name (e.g., 'microsoft', 'google')"
                        },
                        "max_files_per_repo": {
                            "type": "integer",
                            "description": "Maximum files to scan per repository",
                            "default": 50
                        },
                        "include_private": {
                            "type": "boolean",
                            "description": "Include private repositories (requires authentication)",
                            "default": false
                        },
                        "language_filter": {
                            "type": "string",
                            "description": "Only scan repos with this primary language"
                        }
                    },
                    "required": ["org"]
                }),
            },
            McpTool {
                name: "scan_github_repo".to_string(),
                description: "Scan a specific GitHub repository for quantum-vulnerable cryptographic algorithms.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository in format 'owner/repo' (e.g., 'facebook/react')"
                        },
                        "max_files": {
                            "type": "integer",
                            "description": "Maximum files to scan",
                            "default": 100
                        },
                        "path": {
                            "type": "string",
                            "description": "Specific path to scan (optional, scans entire repo if not specified)"
                        }
                    },
                    "required": ["repo"]
                }),
            },
            McpTool {
                name: "list_github_repos".to_string(),
                description: "List all repositories in a GitHub organization with their languages and sizes.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "org": {
                            "type": "string",
                            "description": "GitHub organization name"
                        },
                        "include_archived": {
                            "type": "boolean",
                            "description": "Include archived repositories",
                            "default": false
                        }
                    },
                    "required": ["org"]
                }),
            },
            McpTool {
                name: "scan_github_file".to_string(),
                description: "Scan a specific file from a GitHub repository for quantum-vulnerable cryptographic algorithms.".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "repo": {
                            "type": "string",
                            "description": "Repository in format 'owner/repo'"
                        },
                        "path": {
                            "type": "string",
                            "description": "File path in the repository (e.g., 'src/crypto/keys.py')"
                        }
                    },
                    "required": ["repo", "path"]
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
            // Existing tools
            "scan_code" => self.tool_scan_code(arguments).await,
            "get_recommendations" => self.tool_get_recommendations(arguments).await,
            "list_algorithms" => self.tool_list_algorithms(arguments).await,
            "check_compliance" => self.tool_check_compliance(arguments).await,
            // GitHub tools
            "scan_github_org" => self.tool_scan_github_org(arguments).await,
            "scan_github_repo" => self.tool_scan_github_repo(arguments).await,
            "list_github_repos" => self.tool_list_github_repos(arguments).await,
            "scan_github_file" => self.tool_scan_github_file(arguments).await,
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

    // ==================== GitHub Tools ====================

    /// Scan all repositories in a GitHub organization
    async fn tool_scan_github_org(&self, args: &Value) -> Result<String> {
        let params: ScanGitHubOrgParams =
            serde_json::from_value(args.clone()).context("Invalid parameters for scan_github_org")?;

        info!("Starting scan of GitHub organization: {}", params.org);

        // Get organization info
        let org_info = self.github_client.get_organization(&params.org).await?;

        let mut output = String::new();
        output.push_str(&format!("# PQC Vulnerability Scan: {}\n\n", params.org));
        output.push_str(&format!("**Organization:** {}\n", org_info.login));
        if let Some(desc) = &org_info.description {
            output.push_str(&format!("**Description:** {}\n", desc));
        }
        output.push_str(&format!("**Public Repos:** {}\n\n", org_info.public_repos));

        // Scan all repositories
        let scan_targets = self.github_client
            .scan_organization(&params.org, params.max_files_per_repo)
            .await?;

        if scan_targets.is_empty() {
            output.push_str("No scannable files found in the organization.\n");
            return Ok(output);
        }

        output.push_str(&format!("**Files Scanned:** {}\n\n", scan_targets.len()));
        output.push_str("---\n\n");

        // Scan each file and aggregate results
        let scanner = Scanner::new();
        let mut total_critical = 0;
        let mut total_high = 0;
        let mut total_medium = 0;
        let mut total_low = 0;
        let mut repo_results: std::collections::HashMap<String, Vec<(String, crate::scanner::ScanResult)>> =
            std::collections::HashMap::new();

        for target in &scan_targets {
            let result = if let Some(ref lang) = target.language {
                Scanner::new().with_language_hint(lang).scan(&target.content)
            } else {
                scanner.scan(&target.content)
            };

            if result.summary.total > 0 {
                total_critical += result.summary.critical;
                total_high += result.summary.high;
                total_medium += result.summary.medium;
                total_low += result.summary.low;

                repo_results
                    .entry(target.repo.clone())
                    .or_default()
                    .push((target.path.clone(), result));
            }
        }

        // Summary
        output.push_str("## Summary\n\n");
        let total_vulns = total_critical + total_high + total_medium + total_low;

        if total_vulns == 0 {
            output.push_str("✅ **No quantum-vulnerable cryptographic algorithms detected!**\n\n");
        } else {
            output.push_str(&format!("⚠️ **Found {} vulnerabilities across {} repositories:**\n\n",
                total_vulns, repo_results.len()));
            output.push_str(&format!("| Risk Level | Count |\n"));
            output.push_str(&format!("|------------|-------|\n"));
            output.push_str(&format!("| CRITICAL | {} |\n", total_critical));
            output.push_str(&format!("| HIGH | {} |\n", total_high));
            output.push_str(&format!("| MEDIUM | {} |\n", total_medium));
            output.push_str(&format!("| LOW | {} |\n\n", total_low));
        }

        // Detailed findings by repository
        if !repo_results.is_empty() {
            output.push_str("## Detailed Findings by Repository\n\n");

            for (repo, files) in &repo_results {
                output.push_str(&format!("### {}\n\n", repo));

                for (path, result) in files {
                    output.push_str(&format!("**{}**\n", path));
                    for vuln in &result.vulnerabilities {
                        output.push_str(&format!(
                            "- Line {}: {} [{}]\n",
                            vuln.line_number, vuln.algorithm, vuln.risk_level
                        ));
                    }
                    output.push('\n');
                }
            }
        }

        // Compliance summary
        output.push_str("## CNSA 2.0 Compliance\n\n");
        if total_critical == 0 && total_high == 0 {
            output.push_str("✅ Organization is CNSA 2.0 compliant (no critical/high vulnerabilities)\n");
        } else {
            output.push_str("❌ Organization is NOT CNSA 2.0 compliant\n\n");
            output.push_str("**Required Actions:**\n");
            output.push_str("1. Migrate all RSA/ECDSA usage to ML-KEM/ML-DSA\n");
            output.push_str("2. Replace MD5/SHA-1 with SHA-256 or SHA-3\n");
            output.push_str("3. Upgrade DES/3DES to AES-256\n");
        }

        Ok(output)
    }

    /// Scan a specific GitHub repository
    async fn tool_scan_github_repo(&self, args: &Value) -> Result<String> {
        let params: ScanGitHubRepoParams =
            serde_json::from_value(args.clone()).context("Invalid parameters for scan_github_repo")?;

        let parts: Vec<&str> = params.repo.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid repo format. Use 'owner/repo'"));
        }
        let (owner, repo_name) = (parts[0], parts[1]);

        info!("Scanning repository: {}", params.repo);

        // Get repository info
        let repo_info = self.github_client.get_repository(owner, repo_name).await?;

        let mut output = String::new();
        output.push_str(&format!("# PQC Vulnerability Scan: {}\n\n", params.repo));
        output.push_str(&format!("**Repository:** {}\n", repo_info.full_name));
        if let Some(desc) = &repo_info.description {
            output.push_str(&format!("**Description:** {}\n", desc));
        }
        if let Some(lang) = &repo_info.language {
            output.push_str(&format!("**Primary Language:** {}\n", lang));
        }
        output.push_str(&format!("**Default Branch:** {}\n\n", repo_info.default_branch));

        // Find and scan files
        let files = self.github_client
            .find_scannable_files(owner, repo_name, params.max_files)
            .await?;

        output.push_str(&format!("**Scannable Files Found:** {}\n\n", files.len()));
        output.push_str("---\n\n");

        let scanner = Scanner::new();
        let mut total_vulns = 0;
        let mut all_results = Vec::new();

        for file in &files {
            match self.github_client.get_file_content(owner, repo_name, &file.path).await {
                Ok(content) => {
                    let result = scanner.scan(&content);
                    if result.summary.total > 0 {
                        total_vulns += result.summary.total;
                        all_results.push((file.path.clone(), result));
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch {}: {}", file.path, e);
                }
            }
        }

        if all_results.is_empty() {
            output.push_str("✅ **No quantum-vulnerable cryptographic algorithms detected!**\n");
        } else {
            output.push_str(&format!("⚠️ **Found {} vulnerabilities in {} files:**\n\n",
                total_vulns, all_results.len()));

            for (path, result) in &all_results {
                output.push_str(&format!("### {}\n\n", path));
                output.push_str(&format!("| Line | Algorithm | Risk | Context |\n"));
                output.push_str(&format!("|------|-----------|------|--------|\n"));

                for vuln in &result.vulnerabilities {
                    output.push_str(&format!(
                        "| {} | {} | {} | {} |\n",
                        vuln.line_number, vuln.algorithm, vuln.risk_level, vuln.context
                    ));
                }
                output.push('\n');
            }
        }

        Ok(output)
    }

    /// List repositories in a GitHub organization
    async fn tool_list_github_repos(&self, args: &Value) -> Result<String> {
        let params: ListGitHubReposParams =
            serde_json::from_value(args.clone()).context("Invalid parameters for list_github_repos")?;

        info!("Listing repositories for organization: {}", params.org);

        let repos = self.github_client.list_org_repos(&params.org).await?;

        let mut output = String::new();
        output.push_str(&format!("# Repositories in {}\n\n", params.org));
        output.push_str(&format!("**Total:** {} repositories\n\n", repos.len()));

        output.push_str("| Repository | Language | Size (KB) | Private | Description |\n");
        output.push_str("|------------|----------|-----------|---------|-------------|\n");

        for repo in &repos {
            if !params.include_archived && repo.archived {
                continue;
            }

            let lang = repo.language.as_deref().unwrap_or("-");
            let desc = repo.description.as_deref().unwrap_or("-")
                .chars().take(50).collect::<String>();
            let private = if repo.private { "Yes" } else { "No" };

            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                repo.name, lang, repo.size, private, desc
            ));
        }

        Ok(output)
    }

    /// Scan a specific file from a GitHub repository
    async fn tool_scan_github_file(&self, args: &Value) -> Result<String> {
        let params: ScanGitHubFileParams =
            serde_json::from_value(args.clone()).context("Invalid parameters for scan_github_file")?;

        let parts: Vec<&str> = params.repo.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid repo format. Use 'owner/repo'"));
        }
        let (owner, repo_name) = (parts[0], parts[1]);

        info!("Scanning file: {} in {}", params.path, params.repo);

        let content = self.github_client
            .get_file_content(owner, repo_name, &params.path)
            .await?;

        let scanner = Scanner::new();
        let result = scanner.scan(&content);

        let mut output = String::new();
        output.push_str(&format!("# PQC Scan: {}/{}\n\n", params.repo, params.path));

        let report = Scanner::format_report(&result);
        output.push_str(&report);

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
                    },
                    {
                        "name": "scan-github-org",
                        "description": "Scan all repositories in a GitHub organization",
                        "arguments": [
                            {
                                "name": "org",
                                "description": "GitHub organization name",
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
            "scan-github-org" => json!({
                "description": "Scan all repositories in a GitHub organization",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": "Please scan all repositories in the {{org}} GitHub organization for quantum-vulnerable cryptographic algorithms and provide a comprehensive report."
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

        // Should have original tools plus GitHub tools
        assert!(tools.len() >= 8);

        // Check for GitHub tools
        let tool_names: Vec<&str> = tools.iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(tool_names.contains(&"scan_github_org"));
        assert!(tool_names.contains(&"scan_github_repo"));
        assert!(tool_names.contains(&"list_github_repos"));
        assert!(tool_names.contains(&"scan_github_file"));
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
