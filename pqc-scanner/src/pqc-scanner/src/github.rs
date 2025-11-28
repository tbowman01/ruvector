//! GitHub API client for organization and repository scanning
//!
//! Provides functionality to:
//! - List all repositories in a GitHub organization
//! - Fetch file contents from repositories
//! - Search for code files to scan
//! - Handle pagination and rate limiting

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures::future::join_all;
use reqwest::{header, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// GitHub API base URL
const GITHUB_API_BASE: &str = "https://api.github.com";

/// File extensions to scan for cryptographic code
const SCANNABLE_EXTENSIONS: &[&str] = &[
    "py", "js", "ts", "jsx", "tsx", "java", "go", "rs", "rb", "php",
    "cs", "cpp", "c", "h", "hpp", "swift", "kt", "scala", "sh", "bash",
];

/// Maximum concurrent API requests
const MAX_CONCURRENT_REQUESTS: usize = 10;

/// GitHub API client
#[derive(Clone)]
pub struct GitHubClient {
    client: Client,
    token: Option<String>,
    semaphore: Arc<Semaphore>,
}

/// Repository information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub id: u64,
    pub name: String,
    pub full_name: String,
    pub description: Option<String>,
    pub default_branch: String,
    pub language: Option<String>,
    pub private: bool,
    pub html_url: String,
    pub size: u64,
    pub archived: bool,
    pub disabled: bool,
}

/// File in a repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoFile {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub file_type: String,
    pub sha: String,
    pub size: Option<u64>,
    pub url: String,
    pub download_url: Option<String>,
}

/// File content response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContent {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub size: u64,
    pub content: Option<String>,
    pub encoding: Option<String>,
}

/// Organization info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub login: String,
    pub id: u64,
    pub description: Option<String>,
    pub public_repos: u32,
    pub total_private_repos: Option<u32>,
}

/// Scan target - a file to be scanned
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    pub repo: String,
    pub path: String,
    pub content: String,
    pub language: Option<String>,
}

/// Organization scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgScanProgress {
    pub org: String,
    pub total_repos: usize,
    pub scanned_repos: usize,
    pub total_files: usize,
    pub scanned_files: usize,
    pub errors: Vec<String>,
}

impl GitHubClient {
    /// Create a new GitHub client
    pub fn new(token: Option<String>) -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/vnd.github.v3+json"),
        );
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("pqc-scanner/0.1.0"),
        );

        if let Some(ref token) = token {
            if let Ok(auth_value) = header::HeaderValue::from_str(&format!("Bearer {}", token)) {
                headers.insert(header::AUTHORIZATION, auth_value);
            }
        }

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            token,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        }
    }

    /// Check if client is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// Get organization info
    pub async fn get_organization(&self, org: &str) -> Result<Organization> {
        let url = format!("{}/orgs/{}", GITHUB_API_BASE, org);
        let _permit = self.semaphore.acquire().await?;

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch organization")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error {}: {}", status, body);
        }

        response
            .json::<Organization>()
            .await
            .context("Failed to parse organization response")
    }

    /// List all repositories in an organization
    pub async fn list_org_repos(&self, org: &str) -> Result<Vec<Repository>> {
        let mut repos = Vec::new();
        let mut page = 1;
        let per_page = 100;

        loop {
            let url = format!(
                "{}/orgs/{}/repos?per_page={}&page={}&type=all",
                GITHUB_API_BASE, org, per_page, page
            );

            let _permit = self.semaphore.acquire().await?;

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .context("Failed to fetch repositories")?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                anyhow::bail!("GitHub API error {}: {}", status, body);
            }

            let page_repos: Vec<Repository> = response
                .json()
                .await
                .context("Failed to parse repositories response")?;

            let count = page_repos.len();
            repos.extend(page_repos);

            info!("Fetched page {} with {} repos (total: {})", page, count, repos.len());

            if count < per_page {
                break;
            }

            page += 1;

            // Rate limit protection
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Filter out archived and disabled repos
        let active_repos: Vec<Repository> = repos
            .into_iter()
            .filter(|r| !r.archived && !r.disabled)
            .collect();

        Ok(active_repos)
    }

    /// List files in a repository directory (recursive)
    pub async fn list_repo_files(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> Result<Vec<RepoFile>> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}",
            GITHUB_API_BASE, owner, repo, path
        );

        let _permit = self.semaphore.acquire().await?;

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch repository contents")?;

        if !response.status().is_success() {
            let status = response.status();
            if status.as_u16() == 404 {
                return Ok(Vec::new());
            }
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error {}: {}", status, body);
        }

        // GitHub returns either a single object or an array
        let text = response.text().await?;

        if text.starts_with('[') {
            serde_json::from_str(&text).context("Failed to parse file list")
        } else {
            let file: RepoFile = serde_json::from_str(&text)?;
            Ok(vec![file])
        }
    }

    /// Recursively find all scannable files in a repository
    pub async fn find_scannable_files(
        &self,
        owner: &str,
        repo: &str,
        max_files: usize,
    ) -> Result<Vec<RepoFile>> {
        let mut all_files = Vec::new();
        let mut dirs_to_scan = vec!["".to_string()];

        while !dirs_to_scan.is_empty() && all_files.len() < max_files {
            let dir = dirs_to_scan.pop().unwrap();

            match self.list_repo_files(owner, repo, &dir).await {
                Ok(files) => {
                    for file in files {
                        if file.file_type == "dir" {
                            // Skip common non-code directories
                            if !should_skip_directory(&file.name) {
                                dirs_to_scan.push(file.path.clone());
                            }
                        } else if file.file_type == "file" && is_scannable_file(&file.name) {
                            // Check file size (skip very large files)
                            if file.size.unwrap_or(0) < 500_000 {
                                all_files.push(file);
                            }
                        }

                        if all_files.len() >= max_files {
                            break;
                        }
                    }
                }
                Err(e) => {
                    debug!("Error listing directory {}: {}", dir, e);
                }
            }

            // Rate limit protection
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Ok(all_files)
    }

    /// Get file content from a repository
    pub async fn get_file_content(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
    ) -> Result<String> {
        let url = format!(
            "{}/repos/{}/{}/contents/{}",
            GITHUB_API_BASE, owner, repo, path
        );

        let _permit = self.semaphore.acquire().await?;

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch file content")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error {}: {}", status, body);
        }

        let content: FileContent = response.json().await?;

        // Decode base64 content
        if let (Some(encoded), Some(encoding)) = (&content.content, &content.encoding) {
            if encoding == "base64" {
                let cleaned = encoded.replace('\n', "");
                let decoded = STANDARD
                    .decode(&cleaned)
                    .context("Failed to decode base64 content")?;
                return String::from_utf8(decoded).context("File is not valid UTF-8");
            }
        }

        anyhow::bail!("Unexpected content format")
    }

    /// Scan all repositories in an organization
    pub async fn scan_organization(
        &self,
        org: &str,
        max_files_per_repo: usize,
    ) -> Result<Vec<ScanTarget>> {
        info!("Starting scan of organization: {}", org);

        // Get all repos
        let repos = self.list_org_repos(org).await?;
        info!("Found {} repositories to scan", repos.len());

        let mut all_targets = Vec::new();

        for repo in repos {
            info!("Scanning repository: {}", repo.full_name);

            // Parse owner/repo
            let parts: Vec<&str> = repo.full_name.split('/').collect();
            if parts.len() != 2 {
                continue;
            }
            let (owner, repo_name) = (parts[0], parts[1]);

            // Find scannable files
            match self.find_scannable_files(owner, repo_name, max_files_per_repo).await {
                Ok(files) => {
                    info!("Found {} scannable files in {}", files.len(), repo.full_name);

                    // Fetch content for each file concurrently
                    let futures: Vec<_> = files
                        .iter()
                        .take(max_files_per_repo)
                        .map(|file| {
                            let owner = owner.to_string();
                            let repo_name = repo_name.to_string();
                            let path = file.path.clone();
                            let full_name = repo.full_name.clone();
                            let client = self.clone();

                            async move {
                                match client.get_file_content(&owner, &repo_name, &path).await {
                                    Ok(content) => Some(ScanTarget {
                                        repo: full_name,
                                        path,
                                        content,
                                        language: detect_language_from_path(&file.name),
                                    }),
                                    Err(e) => {
                                        warn!("Failed to fetch {}: {}", path, e);
                                        None
                                    }
                                }
                            }
                        })
                        .collect();

                    let results = join_all(futures).await;
                    all_targets.extend(results.into_iter().flatten());
                }
                Err(e) => {
                    warn!("Failed to list files in {}: {}", repo.full_name, e);
                }
            }

            // Rate limit protection between repos
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        info!(
            "Collected {} files to scan from {} repos",
            all_targets.len(),
            repos.len()
        );

        Ok(all_targets)
    }

    /// List a single repository
    pub async fn get_repository(&self, owner: &str, repo: &str) -> Result<Repository> {
        let url = format!("{}/repos/{}/{}", GITHUB_API_BASE, owner, repo);
        let _permit = self.semaphore.acquire().await?;

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch repository")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("GitHub API error {}: {}", status, body);
        }

        response
            .json::<Repository>()
            .await
            .context("Failed to parse repository response")
    }
}

/// Check if a file should be scanned based on extension
fn is_scannable_file(filename: &str) -> bool {
    if let Some(ext) = filename.rsplit('.').next() {
        SCANNABLE_EXTENSIONS.contains(&ext.to_lowercase().as_str())
    } else {
        false
    }
}

/// Check if a directory should be skipped
fn should_skip_directory(name: &str) -> bool {
    const SKIP_DIRS: &[&str] = &[
        "node_modules",
        "vendor",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        "target",
        "build",
        "dist",
        ".next",
        ".nuxt",
        "coverage",
        ".cache",
        "tmp",
        "temp",
    ];

    SKIP_DIRS.contains(&name.to_lowercase().as_str())
}

/// Detect language from file path
fn detect_language_from_path(filename: &str) -> Option<String> {
    let ext = filename.rsplit('.').next()?;
    match ext.to_lowercase().as_str() {
        "py" => Some("python".to_string()),
        "js" | "jsx" | "ts" | "tsx" => Some("javascript".to_string()),
        "java" => Some("java".to_string()),
        "go" => Some("go".to_string()),
        "rs" => Some("rust".to_string()),
        "rb" => Some("ruby".to_string()),
        "php" => Some("php".to_string()),
        "cs" => Some("csharp".to_string()),
        "cpp" | "cc" | "cxx" | "c" | "h" | "hpp" => Some("cpp".to_string()),
        "swift" => Some("swift".to_string()),
        "kt" | "kts" => Some("kotlin".to_string()),
        "scala" => Some("scala".to_string()),
        "sh" | "bash" => Some("bash".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_scannable_file() {
        assert!(is_scannable_file("main.py"));
        assert!(is_scannable_file("index.js"));
        assert!(is_scannable_file("App.tsx"));
        assert!(is_scannable_file("Main.java"));
        assert!(!is_scannable_file("README.md"));
        assert!(!is_scannable_file("image.png"));
    }

    #[test]
    fn test_should_skip_directory() {
        assert!(should_skip_directory("node_modules"));
        assert!(should_skip_directory(".git"));
        assert!(should_skip_directory("vendor"));
        assert!(!should_skip_directory("src"));
        assert!(!should_skip_directory("lib"));
    }

    #[test]
    fn test_detect_language() {
        assert_eq!(detect_language_from_path("main.py"), Some("python".to_string()));
        assert_eq!(detect_language_from_path("index.js"), Some("javascript".to_string()));
        assert_eq!(detect_language_from_path("Main.java"), Some("java".to_string()));
        assert_eq!(detect_language_from_path("README.md"), None);
    }
}
