//! PQC Scanner Library
//!
//! Post-Quantum Cryptography vulnerability scanner for detecting
//! quantum-vulnerable cryptographic algorithms in source code.

pub mod github;
pub mod mcp;
pub mod patterns;
pub mod scanner;

pub use github::{GitHubClient, Repository, ScanTarget, OrgScanProgress};
pub use patterns::{RiskLevel, VulnerableAlgorithm, PqcAlternative};
pub use scanner::{Scanner, ScanResult, Vulnerability};
