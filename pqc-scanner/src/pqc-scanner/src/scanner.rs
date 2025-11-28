//! PQC vulnerability scanner engine
//!
//! Scans source code for quantum-vulnerable cryptographic algorithms
//! and provides migration recommendations.

use crate::patterns::{LanguagePattern, RiskLevel, VulnerableAlgorithm, VULNERABILITY_PATTERNS};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A detected vulnerability in the code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    /// Algorithm name (e.g., "RSA", "MD5")
    pub algorithm: String,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Line number where detected (1-indexed)
    pub line_number: usize,
    /// The matching code snippet
    pub code_snippet: String,
    /// Context description
    pub context: String,
    /// Full algorithm metadata
    pub algorithm_info: VulnerableAlgorithm,
}

/// Scan result summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Total lines scanned
    pub lines_scanned: usize,
    /// Detected language (best guess)
    pub detected_language: Option<String>,
    /// All vulnerabilities found
    pub vulnerabilities: Vec<Vulnerability>,
    /// Summary by risk level
    pub summary: ScanSummary,
    /// Overall compliance status
    pub cnsa_compliant: bool,
}

/// Summary statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}

/// Code scanner
pub struct Scanner {
    /// Language hint (optional)
    language_hint: Option<String>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new()
    }
}

impl Scanner {
    pub fn new() -> Self {
        Self {
            language_hint: None,
        }
    }

    /// Set a language hint to prioritize certain patterns
    pub fn with_language_hint(mut self, language: impl Into<String>) -> Self {
        self.language_hint = Some(language.into().to_lowercase());
        self
    }

    /// Detect the programming language from code content
    pub fn detect_language(&self, code: &str) -> Option<String> {
        // Simple heuristic-based language detection
        let code_lower = code.to_lowercase();

        // Check for language-specific patterns
        let mut scores: HashMap<&str, i32> = HashMap::new();

        // Python indicators
        if code.contains("import ") && code.contains("def ") {
            *scores.entry("python").or_insert(0) += 3;
        }
        if code.contains("from ") && code.contains(" import ") {
            *scores.entry("python").or_insert(0) += 2;
        }
        if code_lower.contains("hashlib") || code_lower.contains("crypto.cipher") {
            *scores.entry("python").or_insert(0) += 2;
        }

        // JavaScript/TypeScript indicators
        if code.contains("const ") || code.contains("let ") || code.contains("var ") {
            *scores.entry("javascript").or_insert(0) += 2;
        }
        if code.contains("require(") || code.contains("import {") {
            *scores.entry("javascript").or_insert(0) += 2;
        }
        if code.contains("crypto.") && code.contains("createHash") {
            *scores.entry("javascript").or_insert(0) += 3;
        }

        // Java indicators
        if code.contains("public class ") || code.contains("private ") {
            *scores.entry("java").or_insert(0) += 2;
        }
        if code.contains("import java.") || code.contains("javax.crypto") {
            *scores.entry("java").or_insert(0) += 3;
        }
        if code.contains("MessageDigest.getInstance") {
            *scores.entry("java").or_insert(0) += 3;
        }

        // Go indicators
        if code.contains("package ") && code.contains("func ") {
            *scores.entry("go").or_insert(0) += 3;
        }
        if code.contains("import (") || code.contains("crypto/") {
            *scores.entry("go").or_insert(0) += 2;
        }

        // Rust indicators
        if code.contains("fn ") && code.contains("let ") && code.contains("->") {
            *scores.entry("rust").or_insert(0) += 3;
        }
        if code.contains("use ") && code.contains("::") {
            *scores.entry("rust").or_insert(0) += 2;
        }

        // Return language with highest score
        scores
            .into_iter()
            .max_by_key(|(_, score)| *score)
            .filter(|(_, score)| *score >= 2)
            .map(|(lang, _)| lang.to_string())
    }

    /// Scan code for vulnerabilities
    pub fn scan(&self, code: &str) -> ScanResult {
        let lines: Vec<&str> = code.lines().collect();
        let lines_scanned = lines.len();

        // Detect language
        let detected_language = self
            .language_hint
            .clone()
            .or_else(|| self.detect_language(code));

        let mut vulnerabilities = Vec::new();

        // Scan each line against all patterns
        for (line_idx, line) in lines.iter().enumerate() {
            let line_number = line_idx + 1; // 1-indexed

            for vuln_pattern in VULNERABILITY_PATTERNS.iter() {
                // Get patterns for detected language, or all patterns
                let patterns_to_check: Vec<&LanguagePattern> = if let Some(ref lang) =
                    detected_language
                {
                    vuln_pattern
                        .patterns
                        .iter()
                        .filter(|p| p.language == *lang)
                        .collect()
                } else {
                    vuln_pattern.patterns.iter().collect()
                };

                for pattern in patterns_to_check {
                    if pattern.regex.is_match(line) {
                        vulnerabilities.push(Vulnerability {
                            algorithm: vuln_pattern.algorithm.name.clone(),
                            risk_level: vuln_pattern.algorithm.risk_level,
                            line_number,
                            code_snippet: line.trim().to_string(),
                            context: pattern.context.clone(),
                            algorithm_info: vuln_pattern.algorithm.clone(),
                        });
                        // Only match once per line per algorithm
                        break;
                    }
                }
            }
        }

        // Calculate summary
        let summary = ScanSummary {
            critical: vulnerabilities
                .iter()
                .filter(|v| v.risk_level == RiskLevel::Critical)
                .count(),
            high: vulnerabilities
                .iter()
                .filter(|v| v.risk_level == RiskLevel::High)
                .count(),
            medium: vulnerabilities
                .iter()
                .filter(|v| v.risk_level == RiskLevel::Medium)
                .count(),
            low: vulnerabilities
                .iter()
                .filter(|v| v.risk_level == RiskLevel::Low)
                .count(),
            total: vulnerabilities.len(),
        };

        // CNSA 2.0 compliant if no critical vulnerabilities
        let cnsa_compliant = summary.critical == 0 && summary.high == 0;

        ScanResult {
            lines_scanned,
            detected_language,
            vulnerabilities,
            summary,
            cnsa_compliant,
        }
    }

    /// Format scan result as human-readable report
    pub fn format_report(result: &ScanResult) -> String {
        let mut report = String::new();

        // Header
        report.push_str("═══════════════════════════════════════════════════════════════\n");
        report.push_str("                   PQC VULNERABILITY SCAN REPORT                \n");
        report.push_str("═══════════════════════════════════════════════════════════════\n\n");

        // Summary
        report.push_str(&format!("Lines scanned: {}\n", result.lines_scanned));
        if let Some(ref lang) = result.detected_language {
            report.push_str(&format!("Detected language: {}\n", lang));
        }
        report.push_str(&format!(
            "CNSA 2.0 Compliant: {}\n\n",
            if result.cnsa_compliant { "✓ YES" } else { "✗ NO" }
        ));

        // Risk summary
        report.push_str("─────────────────────────────────────────────────────────────────\n");
        report.push_str("                         RISK SUMMARY                            \n");
        report.push_str("─────────────────────────────────────────────────────────────────\n");
        report.push_str(&format!("  CRITICAL: {}\n", result.summary.critical));
        report.push_str(&format!("  HIGH:     {}\n", result.summary.high));
        report.push_str(&format!("  MEDIUM:   {}\n", result.summary.medium));
        report.push_str(&format!("  LOW:      {}\n", result.summary.low));
        report.push_str(&format!("  TOTAL:    {}\n\n", result.summary.total));

        if result.vulnerabilities.is_empty() {
            report.push_str("No quantum-vulnerable cryptographic algorithms detected.\n");
            return report;
        }

        // Detailed findings
        report.push_str("─────────────────────────────────────────────────────────────────\n");
        report.push_str("                      DETAILED FINDINGS                          \n");
        report.push_str("─────────────────────────────────────────────────────────────────\n\n");

        for (i, vuln) in result.vulnerabilities.iter().enumerate() {
            report.push_str(&format!("{}. {} [{}]\n", i + 1, vuln.algorithm, vuln.risk_level));
            report.push_str(&format!("   Line {}: {}\n", vuln.line_number, vuln.code_snippet));
            report.push_str(&format!("   Context: {}\n", vuln.context));
            report.push_str(&format!(
                "   CNSA 2.0 Deadline: {}\n",
                vuln.algorithm_info.cnsa_deadline
            ));
            report.push_str("   Recommended alternatives:\n");
            for alt in &vuln.algorithm_info.pqc_alternatives {
                report.push_str(&format!("     • {} ({})\n", alt.name, alt.nist_name));
                report.push_str(&format!("       Use case: {}\n", alt.use_case));
            }
            report.push('\n');
        }

        // Migration guidance
        report.push_str("─────────────────────────────────────────────────────────────────\n");
        report.push_str("                    MIGRATION GUIDANCE                           \n");
        report.push_str("─────────────────────────────────────────────────────────────────\n\n");
        report.push_str("1. Prioritize CRITICAL and HIGH risk items for immediate action\n");
        report.push_str("2. For RSA/ECDSA: Migrate to ML-KEM (FIPS 203) or ML-DSA (FIPS 204)\n");
        report.push_str("3. For hash functions: Use SHA-256 or SHA-3 minimum\n");
        report.push_str("4. For symmetric encryption: Use AES-256 with proper modes\n");
        report.push_str("5. Consider crypto-agility for easier future migrations\n\n");
        report.push_str("References:\n");
        report.push_str("  • NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography\n");
        report.push_str("  • NSA CNSA 2.0: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF\n");

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_python() {
        let scanner = Scanner::new();
        let code = r#"
from Crypto.PublicKey import RSA
import hashlib

def generate_key():
    key = RSA.generate(2048)
    return key
"#;
        assert_eq!(scanner.detect_language(code), Some("python".to_string()));
    }

    #[test]
    fn test_scan_rsa_python() {
        let scanner = Scanner::new();
        let code = r#"
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
"#;
        let result = scanner.scan(code);

        assert!(result.summary.critical > 0);
        assert!(!result.cnsa_compliant);

        let rsa_vuln = result
            .vulnerabilities
            .iter()
            .find(|v| v.algorithm == "RSA");
        assert!(rsa_vuln.is_some());
    }

    #[test]
    fn test_scan_md5_python() {
        let scanner = Scanner::new();
        let code = r#"
import hashlib
h = hashlib.md5(b"data")
"#;
        let result = scanner.scan(code);

        assert!(result.summary.high > 0);

        let md5_vuln = result
            .vulnerabilities
            .iter()
            .find(|v| v.algorithm == "MD5");
        assert!(md5_vuln.is_some());
    }

    #[test]
    fn test_scan_clean_code() {
        let scanner = Scanner::new();
        let code = r#"
import hashlib
h = hashlib.sha256(b"data")
"#;
        let result = scanner.scan(code);

        assert_eq!(result.summary.total, 0);
        assert!(result.cnsa_compliant);
    }

    #[test]
    fn test_scan_multiple_vulnerabilities() {
        let scanner = Scanner::new();
        let code = r#"
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
import hashlib

key = RSA.generate(2048)
h1 = MD5.new()
h2 = hashlib.sha1(b"data")
"#;
        let result = scanner.scan(code);

        // Should detect RSA (critical), MD5 (high), SHA-1 (medium)
        assert!(result.summary.critical >= 1);
        assert!(result.summary.high >= 1);
        assert!(result.summary.medium >= 1);
        assert!(!result.cnsa_compliant);
    }

    #[test]
    fn test_format_report() {
        let scanner = Scanner::new();
        let code = "key = RSA.generate(2048)";
        let result = scanner.scan(code);
        let report = Scanner::format_report(&result);

        assert!(report.contains("PQC VULNERABILITY SCAN REPORT"));
        assert!(report.contains("RSA"));
        assert!(report.contains("CRITICAL"));
    }
}
