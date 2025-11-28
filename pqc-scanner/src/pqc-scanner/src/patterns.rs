//! Vulnerability patterns for quantum-vulnerable cryptographic algorithms
//!
//! This module defines regex patterns and metadata for detecting cryptographic
//! algorithms that are vulnerable to quantum computing attacks.

use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Risk level for quantum vulnerability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Critical => write!(f, "CRITICAL"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::Low => write!(f, "LOW"),
        }
    }
}

/// Post-Quantum Cryptography alternative recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcAlternative {
    pub name: String,
    pub nist_name: String,
    pub description: String,
    pub use_case: String,
}

/// Vulnerable algorithm definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerableAlgorithm {
    pub name: String,
    pub category: String,
    pub risk_level: RiskLevel,
    pub description: String,
    pub cnsa_deadline: String,
    pub pqc_alternatives: Vec<PqcAlternative>,
}

/// Pattern for detecting vulnerable algorithms in code
#[derive(Debug, Clone)]
pub struct VulnerabilityPattern {
    pub algorithm: VulnerableAlgorithm,
    pub patterns: Vec<LanguagePattern>,
}

/// Language-specific pattern
#[derive(Debug, Clone)]
pub struct LanguagePattern {
    pub language: String,
    pub regex: Regex,
    pub context: String,
}

lazy_static! {
    /// All vulnerability patterns for scanning
    pub static ref VULNERABILITY_PATTERNS: Vec<VulnerabilityPattern> = build_patterns();
}

fn build_patterns() -> Vec<VulnerabilityPattern> {
    vec![
        // RSA - Critical (broken by Shor's algorithm)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "RSA".to_string(),
                category: "Asymmetric Encryption / Digital Signature".to_string(),
                risk_level: RiskLevel::Critical,
                description: "RSA is vulnerable to Shor's algorithm on quantum computers. A sufficiently powerful quantum computer could factor large primes and break RSA encryption.".to_string(),
                cnsa_deadline: "2030".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "ML-KEM (Kyber)".to_string(),
                        nist_name: "FIPS 203".to_string(),
                        description: "Module-Lattice-Based Key-Encapsulation Mechanism".to_string(),
                        use_case: "Key encapsulation / Key exchange".to_string(),
                    },
                    PqcAlternative {
                        name: "ML-DSA (Dilithium)".to_string(),
                        nist_name: "FIPS 204".to_string(),
                        description: "Module-Lattice-Based Digital Signature Algorithm".to_string(),
                        use_case: "Digital signatures".to_string(),
                    },
                ],
            },
            patterns: vec![
                // Python
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(RSA\.generate|RSA\.import_key|from\s+Crypto\.PublicKey\s+import\s+RSA|from\s+cryptography.*rsa|rsa\.generate_private_key|RSAPrivateKey|RSAPublicKey)").unwrap(),
                    context: "RSA key generation or import".to_string(),
                },
                // JavaScript/TypeScript
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(crypto\.generateKeyPair\s*\(\s*['"]rsa['"]|subtle\.generateKey.*RSA|new\s+RSAKey|jose.*RSA|jsonwebtoken.*RS256|RS384|RS512)"#).unwrap(),
                    context: "RSA key generation or JWT signing".to_string(),
                },
                // Java
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(KeyPairGenerator\.getInstance\s*\(\s*"RSA"|Cipher\.getInstance\s*\(\s*"RSA|RSAPublicKey|RSAPrivateKey|RSAKeyGenParameterSpec)"#).unwrap(),
                    context: "RSA cipher or key generation".to_string(),
                },
                // Go
                LanguagePattern {
                    language: "go".to_string(),
                    regex: Regex::new(r"(?i)(rsa\.GenerateKey|rsa\.EncryptPKCS1v15|rsa\.DecryptPKCS1v15|rsa\.SignPKCS1v15|x509\.ParsePKCS1PrivateKey)").unwrap(),
                    context: "RSA operations".to_string(),
                },
                // Rust
                LanguagePattern {
                    language: "rust".to_string(),
                    regex: Regex::new(r"(?i)(RsaPrivateKey::new|RsaPublicKey|rsa::pkcs1|openssl::rsa)").unwrap(),
                    context: "RSA key operations".to_string(),
                },
            ],
        },

        // ECDSA/ECC - Critical (broken by Shor's algorithm)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "ECDSA/ECC".to_string(),
                category: "Asymmetric Encryption / Digital Signature".to_string(),
                risk_level: RiskLevel::Critical,
                description: "Elliptic Curve Cryptography is vulnerable to Shor's algorithm. Quantum computers can solve the discrete logarithm problem on elliptic curves.".to_string(),
                cnsa_deadline: "2030".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "ML-DSA (Dilithium)".to_string(),
                        nist_name: "FIPS 204".to_string(),
                        description: "Module-Lattice-Based Digital Signature Algorithm".to_string(),
                        use_case: "Digital signatures".to_string(),
                    },
                    PqcAlternative {
                        name: "SLH-DSA (SPHINCS+)".to_string(),
                        nist_name: "FIPS 205".to_string(),
                        description: "Stateless Hash-Based Digital Signature Algorithm".to_string(),
                        use_case: "Digital signatures (hash-based, conservative choice)".to_string(),
                    },
                ],
            },
            patterns: vec![
                // Python
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(ec\.generate_private_key|ECDSA|EllipticCurve|SECP256R1|SECP384R1|SECP521R1|ed25519|ed448|from\s+ecdsa\s+import)").unwrap(),
                    context: "Elliptic curve key generation or signing".to_string(),
                },
                // JavaScript/TypeScript
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(subtle\.generateKey.*ECDSA|subtle\.generateKey.*ECDH|crypto\.generateKeyPair\s*\(\s*['"]ec['"]|ES256|ES384|ES512|secp256k1)"#).unwrap(),
                    context: "ECDSA/ECDH key generation".to_string(),
                },
                // Java
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(KeyPairGenerator\.getInstance\s*\(\s*"EC"|ECGenParameterSpec|ECPrivateKey|ECPublicKey|ECDSA|Signature\.getInstance\s*\(\s*".*ECDSA)"#).unwrap(),
                    context: "EC key or signature operations".to_string(),
                },
                // Go
                LanguagePattern {
                    language: "go".to_string(),
                    regex: Regex::new(r"(?i)(ecdsa\.GenerateKey|elliptic\.P256|elliptic\.P384|elliptic\.P521|ed25519\.GenerateKey)").unwrap(),
                    context: "ECDSA/Ed25519 operations".to_string(),
                },
                // Rust
                LanguagePattern {
                    language: "rust".to_string(),
                    regex: Regex::new(r"(?i)(EcdsaSigningKey|p256::|p384::|ed25519::|ecdsa::)").unwrap(),
                    context: "ECDSA operations".to_string(),
                },
            ],
        },

        // Diffie-Hellman - Critical
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "Diffie-Hellman".to_string(),
                category: "Key Exchange".to_string(),
                risk_level: RiskLevel::Critical,
                description: "Classic Diffie-Hellman key exchange is vulnerable to Shor's algorithm for solving discrete logarithms.".to_string(),
                cnsa_deadline: "2030".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "ML-KEM (Kyber)".to_string(),
                        nist_name: "FIPS 203".to_string(),
                        description: "Module-Lattice-Based Key-Encapsulation Mechanism".to_string(),
                        use_case: "Key encapsulation / Key exchange".to_string(),
                    },
                ],
            },
            patterns: vec![
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(dh\.generate_parameters|DHParameterNumbers|generate_dh|DiffieHellman)").unwrap(),
                    context: "Diffie-Hellman key exchange".to_string(),
                },
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r"(?i)(createDiffieHellman|getDiffieHellman|crypto\.diffieHellman)").unwrap(),
                    context: "Diffie-Hellman key exchange".to_string(),
                },
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(KeyAgreement\.getInstance\s*\(\s*"DH"|DHParameterSpec|DHPublicKey|DHPrivateKey)"#).unwrap(),
                    context: "Diffie-Hellman key agreement".to_string(),
                },
                LanguagePattern {
                    language: "go".to_string(),
                    regex: Regex::new(r"(?i)(dh\.GenerateKey|dh\.GenerateParameters)").unwrap(),
                    context: "Diffie-Hellman operations".to_string(),
                },
            ],
        },

        // MD5 - High (collision attacks, not quantum-specific but weak)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "MD5".to_string(),
                category: "Hash Function".to_string(),
                risk_level: RiskLevel::High,
                description: "MD5 is cryptographically broken due to collision attacks. While not specifically quantum-vulnerable, it should be replaced with stronger hash functions.".to_string(),
                cnsa_deadline: "Immediate".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "SHA-256".to_string(),
                        nist_name: "FIPS 180-4".to_string(),
                        description: "Secure Hash Algorithm 256-bit".to_string(),
                        use_case: "General purpose hashing".to_string(),
                    },
                    PqcAlternative {
                        name: "SHA-3".to_string(),
                        nist_name: "FIPS 202".to_string(),
                        description: "SHA-3 (Keccak) hash function".to_string(),
                        use_case: "General purpose hashing, quantum-resistant".to_string(),
                    },
                ],
            },
            patterns: vec![
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(hashlib\.md5|MD5\.new|from\s+Crypto\.Hash\s+import\s+MD5)").unwrap(),
                    context: "MD5 hash creation".to_string(),
                },
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(createHash\s*\(\s*['"]md5['"]|crypto-js.*MD5|md5\s*\()"#).unwrap(),
                    context: "MD5 hash creation".to_string(),
                },
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(MessageDigest\.getInstance\s*\(\s*"MD5"|DigestUtils\.md5)"#).unwrap(),
                    context: "MD5 hash creation".to_string(),
                },
                LanguagePattern {
                    language: "go".to_string(),
                    regex: Regex::new(r"(?i)(md5\.New|md5\.Sum|crypto/md5)").unwrap(),
                    context: "MD5 hash creation".to_string(),
                },
                LanguagePattern {
                    language: "rust".to_string(),
                    regex: Regex::new(r"(?i)(md5::|Md5::new|use\s+md5)").unwrap(),
                    context: "MD5 hash creation".to_string(),
                },
            ],
        },

        // SHA-1 - Medium (deprecated, collision attacks demonstrated)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "SHA-1".to_string(),
                category: "Hash Function".to_string(),
                risk_level: RiskLevel::Medium,
                description: "SHA-1 has known collision vulnerabilities (SHAttered attack). While still used in legacy systems, migration to SHA-256 or SHA-3 is recommended.".to_string(),
                cnsa_deadline: "2025".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "SHA-256".to_string(),
                        nist_name: "FIPS 180-4".to_string(),
                        description: "Secure Hash Algorithm 256-bit".to_string(),
                        use_case: "General purpose hashing".to_string(),
                    },
                    PqcAlternative {
                        name: "SHA-3".to_string(),
                        nist_name: "FIPS 202".to_string(),
                        description: "SHA-3 (Keccak) hash function".to_string(),
                        use_case: "General purpose hashing".to_string(),
                    },
                ],
            },
            patterns: vec![
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(hashlib\.sha1|SHA\.new|from\s+Crypto\.Hash\s+import\s+SHA)").unwrap(),
                    context: "SHA-1 hash creation".to_string(),
                },
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(createHash\s*\(\s*['"]sha1['"]|crypto-js.*SHA1)"#).unwrap(),
                    context: "SHA-1 hash creation".to_string(),
                },
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(MessageDigest\.getInstance\s*\(\s*"SHA-?1"|DigestUtils\.sha1)"#).unwrap(),
                    context: "SHA-1 hash creation".to_string(),
                },
                LanguagePattern {
                    language: "go".to_string(),
                    regex: Regex::new(r"(?i)(sha1\.New|sha1\.Sum|crypto/sha1)").unwrap(),
                    context: "SHA-1 hash creation".to_string(),
                },
                LanguagePattern {
                    language: "rust".to_string(),
                    regex: Regex::new(r"(?i)(sha1::|Sha1::new|use\s+sha1)").unwrap(),
                    context: "SHA-1 hash creation".to_string(),
                },
            ],
        },

        // DES - High (56-bit key, brute-forceable)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "DES".to_string(),
                category: "Symmetric Encryption".to_string(),
                risk_level: RiskLevel::High,
                description: "DES uses only 56-bit keys and is vulnerable to brute-force attacks. Grover's algorithm on quantum computers would further reduce security.".to_string(),
                cnsa_deadline: "Immediate".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "AES-256".to_string(),
                        nist_name: "FIPS 197".to_string(),
                        description: "Advanced Encryption Standard with 256-bit keys".to_string(),
                        use_case: "Symmetric encryption (quantum-resistant with 256-bit keys)".to_string(),
                    },
                ],
            },
            patterns: vec![
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(DES\.new|from\s+Crypto\.Cipher\s+import\s+DES[^3])").unwrap(),
                    context: "DES cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(createCipher\s*\(\s*['"]des['"]|crypto-js.*DES[^3])"#).unwrap(),
                    context: "DES cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(Cipher\.getInstance\s*\(\s*"DES[^e]|SecretKeySpec.*"DES")"#).unwrap(),
                    context: "DES cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "go".to_string(),
                    regex: Regex::new(r"(?i)(des\.NewCipher|crypto/des)").unwrap(),
                    context: "DES cipher creation".to_string(),
                },
            ],
        },

        // 3DES/Triple DES - Medium (deprecated, slow)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "3DES/Triple-DES".to_string(),
                category: "Symmetric Encryption".to_string(),
                risk_level: RiskLevel::Medium,
                description: "Triple-DES is deprecated by NIST. While more secure than DES, it has a 64-bit block size vulnerable to birthday attacks and is slow.".to_string(),
                cnsa_deadline: "2023 (deprecated)".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "AES-256".to_string(),
                        nist_name: "FIPS 197".to_string(),
                        description: "Advanced Encryption Standard with 256-bit keys".to_string(),
                        use_case: "Symmetric encryption".to_string(),
                    },
                ],
            },
            patterns: vec![
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(DES3\.new|from\s+Crypto\.Cipher\s+import\s+DES3|TripleDES)").unwrap(),
                    context: "Triple-DES cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(createCipher\s*\(\s*['"]des3['"]|crypto-js.*TripleDES|des-ede3)"#).unwrap(),
                    context: "Triple-DES cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(Cipher\.getInstance\s*\(\s*"DESede|TripleDES)"#).unwrap(),
                    context: "Triple-DES cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "go".to_string(),
                    regex: Regex::new(r"(?i)(des\.NewTripleDESCipher|crypto/des.*triple)").unwrap(),
                    context: "Triple-DES cipher creation".to_string(),
                },
            ],
        },

        // DSA - Critical (quantum-vulnerable)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "DSA".to_string(),
                category: "Digital Signature".to_string(),
                risk_level: RiskLevel::Critical,
                description: "DSA is vulnerable to quantum attacks via Shor's algorithm, similar to RSA and ECDSA.".to_string(),
                cnsa_deadline: "2030".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "ML-DSA (Dilithium)".to_string(),
                        nist_name: "FIPS 204".to_string(),
                        description: "Module-Lattice-Based Digital Signature Algorithm".to_string(),
                        use_case: "Digital signatures".to_string(),
                    },
                    PqcAlternative {
                        name: "SLH-DSA (SPHINCS+)".to_string(),
                        nist_name: "FIPS 205".to_string(),
                        description: "Stateless Hash-Based Digital Signature Algorithm".to_string(),
                        use_case: "Digital signatures".to_string(),
                    },
                ],
            },
            patterns: vec![
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(DSA\.generate|from\s+Crypto\.PublicKey\s+import\s+DSA|dsa\.generate_private_key)").unwrap(),
                    context: "DSA key generation".to_string(),
                },
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(crypto\.generateKeyPair\s*\(\s*['"]dsa['"])"#).unwrap(),
                    context: "DSA key generation".to_string(),
                },
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(KeyPairGenerator\.getInstance\s*\(\s*"DSA"|DSAPrivateKey|DSAPublicKey)"#).unwrap(),
                    context: "DSA key operations".to_string(),
                },
                LanguagePattern {
                    language: "go".to_string(),
                    regex: Regex::new(r"(?i)(dsa\.GenerateKey|dsa\.GenerateParameters|crypto/dsa)").unwrap(),
                    context: "DSA operations".to_string(),
                },
            ],
        },

        // RC4 - High (multiple vulnerabilities)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "RC4".to_string(),
                category: "Stream Cipher".to_string(),
                risk_level: RiskLevel::High,
                description: "RC4 has multiple known vulnerabilities and biases in its keystream. It has been prohibited for TLS and should be replaced.".to_string(),
                cnsa_deadline: "Immediate".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "AES-256-GCM".to_string(),
                        nist_name: "SP 800-38D".to_string(),
                        description: "AES in Galois/Counter Mode".to_string(),
                        use_case: "Authenticated encryption".to_string(),
                    },
                    PqcAlternative {
                        name: "ChaCha20-Poly1305".to_string(),
                        nist_name: "RFC 8439".to_string(),
                        description: "ChaCha20 stream cipher with Poly1305 authenticator".to_string(),
                        use_case: "Authenticated encryption".to_string(),
                    },
                ],
            },
            patterns: vec![
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(ARC4\.new|from\s+Crypto\.Cipher\s+import\s+ARC4)").unwrap(),
                    context: "RC4 cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(createCipher\s*\(\s*['"]rc4['"]|crypto-js.*RC4)"#).unwrap(),
                    context: "RC4 cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(Cipher\.getInstance\s*\(\s*"RC4|ARCFOUR)"#).unwrap(),
                    context: "RC4 cipher creation".to_string(),
                },
            ],
        },

        // Blowfish - Low (still secure but 64-bit block)
        VulnerabilityPattern {
            algorithm: VulnerableAlgorithm {
                name: "Blowfish".to_string(),
                category: "Symmetric Encryption".to_string(),
                risk_level: RiskLevel::Low,
                description: "Blowfish has a 64-bit block size making it vulnerable to birthday attacks when encrypting large amounts of data. Consider AES for new applications.".to_string(),
                cnsa_deadline: "Migration recommended".to_string(),
                pqc_alternatives: vec![
                    PqcAlternative {
                        name: "AES-256".to_string(),
                        nist_name: "FIPS 197".to_string(),
                        description: "Advanced Encryption Standard with 256-bit keys".to_string(),
                        use_case: "Symmetric encryption".to_string(),
                    },
                ],
            },
            patterns: vec![
                LanguagePattern {
                    language: "python".to_string(),
                    regex: Regex::new(r"(?i)(Blowfish\.new|from\s+Crypto\.Cipher\s+import\s+Blowfish)").unwrap(),
                    context: "Blowfish cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "javascript".to_string(),
                    regex: Regex::new(r#"(?i)(createCipher\s*\(\s*['"]bf['"]|crypto-js.*Blowfish)"#).unwrap(),
                    context: "Blowfish cipher creation".to_string(),
                },
                LanguagePattern {
                    language: "java".to_string(),
                    regex: Regex::new(r#"(?i)(Cipher\.getInstance\s*\(\s*"Blowfish)"#).unwrap(),
                    context: "Blowfish cipher creation".to_string(),
                },
            ],
        },
    ]
}

/// Get all detectable algorithms with their metadata
pub fn get_all_algorithms() -> Vec<VulnerableAlgorithm> {
    VULNERABILITY_PATTERNS
        .iter()
        .map(|p| p.algorithm.clone())
        .collect()
}

/// Get algorithms filtered by risk level
pub fn get_algorithms_by_risk(risk: RiskLevel) -> Vec<VulnerableAlgorithm> {
    VULNERABILITY_PATTERNS
        .iter()
        .filter(|p| p.algorithm.risk_level == risk)
        .map(|p| p.algorithm.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patterns_compile() {
        // Ensure all patterns compile successfully
        let patterns = &*VULNERABILITY_PATTERNS;
        assert!(!patterns.is_empty());
    }

    #[test]
    fn test_rsa_pattern_matches() {
        let patterns = &*VULNERABILITY_PATTERNS;
        let rsa_pattern = patterns.iter().find(|p| p.algorithm.name == "RSA").unwrap();

        let python_pattern = rsa_pattern.patterns.iter()
            .find(|p| p.language == "python").unwrap();

        assert!(python_pattern.regex.is_match("from Crypto.PublicKey import RSA"));
        assert!(python_pattern.regex.is_match("key = RSA.generate(2048)"));
    }

    #[test]
    fn test_md5_pattern_matches() {
        let patterns = &*VULNERABILITY_PATTERNS;
        let md5_pattern = patterns.iter().find(|p| p.algorithm.name == "MD5").unwrap();

        let python_pattern = md5_pattern.patterns.iter()
            .find(|p| p.language == "python").unwrap();

        assert!(python_pattern.regex.is_match("hashlib.md5(b'data')"));
    }
}
