use serde::{ Deserialize, Serialize };

/// Verdict tiers, matching the Java backend's SecurityServiceImpl exactly.
/// Do not rename these variants without updating the cross-engine diff job,
/// the serialized string form is compared directly against the Java engine's
/// output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Clean => "CLEAN",
            Verdict::Suspicious => "SUSPICIOUS",
            Verdict::Malicious => "MALICIOUS",
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A single contributing signal to the final score, kept for explainability
/// (matches the Java engine's practice of citing which check fired).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreContribution {
    pub reason: String,
    pub points: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_name: String,
    pub sha256: String,
    pub verdict: Verdict,
    pub score: i32,
    pub threat_type: Option<String>,
    pub contributions: Vec<ScoreContribution>,
}
