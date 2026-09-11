use yara_x::{Compiler, Rules, Scanner};

/// A compiled rule set, wraps yara-x::Rules. Kept as its own type so the rest
/// of the crate depends on this thin wrapper, not on yara-x's API directly,
/// this is the seam to swap the engine later if ever needed without
/// rewriting scoring.rs.
pub struct RuleSet {
    rules: Rules,
}

#[derive(Debug)]
pub struct MatchedRule {
    pub identifier: String,
}

impl RuleSet {
    /// Compiles a YARA-X source string into a RuleSet. Source, not a path,
    /// so callers control whether rules come from an embedded default set or
    /// a file on disk.
    pub fn compile(source: &str) -> Result<Self, String> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(source)
            .map_err(|e| format!("YARA-X rule compilation failed: {e}"))?;
        let rules = compiler.build();
        Ok(Self { rules })
    }

    /// Scans a buffer and returns the identifiers of every rule that
    /// matched. Empty result means no pattern-based match, not "clean",
    /// that determination belongs to scoring.rs, this module only reports
    /// matches.
    pub fn scan(&self, data: &[u8]) -> Result<Vec<MatchedRule>, String> {
        let mut scanner = Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| format!("YARA-X scan failed: {e}"))?;
        Ok(results
            .matching_rules()
            .map(|r| MatchedRule {
                identifier: r.identifier().to_string(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_a_simple_string_rule() {
        let rules = RuleSet::compile(
            r#"
            rule contains_marker {
                strings:
                    $a = "MALWARE_MARKER"
                condition:
                    $a
            }
            "#,
        )
        .expect("rule should compile");

        let matches = rules
            .scan(b"some bytes MALWARE_MARKER more bytes")
            .expect("scan should succeed");

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].identifier, "contains_marker");
    }

    #[test]
    fn no_match_on_clean_content() {
        let rules = RuleSet::compile(
            r#"
            rule contains_marker {
                strings:
                    $a = "MALWARE_MARKER"
                condition:
                    $a
            }
            "#,
        )
        .expect("rule should compile");

        let matches = rules
            .scan(b"perfectly ordinary file contents")
            .expect("scan should succeed");

        assert!(matches.is_empty());
    }

    #[test]
    fn invalid_rule_source_fails_to_compile() {
        let result = RuleSet::compile("this is not valid YARA syntax {{{");
        assert!(result.is_err());
    }
}
