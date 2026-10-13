//! Hostnames that may be written to the hosts file.
//!
//! The privileged helper writes `127.0.0.1 <domain> # MARKER` lines straight
//! from the strings it is sent. A string containing a newline, a space or a
//! `#` would let a caller add arbitrary hosts entries (for example pointing a
//! bank's address at an attacker), so the helper is the trust boundary and has
//! to check every name itself, whoever the caller is.
//!
//! The check is a type, not a function the writer remembers to call:
//! [`BlockedDomain`] can only be built through [`BlockedDomain::parse`], and
//! `HostsFileWriter::write` only accepts `BlockedDomain`, so an unchecked
//! string cannot reach the file.
//!
//! Deliberately strict: ASCII letters, digits, hyphens and dots only
//! (internationalized names must be given in their `xn--` form), at least two
//! labels (which also rules out `localhost`), and no all-numeric last label
//! (which rules out IP addresses).

use std::fmt;

/// Most entries the helper accepts in one request, and the most the desktop
/// app lets the user add. A hosts file with far more lines than this slows
/// name resolution for the whole machine.
pub const MAX_BLOCKED_DOMAINS: usize = 5_000;

const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// A hostname that is safe to put on one hosts-file line. Lowercase, without a
/// trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockedDomain(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidDomain {
    Empty,
    TooLong,
    EmptyLabel,
    LabelTooLong,
    InvalidCharacter(char),
    HyphenAtLabelEdge,
    SingleLabel,
    NumericLastLabel,
}

impl fmt::Display for InvalidDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "it is empty"),
            Self::TooLong => write!(f, "it is longer than {MAX_DOMAIN_LEN} characters"),
            Self::EmptyLabel => write!(f, "it has an empty part between dots"),
            Self::LabelTooLong => {
                write!(f, "a part between dots is longer than {MAX_LABEL_LEN} characters")
            }
            Self::InvalidCharacter(c) => {
                write!(f, "it contains {c:?}, only letters, digits, '-' and '.' are allowed")
            }
            Self::HyphenAtLabelEdge => write!(f, "a part between dots starts or ends with '-'"),
            Self::SingleLabel => write!(f, "it needs at least two parts, like example.com"),
            Self::NumericLastLabel => write!(f, "it looks like an IP address or number"),
        }
    }
}

impl std::error::Error for InvalidDomain {}

impl BlockedDomain {
    /// Checks and normalizes `input`. Does not trim: whitespace is rejected,
    /// so callers that accept user typing must trim first. Letters are
    /// lowercased and one trailing dot is dropped.
    pub fn parse(input: &str) -> Result<Self, InvalidDomain> {
        let name = input.strip_suffix('.').unwrap_or(input);

        if name.is_empty() {
            return Err(InvalidDomain::Empty);
        }
        if name.len() > MAX_DOMAIN_LEN {
            return Err(InvalidDomain::TooLong);
        }
        // Reject by character first so the error names the real problem
        // (a newline, a space) before any structural complaint.
        if let Some(bad) = name.chars().find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '.')) {
            return Err(InvalidDomain::InvalidCharacter(bad));
        }

        let lowered = name.to_ascii_lowercase();
        let labels: Vec<&str> = lowered.split('.').collect();

        for label in &labels {
            if label.is_empty() {
                return Err(InvalidDomain::EmptyLabel);
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(InvalidDomain::LabelTooLong);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(InvalidDomain::HyphenAtLabelEdge);
            }
        }
        if labels.len() < 2 {
            return Err(InvalidDomain::SingleLabel);
        }
        if labels.last().is_some_and(|last| last.bytes().all(|b| b.is_ascii_digit())) {
            return Err(InvalidDomain::NumericLastLabel);
        }

        Ok(Self(lowered))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BlockedDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainListError {
    TooMany { count: usize },
    Invalid { index: usize, shown: String, reason: InvalidDomain },
}

impl fmt::Display for DomainListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany { count } => {
                write!(f, "{count} entries is more than the limit of {MAX_BLOCKED_DOMAINS}")
            }
            Self::Invalid { index, shown, reason } => {
                write!(f, "entry {index} ({shown}) is not a valid hostname: {reason}")
            }
        }
    }
}

impl std::error::Error for DomainListError {}

/// Checks a whole list. All or nothing: one bad entry rejects the lot, so a
/// request can never be applied halfway. The offending text is shown with
/// Rust's debug escaping and cut to 40 characters, so a hostile entry cannot
/// forge log lines or flood a message.
pub fn parse_domain_list(raw: &[String]) -> Result<Vec<BlockedDomain>, DomainListError> {
    if raw.len() > MAX_BLOCKED_DOMAINS {
        return Err(DomainListError::TooMany { count: raw.len() });
    }
    raw.iter()
        .enumerate()
        .map(|(index, entry)| {
            BlockedDomain::parse(entry).map_err(|reason| {
                let truncated: String = entry.chars().take(40).collect();
                DomainListError::Invalid { index, shown: format!("{truncated:?}"), reason }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_hostnames_and_normalizes_them() {
        for (input, expected) in [
            ("example.com", "example.com"),
            ("Sub.Example.COM", "sub.example.com"),
            ("example.com.", "example.com"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("a-b.co", "a-b.co"),
            ("1password.com", "1password.com"),
        ] {
            assert_eq!(BlockedDomain::parse(input).unwrap().as_str(), expected, "input {input:?}");
        }
    }

    #[test]
    fn rejects_hosts_file_injection_attempts() {
        for input in [
            "ok.example.com\n1.2.3.4 bank.example",
            "ok.example.com\r\n1.2.3.4 bank.example",
            "evil.com # x",
            "evil.com#",
            "evil.com\t",
            "a\nb.com",
            "a\0.com",
            "exa mple.com",
            " example.com",
            "example.com ",
            "example.com/path",
            "http://example.com",
            "user@example.com",
            "a:80.example.com",
            "127.0.0.1 evil.com",
        ] {
            assert!(BlockedDomain::parse(input).is_err(), "must reject {input:?}");
        }
    }

    #[test]
    fn rejects_malformed_names() {
        for (input, expected) in [
            ("", InvalidDomain::Empty),
            (".", InvalidDomain::Empty),
            ("a..com", InvalidDomain::EmptyLabel),
            (".com", InvalidDomain::EmptyLabel),
            ("-a.com", InvalidDomain::HyphenAtLabelEdge),
            ("a-.com", InvalidDomain::HyphenAtLabelEdge),
            ("localhost", InvalidDomain::SingleLabel),
            ("127.0.0.1", InvalidDomain::NumericLastLabel),
            ("1.2.3.4", InvalidDomain::NumericLastLabel),
            ("example.123", InvalidDomain::NumericLastLabel),
        ] {
            assert_eq!(BlockedDomain::parse(input).unwrap_err(), expected, "input {input:?}");
        }
        assert!(matches!(BlockedDomain::parse("münchen.de"), Err(InvalidDomain::InvalidCharacter('ü'))));
        assert!(matches!(BlockedDomain::parse("a_b.com"), Err(InvalidDomain::InvalidCharacter('_'))));
    }

    #[test]
    fn enforces_length_limits() {
        let label63 = "a".repeat(63);
        assert!(BlockedDomain::parse(&format!("{label63}.com")).is_ok());
        assert_eq!(
            BlockedDomain::parse(&format!("{}.com", "a".repeat(64))).unwrap_err(),
            InvalidDomain::LabelTooLong
        );

        // 253 characters in total is the limit.
        let ok = format!("{label63}.{label63}.{label63}.{}.com", "a".repeat(57));
        assert_eq!(ok.len(), 253);
        assert!(BlockedDomain::parse(&ok).is_ok());
        let too_long = format!("{label63}.{label63}.{label63}.{}.com", "a".repeat(58));
        assert_eq!(BlockedDomain::parse(&too_long).unwrap_err(), InvalidDomain::TooLong);
    }

    /// Every ASCII character, one at a time, in the middle of a label: only
    /// letters, digits and '-' may get through. Catches any gap a hand-picked
    /// list of bad inputs would miss.
    #[test]
    fn only_letters_digits_and_hyphen_survive_inside_a_label() {
        for byte in 0u8..=127 {
            let c = byte as char;
            let candidate = format!("a{c}b.example.com");
            let allowed = c.is_ascii_alphanumeric() || c == '-' || c == '.';
            assert_eq!(
                BlockedDomain::parse(&candidate).is_ok(),
                allowed,
                "character {c:?} (0x{byte:02x}) was {}",
                if allowed { "wrongly rejected" } else { "wrongly accepted" }
            );
        }
    }

    #[test]
    fn a_list_is_all_or_nothing_and_errors_do_not_echo_raw_control_characters() {
        let list = vec!["good.example.com".to_string(), "bad\nentry.example.com".to_string()];
        let error = parse_domain_list(&list).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("entry 1"), "{message}");
        assert!(!message.contains('\n'), "the message must not contain a raw newline: {message:?}");
    }

    #[test]
    fn a_long_hostile_entry_is_truncated_in_the_error() {
        let list = vec![format!("{}\n", "x".repeat(10_000))];
        let message = parse_domain_list(&list).unwrap_err().to_string();
        assert!(message.len() < 300, "message was {} characters", message.len());
    }

    #[test]
    fn rejects_lists_over_the_limit_and_accepts_an_empty_list() {
        assert_eq!(parse_domain_list(&[]).unwrap(), vec![]);

        let too_many: Vec<String> = (0..=MAX_BLOCKED_DOMAINS).map(|i| format!("d{i}.example.com")).collect();
        assert_eq!(
            parse_domain_list(&too_many).unwrap_err(),
            DomainListError::TooMany { count: MAX_BLOCKED_DOMAINS + 1 }
        );
        assert_eq!(parse_domain_list(&too_many[..MAX_BLOCKED_DOMAINS]).unwrap().len(), MAX_BLOCKED_DOMAINS);
    }
}
