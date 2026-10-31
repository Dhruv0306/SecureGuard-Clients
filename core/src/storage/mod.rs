use crate::types::{ ScanResult, Verdict };
use rusqlite::{ params, Connection, OptionalExtension, Result as SqliteResult };

pub fn open(path: &str) -> SqliteResult<Connection> {
    let conn = Connection::open(path)?;
    init_schema(&conn)?;
    Ok(conn)
}

pub fn open_in_memory() -> SqliteResult<Connection> {
    let conn = Connection::open_in_memory()?;
    init_schema(&conn)?;
    Ok(conn)
}

fn init_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(include_str!("migrations/0001_init.sql"))
}

pub fn record_scan(conn: &Connection, result: &ScanResult) -> SqliteResult<()> {
    conn.execute(
        "INSERT INTO scan_results (file_name, sha256, verdict, score, threat_type, scanned_at)
         VALUES (?1, ?2, ?3, ?4, ?5, strftime('%s','now'))",
        params![
            result.file_name,
            result.sha256,
            result.verdict.as_str(),
            result.score,
            result.threat_type
        ]
    )?;
    Ok(())
}

/// Records many results in one transaction: one commit instead of one per row,
/// which matters when a folder scan reports hundreds of findings.
pub fn record_scans(conn: &Connection, results: &[ScanResult]) -> SqliteResult<()> {
    if results.is_empty() {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    {
        let mut insert = tx.prepare(
            "INSERT INTO scan_results (file_name, sha256, verdict, score, threat_type, scanned_at)
             VALUES (?1, ?2, ?3, ?4, ?5, strftime('%s','now'))"
        )?;
        for result in results {
            insert.execute(
                params![
                    result.file_name,
                    result.sha256,
                    result.verdict.as_str(),
                    result.score,
                    result.threat_type
                ]
            )?;
        }
    }
    tx.commit()
}

pub fn recent_scans(conn: &Connection, limit: i64) -> SqliteResult<Vec<ScanResult>> {
    let mut stmt = conn.prepare(
        "SELECT file_name, sha256, verdict, score, threat_type
         FROM scan_results ORDER BY scanned_at DESC, rowid DESC LIMIT ?1"
    )?;
    let rows = stmt.query_map(params![limit], |row| {
        let verdict_str: String = row.get(2)?;
        Ok(ScanResult {
            file_name: row.get(0)?,
            sha256: row.get(1)?,
            verdict: parse_verdict(&verdict_str),
            score: row.get(3)?,
            threat_type: row.get(4)?,
            contributions: Vec::new(), // not persisted in Phase 1, see open questions
        })
    })?;
    rows.collect()
}

fn parse_verdict(s: &str) -> Verdict {
    match s {
        "MALICIOUS" => Verdict::Malicious,
        "SUSPICIOUS" => Verdict::Suspicious,
        _ => Verdict::Clean,
    }
}

/// Ported concept from Phase 4's design: presence in this table is the only
/// signal of "active", no separate is_active flag like the Java schema has,
/// see docs/phase4-desktop-privileged-helper-plan.md for why that's a
/// deliberate simplification, not an oversight.
pub fn add_blocked_domain(
    conn: &Connection,
    domain: &str,
    reason: Option<&str>
) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR REPLACE INTO blocked_domains (domain, reason, added_at)
         VALUES (?1, ?2, strftime('%s','now'))",
        params![domain, reason]
    )?;
    Ok(())
}

pub fn remove_blocked_domain(conn: &Connection, domain: &str) -> SqliteResult<()> {
    conn.execute("DELETE FROM blocked_domains WHERE domain = ?1", params![domain])?;
    Ok(())
}

pub fn list_blocked_domains(conn: &Connection) -> SqliteResult<Vec<String>> {
    // Ordered by rowid, not added_at: added_at has only second resolution,
    // two domains added within the same second would tie and risk a
    // nondeterministic order. rowid is monotonic per insert on a normal
    // (non-WITHOUT-ROWID) table, guaranteeing insertion order exactly.
    let mut stmt = conn.prepare("SELECT domain FROM blocked_domains ORDER BY rowid ASC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect()
}

/// When a feed was last fetched (Unix seconds), or `None` if it never was. The
/// sync cooldown reads this so a restart cannot bypass it.
pub fn last_feed_attempt(conn: &Connection, feed: &str) -> SqliteResult<Option<i64>> {
    conn.query_row(
        "SELECT last_attempt_at FROM feed_sync WHERE feed = ?1",
        params![feed],
        |row| row.get(0)
    ).optional()
}

/// Records the time of a fetch attempt for a feed, replacing any earlier time.
pub fn record_feed_attempt(conn: &Connection, feed: &str, at: i64) -> SqliteResult<()> {
    conn.execute(
        "INSERT INTO feed_sync (feed, last_attempt_at) VALUES (?1, ?2)
         ON CONFLICT(feed) DO UPDATE SET last_attempt_at = excluded.last_attempt_at",
        params![feed, at]
    )?;
    Ok(())
}

/// Forgets a feed's last attempt, so its next fetch is allowed at once.
pub fn clear_feed_attempt(conn: &Connection, feed: &str) -> SqliteResult<()> {
    conn.execute("DELETE FROM feed_sync WHERE feed = ?1", params![feed])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ScoreContribution;

    fn sample_result(name: &str, verdict: Verdict) -> ScanResult {
        ScanResult {
            file_name: name.to_string(),
            sha256: "deadbeef".to_string(),
            verdict,
            score: 42,
            threat_type: Some("TEST".to_string()),
            contributions: vec![ScoreContribution {
                reason: "test".to_string(),
                points: 42,
            }],
        }
    }

    #[test]
    fn records_and_retrieves_a_scan() {
        let conn = open_in_memory().unwrap();
        record_scan(&conn, &sample_result("a.txt", Verdict::Clean)).unwrap();
        let scans = recent_scans(&conn, 10).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].file_name, "a.txt");
        assert_eq!(scans[0].verdict, Verdict::Clean);
    }

    #[test]
    fn recent_scans_respects_limit_and_order() {
        let conn = open_in_memory().unwrap();
        for i in 0..5 {
            record_scan(&conn, &sample_result(&format!("f{i}.txt"), Verdict::Suspicious)).unwrap();
        }
        let scans = recent_scans(&conn, 3).unwrap();
        assert_eq!(scans.len(), 3);
        // Most recently inserted should come first.
        assert_eq!(scans[0].file_name, "f4.txt");
    }

    #[test]
    fn record_scans_inserts_every_result_and_newest_comes_first_within_one_second() {
        let conn = open_in_memory().unwrap();
        let batch: Vec<ScanResult> = (0..4)
            .map(|i| sample_result(&format!("batch{i}.txt"), Verdict::Malicious))
            .collect();
        record_scans(&conn, &batch).unwrap();
        record_scans(&conn, &[]).unwrap();

        let all = recent_scans(&conn, 10).unwrap();
        assert_eq!(all.len(), 4);
        // Same-second inserts tie on time; the last one inserted must still be first.
        assert_eq!(all[0].file_name, "batch3.txt");
        assert_eq!(all[3].file_name, "batch0.txt");
    }

    #[test]
    fn adds_and_lists_blocked_domains() {
        let conn = open_in_memory().unwrap();
        add_blocked_domain(&conn, "malware.example.com", Some("test")).unwrap();
        add_blocked_domain(&conn, "phishing.example.com", None).unwrap();

        let domains = list_blocked_domains(&conn).unwrap();
        assert_eq!(domains, vec!["malware.example.com", "phishing.example.com"]);
    }

    #[test]
    fn removing_a_blocked_domain_drops_it_from_the_active_list() {
        let conn = open_in_memory().unwrap();
        add_blocked_domain(&conn, "malware.example.com", None).unwrap();
        remove_blocked_domain(&conn, "malware.example.com").unwrap();

        let domains = list_blocked_domains(&conn).unwrap();
        assert!(domains.is_empty());
    }

    #[test]
    fn adding_the_same_domain_twice_does_not_duplicate_it() {
        let conn = open_in_memory().unwrap();
        add_blocked_domain(&conn, "malware.example.com", Some("first")).unwrap();
        add_blocked_domain(&conn, "malware.example.com", Some("updated reason")).unwrap();

        let domains = list_blocked_domains(&conn).unwrap();
        assert_eq!(domains.len(), 1);
    }

    #[test]
    fn feed_attempt_is_none_until_recorded() {
        let conn = open_in_memory().unwrap();
        assert_eq!(last_feed_attempt(&conn, "f").unwrap(), None);

        record_feed_attempt(&conn, "f", 100).unwrap();

        assert_eq!(last_feed_attempt(&conn, "f").unwrap(), Some(100));
    }

    #[test]
    fn recording_again_replaces_the_time() {
        let conn = open_in_memory().unwrap();
        record_feed_attempt(&conn, "f", 100).unwrap();
        record_feed_attempt(&conn, "f", 250).unwrap();

        assert_eq!(last_feed_attempt(&conn, "f").unwrap(), Some(250));
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM feed_sync", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn feeds_are_tracked_separately_and_clear_removes_only_one() {
        let conn = open_in_memory().unwrap();
        record_feed_attempt(&conn, "a", 10).unwrap();
        record_feed_attempt(&conn, "b", 20).unwrap();

        clear_feed_attempt(&conn, "a").unwrap();

        assert_eq!(last_feed_attempt(&conn, "a").unwrap(), None);
        assert_eq!(last_feed_attempt(&conn, "b").unwrap(), Some(20));
    }

    #[test]
    fn an_older_database_gains_the_table_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("older.db").to_string_lossy().into_owned();
        {
            let conn = open(&path).unwrap();
            conn.execute("DROP TABLE feed_sync", []).unwrap();
        }

        let conn = open(&path).unwrap();

        assert_eq!(last_feed_attempt(&conn, "f").unwrap(), None);
    }
}
