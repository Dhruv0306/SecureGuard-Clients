/// Ported directly from SecurityServiceImpl.THRESHOLD_HIGH_ENTROPY: 7.2 out of
/// a possible 8.0 bits/byte. Calibrated to reach SUSPICIOUS on its own but not
/// MALICIOUS on its own, a legitimate compressed/encrypted file can trigger
/// this alone, so entropy corroborates other signals rather than convicting
/// outright. See the Java source comment above THRESHOLD_HIGH_ENTROPY for the
/// full rationale, this constant must not be changed here without changing it
/// there, they are one spec.
pub const THRESHOLD_HIGH_ENTROPY: f64 = 7.2;

/// Bytes sampled per calculation. Ported from SecurityServiceImpl:
/// `ENTROPY_SAMPLE_BYTES = (int) MAX_PATTERN_SCAN_BYTES` (10 MB), not a
/// small fixed prefix, an earlier version of this file guessed 8192 here
/// without checking source, this is the corrected, verified value.
pub const ENTROPY_SAMPLE_BYTES: usize = 10 * 1024 * 1024;

/// Shannon entropy in bits/byte over the given buffer. Returns 0.0 for an
/// empty buffer (no information, not "suspiciously high").
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Computes entropy over a buffer already bounded to at most `sample_bound`
/// bytes by the caller, and reports whether it crosses
/// THRESHOLD_HIGH_ENTROPY. Split out from `is_high_entropy` purely so the
/// bounding behavior itself can be unit-tested at a small, fast bound
/// without allocating a buffer anywhere near the real 10 MB production
/// value.
fn is_high_entropy_bounded(data: &[u8], sample_bound: usize) -> (f64, bool) {
    let sample = &data[..data.len().min(sample_bound)];
    let entropy = shannon_entropy(sample);
    (entropy, entropy >= THRESHOLD_HIGH_ENTROPY)
}

/// Computes entropy over a bounded sample of `data` (ENTROPY_SAMPLE_BYTES)
/// and reports whether it crosses THRESHOLD_HIGH_ENTROPY.
pub fn is_high_entropy(data: &[u8]) -> (f64, bool) {
    is_high_entropy_bounded(data, ENTROPY_SAMPLE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_has_zero_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn uniform_buffer_has_zero_entropy() {
        let data = vec![0x41u8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn uniformly_random_byte_distribution_is_near_maximum_entropy() {
        // Deterministic pseudo-random fill (no external RNG dependency):
        // every byte value 0..=255 appears exactly once, repeated to fill
        // the sample. This is the theoretical maximum-entropy case (8.0
        // bits/byte) since every symbol is equally likely.
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        let entropy = shannon_entropy(&data);
        assert!(
            entropy > 7.9,
            "expected near-maximum entropy, got {entropy}"
        );
    }

    #[test]
    fn low_entropy_data_is_not_flagged() {
        let data = vec![0u8; 1024];
        let (_, flagged) = is_high_entropy(&data);
        assert!(!flagged);
    }

    #[test]
    fn high_entropy_data_is_flagged() {
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        let (entropy, flagged) = is_high_entropy(&data);
        assert!(flagged, "entropy {entropy} should cross the threshold");
    }

    #[test]
    fn production_constant_matches_the_verified_java_value() {
        // Locks in the corrected value (10 MB = MAX_PATTERN_SCAN_BYTES) so a
        // future edit can't silently reintroduce the earlier unverified
        // 8192-byte guess.
        assert_eq!(ENTROPY_SAMPLE_BYTES, 10 * 1024 * 1024);
    }

    #[test]
    fn sampling_is_bounded_and_does_not_read_past_the_bound() {
        // Uses a small local bound (not the real 10 MB production value) so
        // this test stays fast and light while still proving the actual
        // truncation behavior is correct: high-entropy content inside the
        // bound is seen, a huge low-entropy tail past the bound is not.
        const TEST_BOUND: usize = 8192;

        let mut data = Vec::new();
        for _ in 0..(TEST_BOUND / 256) {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        data.resize(TEST_BOUND, 0);
        data.extend(std::iter::repeat(0u8).take(1_000_000)); // tail past the bound

        let (_, flagged) = is_high_entropy_bounded(&data, TEST_BOUND);
        assert!(
            flagged,
            "high-entropy content within the bound should still flag despite \
             the low-entropy tail beyond it"
        );
    }
}
