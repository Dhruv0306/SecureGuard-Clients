/// Ported directly from SecurityServiceImpl.THRESHOLD_HIGH_ENTROPY: 7.2 out of
/// a possible 8.0 bits/byte. Calibrated to reach SUSPICIOUS on its own but not
/// MALICIOUS on its own, a legitimate compressed/encrypted file can trigger
/// this alone, so entropy corroborates other signals rather than convicting
/// outright. See the Java source comment above THRESHOLD_HIGH_ENTROPY for the
/// full rationale, this constant must not be changed here without changing it
/// there, they are one spec.
pub const THRESHOLD_HIGH_ENTROPY: f64 = 7.2;

/// Bytes sampled per calculation. Ported from the Java engine's sampling
/// approach: entropy is computed over a bounded prefix of the file rather
/// than the whole thing, both for performance on large files and because
/// packed/encrypted sections are typically front-loaded.
pub const ENTROPY_SAMPLE_BYTES: usize = 8192;

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

/// Computes entropy over a bounded sample of `data` and reports whether it
/// crosses THRESHOLD_HIGH_ENTROPY.
pub fn is_high_entropy(data: &[u8]) -> (f64, bool) {
    let sample = &data[..data.len().min(ENTROPY_SAMPLE_BYTES)];
    let entropy = shannon_entropy(sample);
    (entropy, entropy >= THRESHOLD_HIGH_ENTROPY)
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
    fn sampling_is_bounded_to_entropy_sample_bytes() {
        // A buffer larger than the sample size where only the sampled prefix
        // is high-entropy; confirms we don't read past ENTROPY_SAMPLE_BYTES.
        let mut data = Vec::new();
        for _ in 0..(ENTROPY_SAMPLE_BYTES / 256) {
            for b in 0u8..=255 {
                data.push(b);
            }
        }
        data.resize(ENTROPY_SAMPLE_BYTES, 0); // pad the tail of the sample window
        data.extend(std::iter::repeat(0u8).take(1_000_000)); // huge low-entropy tail
        let (_, flagged) = is_high_entropy(&data);
        // The high-entropy content sits early enough in the sample window
        // that this should still flag despite the low-entropy tail beyond
        // the sample boundary.
        assert!(flagged);
    }
}
