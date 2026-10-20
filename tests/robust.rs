//! Deterministic robustness tests over hostile inputs.
//!
//! A seeded xorshift PRNG mutates valid images and feeds random bytes to
//! the parsing and decompression entry points. Malformed input must
//! surface as `Err(_)`, and every successfully parsed image must uphold
//! the parser's structural invariants. A panic in any round is a
//! regression.
//!
//! The rounds are fully deterministic (no floating point, no host
//! endianness dependency), so failures reproduce exactly from the seed.
#![allow(clippy::panic)] // test assertions panic by design

use common::fixtures::{E, TestCompress, build_image};
use qnx_ifs::{Compress, Image, Limits, ParseOptions, decompress::decompress_region};

mod common;

/// Rounds of mutation per fixture.
const MUTATION_ROUNDS: usize = 512;
/// Rounds of pure random data fed to the decoders.
const RANDOM_ROUNDS: usize = 1024;

/// xorshift64* pseudo random generator; deterministic across platforms.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Value in `0..bound`, or `0` when `bound == 0`.
    const fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    const fn byte(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }
}

/// Test compression variants available in this build.
fn compressions() -> Vec<TestCompress> {
    // Without any compression feature the pushes below are compiled out.
    #[allow(unused_mut)]
    let mut variants = vec![TestCompress::None];
    #[cfg(feature = "zlib")]
    {
        variants.push(TestCompress::Zlib);
        variants.push(TestCompress::Gzip);
    }
    #[cfg(feature = "lzo")]
    {
        variants.push(TestCompress::Lzo);
    }
    #[cfg(feature = "ucl")]
    {
        variants.push(TestCompress::Ucl);
    }
    variants
}

/// Apply a handful of random mutations: bit flips, random and zeroed
/// bytes, moves, and truncation.
fn mutate(base: &[u8], rng: &mut XorShift64) -> Vec<u8> {
    let mut out = base.to_vec();
    let rounds = 1 + rng.below(8);
    for _ in 0..rounds {
        if out.is_empty() {
            break;
        }
        match rng.below(5) {
            0 => {
                let index = rng.below(out.len());
                out[index] ^= 1 << rng.below(8);
            }
            1 => {
                let index = rng.below(out.len());
                out[index] = rng.byte();
            }
            2 => {
                let index = rng.below(out.len());
                out[index] = 0;
            }
            3 => {
                let a = rng.below(out.len());
                let b = rng.below(out.len());
                out.swap(a, b);
            }
            _ => {
                out.truncate(rng.below(out.len() + 1));
            }
        }
    }
    out
}

/// Enforce the parser invariants over a successfully parsed image.
fn check_invariants(parsed: &Image<'_>, input: &[u8]) {
    // The image never extends past the input.
    assert!(parsed.total_size() <= input.len());

    // Zero-inode dirents are quarantined, never promoted into the entry
    // list, and recording respects the cap.
    assert!(parsed.entries.iter().all(|entry| entry.ino != 0));
    assert!(parsed.omitted_dirents.len() <= qnx_ifs::MAX_OMITTED_DIRENTS);

    // Regular file entries expose exactly their declared contents; the
    // bounds were validated during the parse.
    for entry in &parsed.entries {
        if let qnx_ifs::EntryKind::File { size, .. } = &entry.kind {
            let contents = parsed
                .file_bytes(entry)
                .unwrap_or_else(|| panic!("file {:?} contents missing", entry.path));
            assert_eq!(contents.len(), *size);
        }
    }

    // Checksum helpers never panic, whatever the (possibly corrupted)
    // trailer contents are.
    let _ = parsed.image_checksum();
    let _ = parsed.startup_checksum();
}

#[test]
fn mutated_images_never_panic() {
    let mut rng = XorShift64::new(0xC0FF_EE01_2026_1001);
    for compress in compressions() {
        let base = build_image(E::LE, compress);
        for _ in 0..MUTATION_ROUNDS {
            let input = mutate(&base, &mut rng);

            // All three parse entry points must terminate without panics.
            if let Ok(parsed) = Image::parse(&input) {
                check_invariants(&parsed, &input);
            }
            if let Ok(parsed) = Image::parse_imagefs(&input) {
                check_invariants(&parsed, &input);
            }
            let options = ParseOptions {
                lenient_startup_header: true,
                ..ParseOptions::default()
            };
            if let Ok(parsed) = Image::parse_with_options(&input, &options) {
                check_invariants(&parsed, &input);
            }
        }
    }
}

#[test]
fn truncated_and_extended_bases_never_panic() {
    let mut rng = XorShift64::new(0xDEAD_C0DE_ADD1_1111);
    let base = build_image(E::BE, TestCompress::None);

    // Byte truncations around the interesting boundaries.
    for cut in [0, 3, 7, 47, 255, 256, 259, 263, 264] {
        if cut < base.len() {
            let _ = Image::parse(&base[..cut]);
        }
    }

    // Random additional trailing bytes.
    for _ in 0..128 {
        let mut extended = base.clone();
        let extra = 1 + rng.below(64);
        let mut tail = Vec::with_capacity(extra);
        for _ in 0..extra {
            tail.push(rng.byte());
        }
        extended.extend_from_slice(&tail);
        let _ = Image::parse(&extended);
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = XorShift64::new(0x5EED_BEEF_F00D_2026);
    let limits = Limits::default();

    for _ in 0..RANDOM_ROUNDS {
        let len = 1 + rng.below(512);
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(rng.byte());
        }

        // Whole image parsing of random bytes.
        if let Ok(parsed) = Image::parse(&data) {
            check_invariants(&parsed, &data);
        }
        // Decompression region dispatch with random framing.
        for kind in [Compress::None, Compress::Zlib, Compress::Lzo, Compress::Ucl] {
            let _ = decompress_region(&data, kind, &limits);
        }
    }
}

#[cfg(feature = "ucl")]
#[test]
fn random_ucl_blocks_never_panic() {
    use qnx_ifs::ucl::nrv2b_decompress_8;

    let mut rng = XorShift64::new(0x1EE6_4242_B0B5_FA4E);
    for _ in 0..RANDOM_ROUNDS {
        let len = 1 + rng.below(256);
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(rng.byte());
        }
        let mut output = Vec::new();
        let _ = nrv2b_decompress_8(&data, &mut output, 1 << 20);
        assert!(output.len() <= 1 << 21);
    }
}

/// Random payload framed by the caller, sometimes mutated afterwards.
#[cfg(any(feature = "lzo", feature = "ucl", feature = "zlib"))]
fn framed_region(build: impl Fn(&[u8]) -> Vec<u8>, rng: &mut XorShift64) -> Vec<u8> {
    if rng.below(2) == 0 {
        let len = 1 + rng.below(256);
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(rng.byte());
        }
        build(&data)
    } else {
        let payload: Vec<u8> = (0..rng.below(1024)).map(|_| rng.byte()).collect();
        mutate(&build(&payload), rng)
    }
}

#[cfg(feature = "lzo")]
#[test]
fn mutated_lzo_region_never_panic() {
    use common::fixtures::lzo_frame;
    use lzokay::compress::compress;

    let mut rng = XorShift64::new(0x105A_0420_BE00_F00D);
    let limits = Limits::default();
    for _ in 0..RANDOM_ROUNDS {
        let region = framed_region(
            |data| lzo_frame(&compress(data).expect("lzo compress")),
            &mut rng,
        );
        let _ = decompress_region(&region, Compress::Lzo, &limits);
    }
}

#[cfg(feature = "ucl")]
#[test]
fn mutated_ucl_region_never_panic() {
    use common::fixtures::ucl_frame;
    use common::ucl_literal_block;

    let mut rng = XorShift64::new(0x0EE5_A5E5_DEAD_F00D);
    let limits = Limits::default();
    for _ in 0..RANDOM_ROUNDS {
        let region = framed_region(|data| ucl_frame(&ucl_literal_block(data)), &mut rng);
        let _ = decompress_region(&region, Compress::Ucl, &limits);
    }
}

#[cfg(feature = "zlib")]
#[test]
fn mutated_zlib_region_never_panic() {
    use common::fixtures::zlib_stream;
    use std::io::Write;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("zlib write");
        encoder.finish().expect("zlib finish")
    }

    let mut rng = XorShift64::new(0x2121_1AB1_FA0E_0FFB);
    let limits = Limits::default();
    for _ in 0..RANDOM_ROUNDS {
        let builder = if rng.below(2) == 0 {
            zlib_stream
        } else {
            deflate
        };
        let region = framed_region(builder, &mut rng);
        let _ = decompress_region(&region, Compress::Zlib, &limits);
    }
}

/// The mutation helpers: identical seeds must produce identical streams
/// (guards against accidental nondeterminism in the suite).
#[test]
fn prng_is_deterministic() {
    fn stream() -> Vec<usize> {
        let mut rng = XorShift64::new(42);
        (0..128).map(|_| rng.below(97)).collect()
    }

    let first = stream();
    let second = stream();
    assert_eq!(first, second);
}
