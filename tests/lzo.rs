//! LZO1X block-chain checks.
//!
//! Two independent sources of truth:
//!
//! - Reference vectors produced by the original LZO C library
//!   (`lzo1x_1`/`lzo1x_999`; see `tests/common/lzo_oracle.rs`).
//! - Round-trips through the real `[len: u16 BE][block]… [len: 0]` region
//!   framing with the independent pure-Rust `lzokay` compressor. These
//!   cover 64 KiB blocks, multi-chunk regions, and match distances beyond
//!   the reference set (including the M4 encoding class).
#![cfg(feature = "lzo")]
#![allow(clippy::panic)] // test assertions panic by design

mod common;

use common::hex_to_bytes;
use common::lzo_oracle::LZO_ORACLE;
use qnx_ifs::decompress::{BLOCK_MAX_OUTPUT, decompress_region};
use qnx_ifs::{Compress, Error, Limits};

/// Frame already-compressed blocks as an IFS LZO region.
fn frame_blocks(blocks: &[&[u8]]) -> Vec<u8> {
    let mut region = Vec::new();
    for block in blocks {
        let len = u16::try_from(block.len()).expect("block fits in a u16 length");
        region.extend_from_slice(&len.to_be_bytes());
        region.extend_from_slice(block);
    }
    region.extend_from_slice(&[0, 0]);
    region
}

/// Compress `source` with `lzokay` using `mkifs`-style 64 KiB input chunks
/// and frame the result as a region.
fn lzokay_region(source: &[u8]) -> Vec<u8> {
    let blocks: Vec<Vec<u8>> = source
        .chunks(BLOCK_MAX_OUTPUT)
        .map(|chunk| lzokay::compress::compress(chunk).expect("lzokay compress"))
        .collect();
    let refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    frame_blocks(&refs)
}

fn decode(region: &[u8]) -> Result<Vec<u8>, Error> {
    decompress_region(region, Compress::Lzo, &Limits::default())
}

/// Deterministic pseudo-random bytes (xorshift32, high byte), used for
/// incompressible data so no test dependency on a random generator crate
/// is needed.
fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

#[test]
fn decodes_reference_vectors() {
    for vector in LZO_ORACLE {
        let source = hex_to_bytes(vector.source);
        for (compressor, compressed_hex) in vector.blocks {
            let block = hex_to_bytes(compressed_hex);
            let region = frame_blocks(&[&block]);
            let decoded = decode(&region)
                .unwrap_or_else(|error| panic!("{} via {compressor}: {error}", vector.name));
            assert_eq!(decoded, source, "{} via {compressor}", vector.name);
        }
    }
}

#[test]
fn roundtrips_lzokay_across_patterns() {
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("single byte", vec![0x41]),
        ("static string", b"hello, lzo world!".to_vec()),
        ("zeros 64 KiB", vec![0; BLOCK_MAX_OUTPUT]),
        ("runs 64 KiB", vec![0xAB; BLOCK_MAX_OUTPUT]),
    ];

    // Incompressible data, stored as literals; single block that still
    // fits the u16 length field.
    cases.push(("incompressible 40000", pseudo_random(40_000, 0x1234_5678)));

    // Repeated pseudo-random units force match distances above the 2 KiB
    // class covered by the reference vectors: 8192 lands in M3 and 32768
    // in M4 (the widest offset class, max 0xBFFF).
    for (name, distance) in [("far M3 distance", 8192usize), ("far M4 distance", 32768)] {
        let unit = pseudo_random(distance, distance as u32);
        let mut data = unit.clone();
        data.extend_from_slice(&unit);
        cases.push((name, data));
    }

    // Mixed compressible/incompressible content in one region.
    let mut mixed = vec![0u8; BLOCK_MAX_OUTPUT];
    mixed.extend_from_slice(&pseudo_random(4096, 0xC0FF_EE00));
    mixed.extend(std::iter::repeat_n(b'A', BLOCK_MAX_OUTPUT));
    cases.push(("mixed multi-chunk", mixed));

    for (name, source) in cases {
        let region = lzokay_region(&source);
        let decoded = decode(&region).unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(decoded, source, "{name}");
    }
}

#[test]
fn roundtrips_many_chunks() {
    // 200000 bytes split into three 65536-byte chunks plus a tail: exercises
    // block-by-block concatenation and ordering.
    let source = vec![0u8; 200_000];
    let region = lzokay_region(&source);
    assert_eq!(decode(&region), Ok(source));
}

#[test]
fn rejects_malformed_framing() {
    // Missing or partial block length.
    assert_eq!(decode(&[]), Err(Error::Truncated));
    assert_eq!(decode(&[0x00]), Err(Error::Truncated));
    // Declared block longer than the data available.
    assert_eq!(decode(&[0x00, 0x04, 0x11, 0x22]), Err(Error::Truncated));
    // Malformed LZO block.
    let malformed = frame_blocks(&[&[0xFF, 0xFF, 0xFF]]);
    assert!(matches!(decode(&malformed), Err(Error::Decompression(_))));
    // Trailing bytes after the zero-length terminator are ignored, matching
    // the reference tool which stops reading at the terminator.
    let mut region = frame_blocks(&[&lzokay::compress::compress(b"payload").unwrap()]);
    region.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
    assert_eq!(decode(&region), Ok(b"payload".to_vec()));
}

#[test]
fn enforces_output_limits() {
    // One block that expands past the configured limit.
    let region = lzokay_region(&vec![0u8; 2048]);
    let limits = Limits {
        max_decompressed: 1024,
    };
    assert_eq!(
        decompress_region(&region, Compress::Lzo, &limits),
        Err(Error::DecompressTooLarge)
    );

    // Two blocks whose combined output exceeds the limit only after the
    // first one exactly exhausts the budget.
    let block = lzokay::compress::compress(&vec![0u8; 1024]).unwrap();
    let region = frame_blocks(&[&block, &block]);
    assert_eq!(
        decompress_region(&region, Compress::Lzo, &limits),
        Err(Error::DecompressTooLarge)
    );

    // Passing `Compress::None` here is an API misuse and is reported as such.
    assert_eq!(
        decompress_region(&[], Compress::None, &Limits::default()),
        Err(Error::Decompress("region is not compressed"))
    );
}
