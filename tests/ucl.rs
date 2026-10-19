//! UCL NRV2B decoder checks against reference-compressor vectors.
#![cfg(feature = "ucl")]
#![allow(clippy::panic)] // test assertions panic by design

mod common;

use common::hex_to_bytes;
use common::ucl_oracle::ORACLE;
use qnx_ifs::Error;
use qnx_ifs::ucl::nrv2b_decompress_8;

#[test]
fn decodes_reference_vectors() {
    for (index, (source_hex, compressed_hex)) in ORACLE.iter().enumerate() {
        let source = hex_to_bytes(source_hex);
        let compressed = hex_to_bytes(compressed_hex);
        let mut output = Vec::new();
        let written = nrv2b_decompress_8(&compressed, &mut output, output_limit(&source))
            .unwrap_or_else(|error| panic!("vector {index}: {error}"));
        assert_eq!(written, source.len(), "vector {index}");
        assert_eq!(output, source, "vector {index}");
    }
}

#[test]
fn rejects_output_limit_before_appending() {
    let (_, compressed_hex) = ORACLE[0];
    let compressed = hex_to_bytes(compressed_hex);
    let mut output = b"prefix".to_vec();

    let error = nrv2b_decompress_8(&compressed, &mut output, 0).unwrap_err();
    assert_eq!(error, Error::DecompressTooLarge);
    assert_eq!(output, b"prefix");
}

#[test]
fn rejects_truncated_input_without_partial_output() {
    let (_, compressed_hex) = ORACLE[0];
    let compressed = hex_to_bytes(compressed_hex);
    let mut output = Vec::new();

    let error =
        nrv2b_decompress_8(&compressed[..compressed.len() - 1], &mut output, 1024).unwrap_err();
    assert!(matches!(error, Error::Decompress(_)));
    assert!(output.is_empty());
}

#[test]
fn literal_encoder_matches_oracle_for_single_literal() {
    let encoded = common::ucl_literal_block(&hex_to_bytes("a5"));
    assert_eq!(encoded, hex_to_bytes(ORACLE[0].1));
}

#[test]
fn literal_encoder_roundtrips_across_cache_boundaries() {
    for len in [0usize, 1, 2, 7, 8, 9, 15, 16, 17, 1023, 1024, 1025] {
        let source: Vec<u8> = (0..len)
            .map(|index| (index as u8).wrapping_mul(37))
            .collect();
        let compressed = common::ucl_literal_block(&source);
        let mut output = Vec::new();
        nrv2b_decompress_8(&compressed, &mut output, output_limit(&source).max(1))
            .unwrap_or_else(|error| panic!("len {len}: {error}"));
        assert_eq!(output, source, "len {len}");
    }
}

fn output_limit(source: &[u8]) -> usize {
    source.len().max(1)
}
