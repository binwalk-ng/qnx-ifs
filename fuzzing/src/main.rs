//! AFL fuzz harness for the qnx-ifs parser.
//!
//! Covers the full parse pipeline (strict and opt-in lenient), bare
//! filesystem carving, file content exposure, and the decompression
//! back ends on arbitrary bytes. Panics are the bug; `Err(_)` is fine.
use afl::fuzz;
use qnx_ifs::{Compress, Image, Limits, ParseOptions, decompress::decompress_region};

fn main() {
    let limits = Limits::default();
    let options = ParseOptions {
        lenient_startup_header: true,
        ..ParseOptions::default()
    };

    fuzz!(|data: &[u8]| {
        // Whole-image parsing, strict and lenient.
        if let Ok(image) = Image::parse(data) {
            for entry in &image.entries {
                let _ = image.file_bytes(entry);
            }
            let _ = image.image_checksum();
            let _ = image.startup_checksum();
        }
        if let Ok(image) = Image::parse_imagefs(data) {
            let _ = image.total_size();
        }
        let _ = Image::parse_with_options(data, &options);

        // The decompression back ends on arbitrary bytes.
        for kind in [Compress::Zlib, Compress::Lzo, Compress::Ucl] {
            let _ = decompress_region(data, kind, &limits);
        }
    });
}
