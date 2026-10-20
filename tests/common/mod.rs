//! Shared helpers for the internal validation tests.
//!
//! Each integration test links its own copy of this module and only uses
//! a subset of the helpers, so dead-code warnings are expected.
#![allow(dead_code)]

/// Byte-accurate image fixture builders.
pub mod fixtures;

/// Decode a hex string into bytes.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Literal-only UCL NRV2B block encoder.
///
/// The production parser never needs an encoder; this exists so the UCL
/// chunk path can be tested end to end without a UCL compressor
/// dependency. The end marker uses the NRV2B escape value
/// `0xffff_ffff`.
pub fn ucl_literal_block(source: &[u8]) -> Vec<u8> {
    /// Bit cache writer matching the NRV2B `_8` container: literal
    /// bytes are queued behind the cache byte whose flag bits reference
    /// them, not directly behind each individual bit.
    struct BitSink {
        out: Vec<u8>,
        cache: u8,
        used: u8,
        pending_literals: Vec<u8>,
    }

    impl BitSink {
        fn flush_cache(&mut self) {
            if self.used != 0 {
                self.out.push(self.cache);
                self.out.append(&mut self.pending_literals);
                self.cache = 0;
                self.used = 0;
            }
        }

        fn push(&mut self, bit: u8) {
            if self.used == 8 {
                self.flush_cache();
            }
            self.cache |= (bit & 1) << (7 - self.used);
            self.used += 1;
        }

        fn literal(&mut self, byte: u8) {
            self.push(1);
            self.pending_literals.push(byte);
        }

        fn raw(&mut self, byte: u8) {
            self.flush_cache();
            self.out.push(byte);
        }

        fn finish(mut self) -> Vec<u8> {
            self.flush_cache();
            self.out
        }
    }

    let mut sink = BitSink {
        out: Vec::new(),
        cache: 0,
        used: 0,
        pending_literals: Vec::new(),
    };

    for &byte in source {
        sink.literal(byte);
    }

    // End marker: match flag 0, offset code 0x1000002, low byte 0xff.
    sink.push(0);
    let offset_code = 0x0100_0002usize;
    for shift in (0..24).rev() {
        sink.push(((offset_code >> shift) & 1) as u8);
        sink.push(u8::from(shift == 0));
    }
    sink.raw(0xFF);
    sink.finish()
}

pub mod lzo_oracle;
pub mod ucl_oracle;
