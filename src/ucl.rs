//! Clean-room UCL NRV2B (`_8` byte bit-container) block decompressor.
//!
//! NRV2B is a byte-oriented LZ77 variant used by the UCL compressor. This
//! module implements the `_8` bit-container variant used by QNX `mkifs`
//! for `--compress=ucl` image filesystems.
//!
//! Coding rules, validated against reference-compressor output:
//!
//! * Flag bits are read most-significant-bit first from a one-byte cache.
//! * A flag bit of `1` copies the next full input byte as a literal.
//! * A flag bit of `0` starts a backwards match. The match distance and
//!   length use the NRV2B variable-length coding described below.
//! * The escape distance `0xffff_ffff` ends the block.

use crate::error::Error;

/// Largest intermediate offset representable by the NRV2B offset coding;
/// the final distance can reach `0x1000003`.
const MAX_OFFSET_LIMIT: usize = 0x00ff_ffff + 3;

/// Build an [`Error::Decompress`] with backend context.
fn ucl_error(message: &'static str) -> Error {
    Error::Decompress(message.to_string())
}

/// Decompress one NRV2B block from `input`, appending the result to `out`.
///
/// `max_add` bounds how many bytes may be appended. On any error, `out` is
/// restored to its original length. Returns the number of bytes appended.
///
/// The whole of `input` must be consumed: a valid block ends with the
/// NRV2B end-of-stream marker, not merely when the input slice is empty.
pub fn nrv2b_decompress_8(input: &[u8], out: &mut Vec<u8>, max_add: usize) -> Result<usize, Error> {
    let start_len = out.len();
    let limit = start_len
        .checked_add(max_add)
        .ok_or(Error::DecompressTooLarge)?;

    let result = decode_block(input, out, limit);
    if result.is_err() {
        out.truncate(start_len);
    }
    result?;
    Ok(out.len() - start_len)
}

/// Shared cursor for flag bits and literal bytes: literals are read from
/// the same stream directly after the flag byte being consumed.
struct BitReader<'a> {
    input: &'a [u8],
    pos: usize,
    cache: u8,
    bits_left: u8,
}

impl<'a> BitReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            cache: 0,
            bits_left: 0,
        }
    }

    /// Read one flag bit, most significant bit first.
    fn bit(&mut self) -> Result<u8, Error> {
        if self.bits_left == 0 {
            self.cache = self.byte()?;
            self.bits_left = 8;
        }
        self.bits_left -= 1;
        Ok((self.cache >> self.bits_left) & 1)
    }

    fn byte(&mut self) -> Result<u8, Error> {
        let byte = *self
            .input
            .get(self.pos)
            .ok_or_else(|| ucl_error("ucl: unexpected end of compressed block"))?;
        self.pos += 1;
        Ok(byte)
    }

    const fn consumed(&self) -> bool {
        self.pos == self.input.len()
    }
}

/// Resolve the distance for a match token.
///
/// Returns `Ok(None)` when the offset code is the NRV2B end marker.
/// `last_offset` is updated when a new distance is recorded.
fn resolve_match_offset(
    reader: &mut BitReader<'_>,
    offset_code: usize,
    last_offset: &mut usize,
) -> Result<Option<usize>, Error> {
    if offset_code == 2 {
        return Ok(Some(*last_offset));
    }
    let low = usize::from(reader.byte()?);
    let encoded = (offset_code - 3)
        .checked_mul(256)
        .and_then(|value| value.checked_add(low))
        .ok_or_else(|| ucl_error("ucl: match offset overflow"))?;
    if encoded == 0xffff_ffff {
        return Ok(None);
    }
    *last_offset = encoded + 1;
    Ok(Some(*last_offset))
}

/// Decode one block into `out`, never growing it beyond `limit` bytes.
fn decode_block(input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<(), Error> {
    let mut reader = BitReader::new(input);
    let mut last_offset = 1usize;

    loop {
        if reader.bit()? == 1 {
            let byte = reader.byte()?;
            if out.len() >= limit {
                return Err(Error::DecompressTooLarge);
            }
            out.push(byte);
            continue;
        }

        // Decode a match distance. The loop builds a value whose low
        // eight bits are supplied separately below; 2 means "reuse the
        // previous distance".
        let mut offset_code = 1usize;
        loop {
            let bit = usize::from(reader.bit()?);
            offset_code = offset_code
                .checked_mul(2)
                .and_then(|value| value.checked_add(bit))
                .ok_or_else(|| ucl_error("ucl: match offset overflow"))?;
            if offset_code > MAX_OFFSET_LIMIT {
                return Err(ucl_error("ucl: match offset too large"));
            }
            if reader.bit()? == 1 {
                break;
            }
        }

        let Some(distance) = resolve_match_offset(&mut reader, offset_code, &mut last_offset)?
        else {
            break;
        };

        let mut length = usize::from(reader.bit()?) * 2 + usize::from(reader.bit()?);
        if length == 0 {
            length += 1;
            loop {
                let bit = usize::from(reader.bit()?);
                length = length
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(bit))
                    .ok_or_else(|| ucl_error("ucl: match length overflow"))?;
                if length > limit {
                    return Err(Error::DecompressTooLarge);
                }
                if reader.bit()? == 1 {
                    break;
                }
            }
            length += 2;
        }
        length += usize::from(distance > 0x0d00);

        if distance == 0 || distance > out.len() {
            return Err(ucl_error("ucl: match distance exceeds output"));
        }

        // NRV2B copies the first match byte plus `length` additional bytes,
        // allowing overlapping copies. Byte-at-a-time copying is required
        // for run-length matches.
        let copy_len = length
            .checked_add(1)
            .ok_or_else(|| ucl_error("ucl: match length overflow"))?;
        let end = out
            .len()
            .checked_add(copy_len)
            .ok_or(Error::DecompressTooLarge)?;
        if end > limit {
            return Err(Error::DecompressTooLarge);
        }

        let start = out.len() - distance;
        for index in 0..copy_len {
            let byte = out[start + index];
            out.push(byte);
        }
    }

    if !reader.consumed() {
        return Err(ucl_error("ucl: trailing data after end marker"));
    }
    Ok(())
}
