//! Decompression of the compressed image filesystem region of an IFS image.
//!
//! `mkifs` compresses the filesystem either as a single zlib/gzip framed
//! stream, or as a chain of independently compressed blocks:
//!
//! ```text
//! [len: u16 BE][block data] [len: u16 BE][block data] ... [len: 0]
//! ```
//!
//! The chain ends at a zero length; zlib streams are self-terminating and
//! may carry gzip framing. The uncompressed size is only known after
//! parsing the filesystem header, which is part of the compressed payload.

use crate::error::Error;
use crate::startup::Compress;

/// Safety limits for decompressing untrusted data.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum total decompressed output in bytes. Defaults to 256 MiB.
    pub max_decompressed: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_decompressed: 256 * 1024 * 1024,
        }
    }
}

/// Maximum output per compressed block, matching the fixed 64 KiB buffer
/// the reference decompressor uses for LZO and UCL blocks.
pub const BLOCK_MAX_OUTPUT: usize = 64 * 1024;

/// Decompress a compressed filesystem region.
///
/// `region` covers `startup_size..stored_size` of the raw image. Returns
/// the decompressed filesystem bytes.
///
/// [`Compress::None`] images carry the filesystem uncompressed; callers
/// slice the region directly and must not invoke this for them.
///
/// The region is decompressed strictly within its declared extent: a zlib
/// or gzip stream truncated by the end of the region is an error, and
/// trailing bytes after a gzip member are rejected instead of being
/// ignored like the reference tool does after `gzread` errors out. Bytes
/// after the end of a zlib stream are not inspected by the decoder (zlib
/// framing carries no region length), so the startup header's declared
/// filesystem size remains the authoritative bound on the output.
pub fn decompress_region(region: &[u8], kind: Compress, limits: &Limits) -> Result<Vec<u8>, Error> {
    match kind {
        Compress::None => Err(Error::Decompress("region is not compressed".to_string())),
        Compress::Zlib => zlib_stream(region, limits),
        Compress::Lzo => lzo_chunks(region, limits),
        Compress::Ucl => ucl_chunks(region, limits),
    }
}

/// Decompress a zlib stream, also accepting gzip framing like the
/// reference tool does through `gzopen`.
#[allow(clippy::missing_const_for_fn)] // non-const when `zlib` is enabled
fn zlib_stream(region: &[u8], limits: &Limits) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "zlib")]
    {
        use std::io::Read;

        // Zlib framing is 0x78 0x.. (CMF/FLG); gzip framing is 0x1f 0x8b.
        // Raw deflate is rejected: the reference tool never produces it.
        let framed: Box<dyn Read> = if region.len() >= 2 && region[0] == 0x1f && region[1] == 0x8b {
            Box::new(flate2::read::MultiGzDecoder::new(region))
        } else {
            Box::new(flate2::read::ZlibDecoder::new(region))
        };

        let mut out = Vec::new();
        let mut chunk = [0u8; 32 * 1024];
        let mut reader = framed;
        loop {
            let read = reader
                .read(&mut chunk)
                .map_err(|error| Error::Decompress(format!("zlib: {error}")))?;
            if read == 0 {
                break;
            }
            if out.len().saturating_add(read) > limits.max_decompressed {
                return Err(Error::DecompressTooLarge);
            }
            out.extend_from_slice(&chunk[..read]);
        }
        Ok(out)
    }

    #[cfg(not(feature = "zlib"))]
    {
        let _ = (region, limits);
        Err(Error::FeatureDisabled("zlib"))
    }
}

/// Decompress the LZO1X block chain.
#[allow(clippy::missing_const_for_fn)] // non-const when `lzo` is enabled
fn lzo_chunks(region: &[u8], limits: &Limits) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "lzo")]
    {
        let mut chunks = ChunkIter::new(region);
        let mut out = Vec::new();

        while let Some(block) = chunks.next_block()? {
            let budget_left = limits.max_decompressed.saturating_sub(out.len());
            if budget_left == 0 {
                return Err(Error::DecompressTooLarge);
            }
            // Bound the output: the reference tool uses a fixed 64 KiB
            // block buffer, so a block never expands beyond `BLOCK_MAX_OUTPUT`.
            let cap = BLOCK_MAX_OUTPUT.min(budget_left);
            let decoded = lzo::decompress(block, cap).map_err(|error| match error {
                // Uniform with the UCL path and the global limit.
                lzo::Error::OutputOverrun => Error::DecompressTooLarge,
                other => Error::Decompress(format!("lzo: {other}")),
            })?;
            if decoded.len() > budget_left || decoded.len() > BLOCK_MAX_OUTPUT {
                return Err(Error::DecompressTooLarge);
            }
            out.extend_from_slice(&decoded);
        }
        Ok(out)
    }

    #[cfg(not(feature = "lzo"))]
    {
        let _ = (region, limits);
        Err(Error::FeatureDisabled("lzo"))
    }
}

/// Decompress the UCL NRV2B block chain.
#[allow(clippy::missing_const_for_fn)] // non-const when `ucl` is enabled
fn ucl_chunks(region: &[u8], limits: &Limits) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "ucl")]
    {
        let mut chunks = ChunkIter::new(region);
        let mut out = Vec::new();

        while let Some(block) = chunks.next_block()? {
            let budget = BLOCK_MAX_OUTPUT.min(limits.max_decompressed.saturating_sub(out.len()));
            if budget == 0 {
                return Err(Error::DecompressTooLarge);
            }
            let mut block_out = Vec::new();
            crate::ucl::nrv2b_decompress_8(block, &mut block_out, budget)?;
            out.extend_from_slice(&block_out);
        }
        Ok(out)
    }

    #[cfg(not(feature = "ucl"))]
    {
        let _ = (region, limits);
        Err(Error::FeatureDisabled("ucl"))
    }
}

/// Iterator over `[len: u16 BE][block]... [len == 0]` chunk chains.
#[cfg(any(feature = "lzo", feature = "ucl"))]
struct ChunkIter<'a> {
    region: &'a [u8],
    pos: usize,
}

#[cfg(any(feature = "lzo", feature = "ucl"))]
impl<'a> ChunkIter<'a> {
    const fn new(region: &'a [u8]) -> Self {
        Self { region, pos: 0 }
    }

    /// Return the next block, or `None` at the terminating zero length.
    fn next_block(&mut self) -> Result<Option<&'a [u8]>, Error> {
        let header = self
            .region
            .get(self.pos..self.pos + 2)
            .ok_or(Error::Truncated)?;
        self.pos += 2;
        let len = u16::from_be_bytes([header[0], header[1]]);
        if len == 0 {
            return Ok(None);
        }
        let block = self
            .region
            .get(self.pos..self.pos + usize::from(len))
            .ok_or(Error::Truncated)?;
        self.pos += usize::from(len);
        Ok(Some(block))
    }
}
