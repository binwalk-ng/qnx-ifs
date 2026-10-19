//! QNX IFS startup header parsing and validation.
//!
//! Multi-byte fields use the target byte order selected by the
//! `STARTUP_HDR_FLAGS1_BIGENDIAN` flag; the signature magic and the flag
//! bytes are endian neutral, so byte-swapped magic is accepted too.

use zerocopy::{
    FromBytes, Immutable, KnownLayout, U16, U32, Unaligned,
    byteorder::{BE, ByteOrder, LE},
};

use crate::error::Error;

/// Startup header magic bytes, stored little endian.
pub const STARTUP_MAGIC_LE: [u8; 4] = [0xEB, 0x7E, 0xFF, 0x00];
/// Startup header magic bytes, stored big endian (legacy cross-endian images).
pub const STARTUP_MAGIC_BE: [u8; 4] = [0x00, 0xFF, 0x7E, 0xEB];
/// Startup header version understood by this parser.
pub const STARTUP_HDR_VERSION: u16 = 1;
/// Byte size of the fixed startup header prefix parsed by this crate.
///
/// On-disk `struct startup_header` is normally 256 bytes; startup program
/// bytes begin after `StartupHeader::header_size`.
pub const STARTUP_HEADER_SIZE: usize = 64;

/// Scan the whole buffer for a valid startup header.
///
/// Returns `(offset, header)`. Every structural check (signature,
/// version, zero fields) must pass.
pub fn find_startup_header(data: &[u8]) -> Option<(usize, StartupHeader)> {
    if data.len() < STARTUP_HEADER_SIZE {
        return None;
    }
    for off in 0..=data.len() - STARTUP_HEADER_SIZE {
        let matches_magic =
            data[off..off + 4] == STARTUP_MAGIC_LE || data[off..off + 4] == STARTUP_MAGIC_BE;
        if matches_magic && let Ok(hdr) = parse_startup_header(data, off) {
            return Some((off, hdr));
        }
    }
    None
}

/// Decompression type declared by the startup header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Compress {
    /// No compression.
    None,
    /// zlib (also accepted with gzip framing).
    Zlib,
    /// LZO1X blocks, `[len: u16 BE][block]...` chunks ended by a zero length.
    Lzo,
    /// UCL NRV2B blocks, `[len: u16 BE][block]...` chunks ended by a zero length.
    Ucl,
}

/// Byte order used by multi-byte fields within an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// Little endian (`STARTUP_HDR_FLAGS1_BIGENDIAN` unset).
    Little,
    /// Big endian (`STARTUP_HDR_FLAGS1_BIGENDIAN` set).
    Big,
}

impl Endian {
    /// Endian as signalled by the startup header flags.
    pub const fn from_startup_flags1(flags1: u8) -> Self {
        if flags1 & 0x02 != 0 {
            Self::Big
        } else {
            Self::Little
        }
    }

    /// Endian as signalled by the image filesystem header flags byte.
    pub const fn from_image_flags(flags: u8) -> Self {
        if flags & 0x01 != 0 {
            Self::Big
        } else {
            Self::Little
        }
    }
}

/// Parsed and validated QNX IFS startup header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupHeader {
    /// Producer's recorded header size; normally 256 and at least the
    /// fixed 64-byte prefix parsed by this crate.
    pub header_size: usize,
    /// Signed 16-bit machine type of the target.
    pub machine: i16,
    /// Startup program virtual address.
    pub startup_vaddr: u32,
    /// Bias applied to physical addresses.
    pub paddr_bias: u32,
    /// Physical address where the image is loaded.
    pub image_paddr: u32,
    /// Physical address of the RAM image.
    pub ram_paddr: u32,
    /// Size of the RAM used by the startup program.
    pub ram_size: u32,
    /// Size of the (never compressed) startup program.
    pub startup_size: usize,
    /// Size of the entire stored image, including the startup header.
    pub stored_size: usize,
    /// Where the IPL sets the image filesystem when the startup runs.
    pub imagefs_paddr: u32,
    /// Size of the uncompressed image filesystem.
    pub imagefs_size: u32,
    /// Size of the preloaded part of the startup.
    pub preboot_size: u16,
    /// Byte order of this image.
    pub endian: Endian,
    /// Decompression type of the filesystem region.
    pub compress: Compress,
}

/// Startup header with a compile-time byte order.
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug)]
#[repr(C, packed)]
struct StartupHeaderBytes<O: ByteOrder> {
    signature: [u8; 4],
    version: U16<O>,
    flags1: u8,
    flags2: u8,
    header_size: U16<O>,
    machine: U16<O>,
    startup_vaddr: U32<O>,
    paddr_bias: U32<O>,
    image_paddr: U32<O>,
    ram_paddr: U32<O>,
    ram_size: U32<O>,
    startup_size: U32<O>,
    stored_size: U32<O>,
    imagefs_paddr: U32<O>,
    imagefs_size: U32<O>,
    preboot_size: U16<O>,
    /// `zero0` (2 bytes) followed by `zero[3]` (12 bytes); must all be zero.
    zeros: [u8; 14],
}

/// Parse and validate the startup header at `offset`.
pub fn parse_startup_header(data: &[u8], offset: usize) -> Result<StartupHeader, Error> {
    let bytes = data.get(offset..).ok_or(Error::BadOffset)?;
    if bytes.len() < STARTUP_HEADER_SIZE {
        return Err(Error::Truncated);
    }

    // The magic and flag bytes are endian neutral, so the byte order is
    // known before the rest of the header is parsed.
    let signature = &bytes[..4];
    if signature != STARTUP_MAGIC_LE && signature != STARTUP_MAGIC_BE {
        return Err(Error::BadStartupHeader);
    }
    let endian = Endian::from_startup_flags1(bytes[6]);

    let hdr = match endian {
        Endian::Little => {
            let (raw, _) = StartupHeaderBytes::<LE>::ref_from_prefix(bytes)
                .map_err(|_| Error::BadStartupHeader)?;
            build_startup_header(raw)?
        }
        Endian::Big => {
            let (raw, _) = StartupHeaderBytes::<BE>::ref_from_prefix(bytes)
                .map_err(|_| Error::BadStartupHeader)?;
            build_startup_header(raw)?
        }
    };
    Ok(hdr)
}

/// Convert a byte order specific raw header into the public, validated form.
fn build_startup_header<O: ByteOrder>(raw: &StartupHeaderBytes<O>) -> Result<StartupHeader, Error> {
    if raw.version.get() != STARTUP_HDR_VERSION {
        return Err(Error::BadStartupHeader);
    }
    if raw.flags2 != 0 {
        return Err(Error::BadStartupHeader);
    }
    if !raw.zeros.iter().all(|&b| b == 0) {
        return Err(Error::BadStartupHeaderZeros);
    }
    if (raw.header_size.get() as usize) < STARTUP_HEADER_SIZE {
        return Err(Error::BadStartupHeader);
    }

    let header_size = raw.header_size.get() as usize;
    let startup_size = raw.startup_size.get() as usize;
    let stored_size = raw.stored_size.get() as usize;
    if startup_size < header_size || stored_size < startup_size {
        return Err(Error::BadStartupHeader);
    }

    let compress = match raw.flags1 & 0x1c {
        0x00 => Compress::None,
        0x04 => Compress::Zlib,
        0x08 => Compress::Lzo,
        0x0c => Compress::Ucl,
        other => return Err(Error::UnknownCompression(other)),
    };

    Ok(StartupHeader {
        header_size,
        machine: raw.machine.get() as i16,
        startup_vaddr: raw.startup_vaddr.get(),
        paddr_bias: raw.paddr_bias.get(),
        image_paddr: raw.image_paddr.get(),
        ram_paddr: raw.ram_paddr.get(),
        ram_size: raw.ram_size.get(),
        startup_size,
        stored_size,
        imagefs_paddr: raw.imagefs_paddr.get(),
        imagefs_size: raw.imagefs_size.get(),
        preboot_size: raw.preboot_size.get(),
        endian: Endian::from_startup_flags1(raw.flags1),
        compress,
    })
}
