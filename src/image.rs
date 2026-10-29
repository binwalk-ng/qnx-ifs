//! QNX IFS image filesystem header and directory entry parsing.
//!
//! The image filesystem ("imagefs") header is followed by a flat chain of
//! variable size directory entries, each storing its own full path without
//! a leading slash. All fields use the byte order selected by the
//! `IMAGE_FLAGS_BIGENDIAN` header flag.
//!
//! Entry layout (fixed part), as produced by `mkifs`:
//!
//! ```text
//! struct image_attr:      24 bytes, part of every entry
//!   u16 size              size of this dirent
//!   u16 extattr_offset    offset of extended attributes, 0 = none
//!   u32 ino               inode number
//!   u32 mode              type and permission bits
//!   u32 gid               group id (stored before uid)
//!   u32 uid               user id
//!   u32 mtime             modification time (unix epoch)
//!
//! image_file:    attr ++ u32 offset ++ u32 size ++ NUL terminated path
//!                (file data at [hdr + offset, size])
//! image_dir:     attr ++ NUL terminated path
//! image_symlink: attr ++ u16 sym_offset ++ u16 sym_size ++ path ++ target
//!                (sym_offset is relative to `path`; target string of
//!                 sym_size bytes follows the path, inline in the dirent)
//! image_device:  attr ++ u32 dev ++ u32 rdev ++ path
//! ```

use zerocopy::{
    FromBytes, Immutable, KnownLayout, U16, U32, Unaligned,
    byteorder::{BE, ByteOrder, LE},
};

use crate::Limits;
use crate::error::Error;
use crate::startup::Endian;

use memchr_n::MemchrN;

/// Image filesystem signature.
pub const IMAGE_SIGNATURE: &[u8; 7] = b"imagefs";

/// File type selector for mode bits.
pub const S_IFMT: u32 = 0o170000;
/// FIFO device.
pub const S_IFIFO: u32 = 0o010000;
/// Character device.
pub const S_IFCHR: u32 = 0o020000;
/// Directory.
pub const S_IFDIR: u32 = 0o040000;
/// QNX named special file (semaphores / shared memory names).
pub const S_IFNAM: u32 = 0o050000;
/// Block device.
pub const S_IFBLK: u32 = 0o060000;
/// Regular file.
pub const S_IFREG: u32 = 0o100000;
/// Symbolic link.
pub const S_IFLNK: u32 = 0o120000;
/// Socket (defensive; not produced by `mkifs`).
pub const S_IFSOCK: u32 = 0o140000;

/// Image header flags.
pub mod image_flags {
    /// Header, trailer and dirents are stored in big endian format.
    pub const BIGENDIAN: u8 = 0x01;
    /// The image filesystem is read only (rom/flash).
    pub const READONLY: u8 = 0x02;
    /// Inode bits are valid.
    pub const INO_BITS: u8 = 0x04;
}

/// Byte size of the fixed part of the image header (`struct image_header`);
/// the NUL terminated `mountpoint` follows at this offset.
pub const IMAGE_HEADER_SIZE: usize = size_of::<ImageHeaderBytes<LE>>();

/// Recording cap for skipped dirents: bounds the memory a hostile image
/// can force the parser to spend on quarantine records.
pub const MAX_OMITTED_DIRENTS: usize = 100_000;

/// Common directory entry attributes (`struct image_attr`), 24 bytes.
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug)]
#[repr(C, packed)]
struct AttrBytes<O: ByteOrder> {
    size: U16<O>,
    extattr_offset: U16<O>,
    ino: U32<O>,
    mode: U32<O>,
    gid: U32<O>,
    uid: U32<O>,
    mtime: U32<O>,
}

/// Type specific fields of a regular file dirent (`struct image_file`).
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug)]
#[repr(C, packed)]
struct FileExtraBytes<O: ByteOrder> {
    offset: U32<O>,
    size: U32<O>,
}

/// Type specific fields of a symlink dirent (`struct image_symlink`).
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug)]
#[repr(C, packed)]
struct SymlinkExtraBytes<O: ByteOrder> {
    sym_offset: U16<O>,
    sym_size: U16<O>,
}

/// Type specific fields of a device dirent (`struct image_device`).
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug)]
#[repr(C, packed)]
struct DeviceExtraBytes<O: ByteOrder> {
    dev: U32<O>,
    rdev: U32<O>,
}

/// Fixed sizes of the dirent prefixes, derived from the structs above.
/// The wire format does not depend on the byte order, so the `LE` form
/// is used for the derivation.
const ATTR_SIZE: usize = size_of::<AttrBytes<LE>>();
/// Fixed part of a file dirent, before the stored path.
const FILE_DIRENT_FIXED: usize = ATTR_SIZE + size_of::<FileExtraBytes<LE>>();
/// Fixed part of a symlink dirent; the stored path starts here and
/// `sym_offset` is relative to it.
const SYMLINK_DIRENT_FIXED: usize = ATTR_SIZE + size_of::<SymlinkExtraBytes<LE>>();
/// Fixed part of a device dirent, before the stored path.
const DEVICE_DIRENT_FIXED: usize = ATTR_SIZE + size_of::<DeviceExtraBytes<LE>>();

/// On-disk image filesystem header (`struct image_header`), up to the
/// NUL terminated `mountpoint` string.
///
/// Multi-byte fields are [`U32`] byte-order wrappers; convert with their
/// `get` method. Instantiate with `LE` or `BE` according to the header's
/// [`BIGENDIAN`](crate::image::image_flags::BIGENDIAN) flag.
/// [`parse_image_header`] validates the size
/// and offset relationships (see [`validate_image_header`]) and parses
/// these fields into [`ImageHeader`].
///
/// # Example
///
/// ```no_run
/// use qnx_ifs::ImageHeaderBytes;
/// use zerocopy::{FromBytes, LE};
///
/// # fn caller(data: &[u8]) -> Option<(u32, &[u8])> {
/// let (raw, rest) = ImageHeaderBytes::<LE>::ref_from_prefix(data).ok()?;
/// let nul = rest.iter().position(|&b| b == 0)?;
/// Some((raw.image_size.get(), &rest[..nul]))
/// # }
/// ```
///
/// `signature` is not checked; compare it with [`IMAGE_SIGNATURE`].
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug)]
#[repr(C, packed)]
pub struct ImageHeaderBytes<O: ByteOrder> {
    /// Image signature, always `imagefs`.
    pub signature: [u8; 7],
    /// Flag byte; [`image_flags`] names the bits.
    pub flags: u8,
    /// Byte size from the header to the end of the image trailer.
    pub image_size: U32<O>,
    /// Byte size from the header to the last directory entry.
    pub hdr_dir_size: U32<O>,
    /// Offset from the header to the first directory entry.
    pub dir_offset: U32<O>,
    /// Inodes of the bootstrap programs.
    pub boot_ino: [U32<O>; 4],
    /// Inode of the startup script.
    pub script_ino: U32<O>,
    /// Physical address of a chained image filesystem.
    pub chain_paddr: U32<O>,
    /// Reserved; `mkifs` writes zero.
    pub spare: [U32<O>; 10],
    /// Default mount flags.
    pub mountflags: U32<O>,
    // A NUL terminated `mountpoint` string follows the fixed fields.
}

/// Parsed image filesystem header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ImageHeader {
    /// Size from the header to the end of the image trailer.
    pub image_size: usize,
    /// Size from the header to the last directory entry.
    pub hdr_dir_size: usize,
    /// Offset from the header to the first directory entry.
    pub dir_offset: usize,
    /// Inodes of the bootstrap programs.
    pub boot_ino: [u32; 4],
    /// Inode of the startup script.
    pub script_ino: u32,
    /// Physical address of a chained image filesystem.
    pub chain_paddr: u32,
    /// Default mount flags.
    pub mountflags: u32,
    /// Plain flags bytes of the header.
    pub flags: u8,
    /// Default mountpoint of the image filesystem.
    pub mountpoint: String,
    /// Mountpoint as raw stored bytes, before the lossy UTF-8 conversion
    /// behind [`ImageHeader::mountpoint`]. Firmware paths may be
    /// arbitrary bytes.
    pub raw_mountpoint: Vec<u8>,
}

/// A single entry of the image filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// Stored entry path, without a leading slash.
    pub path: String,
    /// Stored entry path as raw bytes, before the lossy UTF-8 conversion
    /// behind [`Entry::path`]. Firmware paths may be arbitrary bytes; use
    /// these for byte-exact disk output.
    pub raw_path: Vec<u8>,
    /// Entry payload.
    pub kind: EntryKind,
    /// Inode number.
    ///
    /// Zero-inode dirents are skipped while parsing (the kernel skips
    /// them) and reported through [`crate::Image::omitted_dirents`], so
    /// parsed entries in [`crate::Image::entries`] never have a zero
    /// inode here.
    pub ino: u32,
    /// Raw mode bits, including the file type bits.
    pub mode: u32,
    /// Unix user id.
    pub uid: u32,
    /// Unix group id (note: stored before `uid` on disk).
    pub gid: u32,
    /// Modification time, unix epoch seconds.
    pub mtime: u32,
    /// Offset of extended attribute data, zero if none.
    pub extattr_offset: u16,
}

/// The type specific payload of a directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// Directory.
    Dir,
    /// Regular file; contents start `offset` bytes after the image header.
    File {
        /// Offset from the image header to the file contents.
        offset: usize,
        /// File content size.
        size: usize,
    },
    /// Symbolic link.
    Symlink {
        /// Symlink target string.
        target: String,
        /// Symlink target as raw bytes, before the lossy UTF-8 conversion.
        raw_target: Vec<u8>,
    },
    /// Character device node.
    Char {
        /// Packed device id.
        dev: u32,
        /// Real device id.
        rdev: u32,
    },
    /// Block device node.
    Block {
        /// Packed device id.
        dev: u32,
        /// Real device id.
        rdev: u32,
    },
    /// Named pipe.
    Fifo {
        /// Packed device id.
        dev: u32,
        /// Real device id.
        rdev: u32,
    },
    /// QNX named special file (semaphore or shared memory name).
    Named {
        /// Named special id.
        dev: u32,
        /// Real device id.
        rdev: u32,
    },
    /// Socket.
    Socket {
        /// Packed device id.
        dev: u32,
        /// Real device id.
        rdev: u32,
    },
}

/// A directory entry the parser skipped because the kernel would skip it
/// (`ino == 0`).
///
/// Recorded for transparency: skipped dirents never appear in
/// [`Image::entries`](crate::Image::entries) and are not extracted, but
/// their position and fixed-size attribute fields remain available for
/// reporting. No strings are parsed from them, and recording stops at
/// [`MAX_OMITTED_DIRENTS`] to bound memory on hostile images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmittedDirent {
    /// Byte offset of the dirent, relative to the image header
    /// (`Image::header_offset`).
    pub offset: usize,
    /// Recorded size of the dirent (at least 24).
    pub size: usize,
    /// Raw mode bits, including the file type bits.
    pub mode: u32,
    /// Offset of extended attribute data, zero if none.
    pub extattr_offset: u16,
}

impl Entry {
    /// Permission bits (`mode & 07777`).
    pub const fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }
}

/// Cast a byte order dependent structure out of a byte slice prefix.
fn cast_prefix<T>(bytes: &[u8], err: Error) -> Result<&T, Error>
where
    T: FromBytes + KnownLayout + Immutable,
{
    T::ref_from_prefix(bytes).map(|(t, _)| t).map_err(|_| err)
}

/// Parse the common attributes of a dirent at absolute offset `offset`.
fn parse_attr(dirent: &[u8], endian: Endian, offset: usize) -> Result<AttrParsed, Error> {
    match endian {
        Endian::Little => {
            let attr = cast_prefix::<AttrBytes<LE>>(dirent, Error::BadDirent { offset })?;
            Ok(AttrParsed::from_bytes(attr))
        }
        Endian::Big => {
            let attr = cast_prefix::<AttrBytes<BE>>(dirent, Error::BadDirent { offset })?;
            Ok(AttrParsed::from_bytes(attr))
        }
    }
}

/// Byte order independent copy of `struct image_attr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AttrParsed {
    extattr_offset: u16,
    ino: u32,
    mode: u32,
    gid: u32,
    uid: u32,
    mtime: u32,
}

impl AttrParsed {
    const fn from_bytes<O: ByteOrder>(raw: &AttrBytes<O>) -> Self {
        Self {
            extattr_offset: raw.extattr_offset.get(),
            ino: raw.ino.get(),
            mode: raw.mode.get(),
            gid: raw.gid.get(),
            uid: raw.uid.get(),
            mtime: raw.mtime.get(),
        }
    }

    const fn entry_common(self, path: String, raw_path: Vec<u8>, kind: EntryKind) -> Entry {
        Entry {
            path,
            raw_path,
            kind,
            ino: self.ino,
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            mtime: self.mtime,
            extattr_offset: self.extattr_offset,
        }
    }
}

/// Scan `data` for the `"imagefs"` signature.
///
/// Returns the offset of the first signature match, if any. The match is
/// not validated: a container may hold look-alike strings before the
/// real header, so prefer [`Image::parse_imagefs`](crate::Image::parse_imagefs),
/// which tries each match in turn.
pub fn find_image_header(data: &[u8]) -> Option<usize> {
    if data.len() < IMAGE_SIGNATURE.len() {
        return None;
    }
    let potential = &data[..data.len() - IMAGE_SIGNATURE.len() + 1];
    // Every occurrence starts with the same first byte, SIMD-scanned.
    MemchrN::new(b"i")
        .iter(potential)
        .find(|&off| matches_signature(data, off))
}

/// Byte offsets of every `"imagefs"` signature match in `data`.
///
/// Signature matches are not validated headers. Parse each candidate
/// with [`parse_image_header`], which validates the recorded sizes and
/// rejects look-alikes with [`Error::BadImageHeader`]; the first
/// candidate that also walks a complete dirent chain is the image.
/// [`Image::parse_imagefs`](crate::Image::parse_imagefs) does exactly
/// this and is the simpler entry point.
pub fn find_image_header_matches(data: &[u8]) -> Vec<usize> {
    if data.len() < IMAGE_SIGNATURE.len() {
        return Vec::new();
    }
    let potential = &data[..data.len() - IMAGE_SIGNATURE.len() + 1];
    let candidates = MemchrN::new(b"i");
    candidates
        .iter(potential)
        .filter(|&off| matches_signature(data, off))
        .collect()
}

/// Compare the seven signature bytes at `offset`.
fn matches_signature(data: &[u8], offset: usize) -> bool {
    &data[offset..offset + IMAGE_SIGNATURE.len()] == IMAGE_SIGNATURE
}

/// Parse the image filesystem header at `offset`.
///
/// The byte order comes from the `IMAGE_FLAGS_BIGENDIAN` flag byte; the
/// mountpoint string follows the fixed fields.
///
/// The recorded sizes are validated with [`validate_image_header`], so
/// the whole image must be present in `data`: this rejects headers whose
/// `image_size` exceeds the buffer. Callers holding only a header prefix
/// must locate the full image first.
pub fn parse_image_header(data: &[u8], offset: usize) -> Result<(ImageHeader, Endian), Error> {
    let bytes = data.get(offset..).ok_or(Error::BadOffset)?;
    if bytes.len() < IMAGE_HEADER_SIZE {
        return Err(Error::Truncated);
    }

    // The flags byte is endian neutral and selects the byte order of the rest.
    let endian = Endian::from_image_flags(bytes[7]);
    let (image_size, hdr_dir_size, dir_offset, boot_ino, script_ino, chain_paddr, mountflags) =
        match endian {
            Endian::Little => header_fixed_fields_checked::<LE>(bytes)?,
            Endian::Big => header_fixed_fields_checked::<BE>(bytes)?,
        };

    let mut header = ImageHeader {
        image_size,
        hdr_dir_size,
        dir_offset,
        boot_ino,
        script_ino,
        chain_paddr,
        mountflags,
        flags: bytes[7],
        mountpoint: String::new(),
        raw_mountpoint: Vec::new(),
    };

    // Validate the declared sizes before reading anything out of the
    // dirent area. The mountpoint scan is then bounded by a `dir_offset`
    // that is known to be within `hdr_dir_size` and the input.
    validate_image_header(data, offset, &header)?;

    // The mountpoint is a NUL terminated string bounded by the dirent
    // area. It only exists when `dir_offset` leaves room after the fixed
    // fields; a `dir_offset` of exactly the fixed header size means there
    // is no mountpoint at all.
    let mountpoint_end = header.dir_offset.min(bytes.len());
    let (mountpoint, raw) = cstring(&bytes[IMAGE_HEADER_SIZE..mountpoint_end]);
    header.mountpoint = mountpoint;
    header.raw_mountpoint = raw.to_vec();

    Ok((header, endian))
}

/// Parse and signature-check the fixed fields of the header at `bytes`.
fn header_fixed_fields_checked<O: ByteOrder>(bytes: &[u8]) -> Result<HeaderFields, Error> {
    let (raw, _) =
        ImageHeaderBytes::<O>::ref_from_prefix(bytes).map_err(|_| Error::BadImageHeader)?;
    if &raw.signature != IMAGE_SIGNATURE {
        return Err(Error::BadImageHeader);
    }
    Ok(header_fixed_fields(raw))
}

/// Endian-independent fixed fields of a header.
type HeaderFields = (usize, usize, usize, [u32; 4], u32, u32, u32);

/// The signature must have been verified by the caller.
const fn header_fixed_fields<O: ByteOrder>(
    raw: &ImageHeaderBytes<O>,
) -> (usize, usize, usize, [u32; 4], u32, u32, u32) {
    (
        raw.image_size.get() as usize,
        raw.hdr_dir_size.get() as usize,
        raw.dir_offset.get() as usize,
        [
            raw.boot_ino[0].get(),
            raw.boot_ino[1].get(),
            raw.boot_ino[2].get(),
            raw.boot_ino[3].get(),
        ],
        raw.script_ino.get(),
        raw.chain_paddr.get(),
        raw.mountflags.get(),
    )
}

/// Validate the sizes recorded in an image filesystem header:
///
/// * `dir_offset` must be at least the fixed header size and not exceed
///   `hdr_dir_size`
/// * `hdr_dir_size` must not exceed `image_size - trailer`
/// * the whole image must fit inside the available bytes
///
/// Exposed so callers doing signature detection can validate a candidate
/// header before committing to a full parse, without duplicating these
/// rules.
pub fn validate_image_header(
    slice: &[u8],
    header_offset: usize,
    header: &ImageHeader,
) -> Result<(), Error> {
    let available = slice
        .len()
        .checked_sub(header_offset)
        .ok_or(Error::BadOffset)?;
    if header.dir_offset < IMAGE_HEADER_SIZE
        || header.dir_offset > header.hdr_dir_size
        || header.image_size < header.hdr_dir_size.saturating_add(4)
        || header.image_size > available
    {
        return Err(Error::BadImageHeader);
    }
    Ok(())
}

/// Walk the flat directory entry chain beginning at `dir_pos`.
///
/// `base` is the offset of the image header within `data`; a zero size
/// entry ends the chain and every entry must lie inside `data`.
///
/// Dirents marked with a zero inode are skipped (the kernel skips them,
/// and untrusted dirents must not enter the extraction set) and are not
/// included in the returned entries. Whole-image callers can inspect
/// the skipped records through [`crate::Image::omitted_dirents`].
///
/// Entry count is bounded by [`Limits::default`].
pub fn parse_dirents(
    data: &[u8],
    base: usize,
    dir_pos: usize,
    endian: Endian,
) -> Result<Vec<Entry>, Error> {
    let (entries, _) = parse_dirents_bounded(
        data,
        base,
        dir_pos,
        data.len(),
        data.len(),
        endian,
        &Limits::default(),
    )?;
    Ok(entries)
}

/// Walk the dirent chain with explicit bounds and limits.
///
/// The chain must end with a zero size entry at or before `dir_end`
/// (the end of the image directory area), and referenced file contents
/// must end at or before `data_end`.
///
/// Returns the entries plus the quarantine records for skipped
/// zero-inode dirents (see [`OmittedDirent`]).
pub(crate) fn parse_dirents_bounded(
    data: &[u8],
    base: usize,
    dir_pos: usize,
    dir_end: usize,
    data_end: usize,
    endian: Endian,
    limits: &Limits,
) -> Result<(Vec<Entry>, Vec<OmittedDirent>), Error> {
    let mut entries = Vec::new();
    let mut omitted: Vec<OmittedDirent> = Vec::new();
    let mut pos = dir_pos;

    loop {
        // Only two bytes are required to detect the terminator: mkifs
        // reserves four, but the stored entry is a zero `u16` size.
        let header_end = pos
            .checked_add(2)
            .ok_or(Error::UnterminatedDirents { offset: pos })?;
        if header_end > dir_end || header_end > data_end {
            return Err(Error::UnterminatedDirents { offset: pos });
        }
        let size_bytes = &data[pos..header_end];
        let size = match endian {
            Endian::Little => u16::from_le_bytes([size_bytes[0], size_bytes[1]]),
            Endian::Big => u16::from_be_bytes([size_bytes[0], size_bytes[1]]),
        } as usize;

        if size == 0 {
            return Ok((entries, omitted));
        }
        if size < ATTR_SIZE {
            return Err(Error::BadDirent { offset: pos });
        }
        let end = pos
            .checked_add(size)
            .ok_or(Error::BadDirent { offset: pos })?;
        if end > dir_end || end > data_end {
            return Err(Error::BadDirent { offset: pos });
        }
        let dirent = &data[pos..end];
        let attr = parse_attr(&dirent[..ATTR_SIZE], endian, pos)?;

        // The kernel skips entries whose inode is zero (sys/image.h).
        // They are recorded in the quarantine list rather than being
        // silently dropped; no strings are parsed from them.
        if attr.ino == 0 {
            if omitted.len() < MAX_OMITTED_DIRENTS
                && let Some(offset) = pos.checked_sub(base)
            {
                omitted.push(OmittedDirent {
                    offset,
                    size,
                    mode: attr.mode,
                    extattr_offset: attr.extattr_offset,
                });
            }
            pos = end;
            continue;
        }

        let entry = match attr.mode & S_IFMT {
            S_IFREG => parse_file_entry(data, base, pos, dirent, &attr, endian, data_end)?,
            S_IFDIR => parse_dir_entry(dirent, &attr),
            S_IFLNK => parse_symlink_entry(pos, dirent, &attr, endian)?,
            S_IFCHR | S_IFBLK | S_IFIFO | S_IFNAM | S_IFSOCK => {
                parse_device_entry(pos, dirent, &attr, endian)?
            }
            _ => return Err(Error::UnknownDirentType { offset: pos }),
        };
        if entries.len() >= limits.max_entries {
            return Err(Error::LimitsExceeded);
        }
        entries.push(entry);
        pos = end;
    }
}

/// Read the type specific fields of a file dirent in byte order `O`.
fn file_extra_fields<O: ByteOrder>(bytes: &[u8], offset: usize) -> Result<(usize, usize), Error> {
    let extra = cast_prefix::<FileExtraBytes<O>>(bytes, Error::BadDirent { offset })?;
    Ok((extra.offset.get() as usize, extra.size.get() as usize))
}

/// Read the type specific fields of a symlink dirent in byte order `O`.
fn symlink_extra_fields<O: ByteOrder>(
    bytes: &[u8],
    offset: usize,
) -> Result<(usize, usize), Error> {
    let extra = cast_prefix::<SymlinkExtraBytes<O>>(bytes, Error::BadDirent { offset })?;
    Ok((
        extra.sym_offset.get() as usize,
        extra.sym_size.get() as usize,
    ))
}

/// Read the type specific fields of a device dirent in byte order `O`.
fn device_extra_fields<O: ByteOrder>(bytes: &[u8], offset: usize) -> Result<(u32, u32), Error> {
    let extra = cast_prefix::<DeviceExtraBytes<O>>(bytes, Error::BadDirent { offset })?;
    Ok((extra.dev.get(), extra.rdev.get()))
}

/// Read a NUL terminated string from a bounded slice.
///
/// Returns the lossy UTF-8 rendering together with the raw stored bytes
/// (excluding the NUL terminator, if any). Strings without a NUL in the
/// bound are returned up to the bound.
fn cstring(bytes: &[u8]) -> (String, &[u8]) {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    (
        String::from_utf8_lossy(&bytes[..end]).into_owned(),
        &bytes[..end],
    )
}

/// Parse a `S_IFREG` directory entry.
fn parse_file_entry(
    data: &[u8],
    base: usize,
    offset: usize,
    dirent: &[u8],
    attr: &AttrParsed,
    endian: Endian,
    data_end: usize,
) -> Result<Entry, Error> {
    if dirent.len() < FILE_DIRENT_FIXED {
        return Err(Error::BadDirent { offset });
    }
    let (file_offset, size) = match endian {
        Endian::Little => file_extra_fields::<LE>(&dirent[ATTR_SIZE..], offset)?,
        Endian::Big => file_extra_fields::<BE>(&dirent[ATTR_SIZE..], offset)?,
    };
    let (path, raw_path) = cstring(&dirent[FILE_DIRENT_FIXED..]);

    // File contents must lie inside the image data.
    let abs = base
        .checked_add(file_offset)
        .and_then(|abs| abs.checked_add(size))
        .ok_or(Error::BadOffset)?;
    if abs > data_end || abs > data.len() {
        return Err(Error::BadOffset);
    }

    Ok(attr.entry_common(
        path,
        raw_path.to_vec(),
        EntryKind::File {
            offset: file_offset,
            size,
        },
    ))
}

/// Parse a `S_IFDIR` directory entry.
fn parse_dir_entry(dirent: &[u8], attr: &AttrParsed) -> Entry {
    if dirent.len() > ATTR_SIZE {
        let (path, raw_path) = cstring(&dirent[ATTR_SIZE..]);
        attr.entry_common(path, raw_path.to_vec(), EntryKind::Dir)
    } else {
        attr.entry_common(String::new(), Vec::new(), EntryKind::Dir)
    }
}

/// Parse a `S_IFLNK` directory entry.
///
/// `sym_offset` is relative to the `path` field; the target of
/// `sym_size` bytes follows the path inline.
fn parse_symlink_entry(
    offset: usize,
    dirent: &[u8],
    attr: &AttrParsed,
    endian: Endian,
) -> Result<Entry, Error> {
    if dirent.len() < SYMLINK_DIRENT_FIXED {
        return Err(Error::BadDirent { offset });
    }
    let (sym_offset, sym_size) = match endian {
        Endian::Little => symlink_extra_fields::<LE>(&dirent[ATTR_SIZE..], offset)?,
        Endian::Big => symlink_extra_fields::<BE>(&dirent[ATTR_SIZE..], offset)?,
    };

    let path_end = SYMLINK_DIRENT_FIXED
        .checked_add(sym_offset)
        .ok_or(Error::BadDirent { offset })?;
    let (path, raw_path) = cstring(
        dirent
            .get(SYMLINK_DIRENT_FIXED..path_end)
            .ok_or(Error::BadDirent { offset })?,
    );

    let kind = if sym_size == 0 {
        EntryKind::Symlink {
            target: String::new(),
            raw_target: Vec::new(),
        }
    } else {
        let target_end = path_end
            .checked_add(sym_size)
            .ok_or(Error::BadDirent { offset })?;
        let (target, raw_target) = cstring(
            dirent
                .get(path_end..target_end)
                .ok_or(Error::BadDirent { offset })?,
        );
        EntryKind::Symlink {
            target,
            raw_target: raw_target.to_vec(),
        }
    };

    Ok(attr.entry_common(path, raw_path.to_vec(), kind))
}

/// Parse a device type directory entry (char/block/fifo/named/socket).
fn parse_device_entry(
    offset: usize,
    dirent: &[u8],
    attr: &AttrParsed,
    endian: Endian,
) -> Result<Entry, Error> {
    if dirent.len() < DEVICE_DIRENT_FIXED {
        return Err(Error::BadDirent { offset });
    }
    let (dev, rdev) = match endian {
        Endian::Little => device_extra_fields::<LE>(&dirent[ATTR_SIZE..], offset)?,
        Endian::Big => device_extra_fields::<BE>(&dirent[ATTR_SIZE..], offset)?,
    };

    let kind = match attr.mode & S_IFMT {
        S_IFCHR => EntryKind::Char { dev, rdev },
        S_IFBLK => EntryKind::Block { dev, rdev },
        S_IFNAM => EntryKind::Named { dev, rdev },
        S_IFSOCK => EntryKind::Socket { dev, rdev },
        _ => EntryKind::Fifo { dev, rdev },
    };
    let (path, raw_path) = cstring(&dirent[DEVICE_DIRENT_FIXED..]);
    Ok(attr.entry_common(path, raw_path.to_vec(), kind))
}
