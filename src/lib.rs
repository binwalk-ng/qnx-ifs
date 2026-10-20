#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # qnx-ifs
//!
//! Pure-Rust parser and decompressor for QNX IFS ("Image File System")
//! firmware images, as produced by QNX `mkifs`/`mkxfs`.
//!
//! ## Usage
//!
//! ```no_run
//! # use qnx_ifs::{Image, Limits};
//! # fn caller(data: &[u8]) -> Result<(), qnx_ifs::Error> {
//! let image = Image::parse_with_limits(data, &Limits::default())?;
//! println!("mountpoint: {}", image.image_header.mountpoint);
//! for entry in &image.entries {
//!     println!("  {entry:?}");
//!     if let qnx_ifs::EntryKind::File { size, .. } = &entry.kind {
//!         let contents = image.file_bytes(entry).unwrap_or(&[]);
//!         assert_eq!(contents.len(), *size);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Scope
//!
//! - Startup header validation (`0x00FF7EEB` signature, version, and
//!   zero-field checks), little- and big-endian images
//! - Image filesystem header and dirent chain walking
//!   (files, directories, symbolic links, and device nodes); dirents the
//!   kernel would skip (`ino == 0`) stay out of the entry list and are
//!   reported in [`Image::omitted_dirents`]
//! - Decompression of the compressed filesystem region according to
//!   `startup_hdr.flags1`, bounded by the declared image extent:
//!     - `0x04` zlib
//!     - `0x08` LZO1X
//!     - `0x0C` UCL NRV2B *(clean-room implementation)*
//! - An in-memory entry model, including raw stored path bytes for
//!   byte-exact extraction of non-UTF-8 names
//!
//! This crate performs **no filesystem I/O**. Writing entries to disk
//! (path sanitization, symlink handling, permissions, timestamps) is
//! intentionally left to callers, e.g. binwalk-ng's internal extractor
//! layer which applies them through its `Chroot` API.
//!
//! ## Parsing policy
//!
//! Parsing mirrors the reference `dumpifs` tool where that is also the
//! defensive choice: a bare `imagefs` filesystem at the very start of the
//! input takes precedence over a whole-buffer startup-header search, so
//! embedded look-alike data deeper in the image cannot hijack the parse.
//! Structural checks are strict by default; reserve-field leniency for
//! damaged images (the `dumpifs -z` behaviour) is opt-in through
//! [`ParseOptions::lenient_startup_header`].
//!
//! ## Licensing
//!
//! MIT. Implementations are derived from publicly documented on-disk
//! structures and black-box behaviour, not from QNX-licensed source, so
//! this crate is safe to redistribute alongside MIT code.

pub mod error;
pub mod image;
#[cfg(feature = "ucl")]
pub mod ucl;

pub use error::Error;
pub use image::{
    Entry, EntryKind, ImageHeader, MAX_OMITTED_DIRENTS, OmittedDirent, find_image_header,
    parse_dirents, parse_image_header,
};

mod startup;
pub use startup::{Compress, Endian, StartupHeader, find_startup_header, parse_startup_header};

pub mod decompress;
pub use decompress::{BLOCK_MAX_OUTPUT, Limits};

/// Decompressed filesystem data or a borrowed view of uncompressed data.
#[derive(Debug, PartialEq, Eq)]
pub enum ImageData<'a> {
    /// The image carried the filesystem uncompressed.
    Borrowed(&'a [u8]),
    /// The image carried the filesystem compressed; owned decompressed data.
    Owned(Box<[u8]>),
}

impl<'a> ImageData<'a> {
    /// The filesystem bytes.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(borrowed) => borrowed,
            Self::Owned(owned) => owned,
        }
    }
}

impl std::ops::Deref for ImageData<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for ImageData<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<ImageData<'_>> for Vec<u8> {
    fn from(value: ImageData<'_>) -> Self {
        match value {
            ImageData::Borrowed(borrowed) => borrowed.to_vec(),
            ImageData::Owned(owned) => owned.into(),
        }
    }
}

/// Tunable parsing policy.
///
/// Parsing is defensive by default; every option here *relaxes* exactly
/// one documented check, always opt-in.
#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOptions {
    /// Bounding decompression work.
    pub limits: Limits,
    /// Accept startup headers whose reserve fields (`zero0`/`zero[3]`)
    /// are non-zero or whose reserved `flags2` byte is set — the
    /// behaviour of `dumpifs -z`, for damaged or vendor-patched images.
    ///
    /// Strict validation (the default) rejects both, matching binwalk-ng's
    /// signature check. Signature, version and size-relationship checks
    /// are never relaxed.
    pub lenient_startup_header: bool,
}

/// Stored and recomputed trailer checksum pair.
///
/// The recomputation follows the reference tool's rule: sum the 32-bit
/// words of the covered region (in the image's byte order) and negate.
/// Avoids the reference tool's host-endian sloppiness on big-endian
/// images.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checksums {
    /// Value read from the trailer on disk.
    pub stored: u32,
    /// Value recomputed over the region the trailer vouches for.
    pub computed: u32,
}

impl Checksums {
    /// Whether the stored checksum matches the recomputation.
    pub const fn valid(&self) -> bool {
        self.stored == self.computed
    }
}

/// A parsed QNX IFS image.
#[derive(Debug, PartialEq, Eq)]
pub struct Image<'a> {
    /// Startup header, if one was found.
    ///
    /// Bare `imagefs` filesystems (as accepted by [`Image::parse_imagefs`])
    /// carry no startup header.
    pub startup: Option<StartupHeader>,
    /// Offset of the startup header within the raw image bytes.
    ///
    /// Zero when the parsed filesystem is a bare `imagefs` without a
    /// startup header.
    pub startup_offset: usize,
    /// Offset of the image filesystem header within the filesystem data.
    ///
    /// All offsets stored by [`Entry`] and [`OmittedDirent`] are relative
    /// to this.
    pub header_offset: usize,
    /// Parsed image filesystem header.
    pub image_header: ImageHeader,
    /// Byte order of the image filesystem structures.
    pub endian: Endian,
    /// All directory entries the kernel would mount.
    pub entries: Vec<Entry>,
    /// Dirents skipped by the kernel's zero-inode rule, quarantined for
    /// reporting instead of being silently dropped.
    pub omitted_dirents: Vec<OmittedDirent>,
    /// Filesystem data: dirents and file contents live in this buffer.
    pub filesystem: ImageData<'a>,
    /// The complete input buffer; used to report startup program bytes.
    source: &'a [u8],
}

impl<'a> Image<'a> {
    /// Parse an IFS image with default [`ParseOptions`].
    ///
    /// The input may start with a startup header (bootable image) or be a
    /// bare `imagefs` filesystem. A bare filesystem at the very start
    /// takes precedence. Use [`Image::parse_imagefs`] when a bare
    /// filesystem may be preceded by unrelated bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        Self::parse_with_limits(data, &Limits::default())
    }

    /// Parse an IFS image, bounding decompression work by `limits`.
    ///
    /// A compressed filesystem region is decompressed into an owned buffer
    /// and the `"imagefs"` header is searched from the end of the startup
    /// program, as the reference tool does.
    ///
    /// Without a startup header, `data` must begin with an `imagefs`
    /// header; use [`Image::parse_imagefs_with_limits`] to search the
    /// whole input instead.
    pub fn parse_with_limits(data: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        Self::parse_with_options(
            data,
            &ParseOptions {
                limits: *limits,
                lenient_startup_header: false,
            },
        )
    }

    /// Parse an IFS image with a fully specified [`ParseOptions`].
    pub fn parse_with_options(data: &'a [u8], options: &ParseOptions) -> Result<Self, Error> {
        // A bare `imagefs` filesystem at the very start takes precedence,
        // mirroring the reference tool's first search step. This keeps the
        // outcome deterministic: embedded startup-header look-alikes
        // deeper in a bare filesystem cannot hijack the parse.
        if data.starts_with(image::IMAGE_SIGNATURE) {
            return Self::parse_imagefs_with_limits(data, &options.limits);
        }

        let Some((startup_offset, startup)) =
            startup::find_startup_header_lenient(data, options.lenient_startup_header)
        else {
            return Err(Error::BadStartupHeader);
        };

        // Bytes past `stored_size` belong to the container, not the image.
        let startup_end = startup_offset
            .checked_add(startup.startup_size)
            .ok_or(Error::BadStartupHeader)?;
        let stored_end = startup_offset
            .checked_add(startup.stored_size)
            .ok_or(Error::BadStartupHeader)?;
        if stored_end > data.len() {
            return Err(Error::Truncated);
        }

        // A non-zero `imagefs_size` bounds the uncompressed filesystem.
        let declared_filesystem_size = if startup.imagefs_size == 0 {
            None
        } else {
            Some(startup.imagefs_size as usize)
        };

        let (filesystem, search_start) = match startup.compress {
            Compress::None => {
                let slice_end = match declared_filesystem_size {
                    Some(size) => startup_end
                        .checked_add(size)
                        .filter(|&end| end <= stored_end)
                        .ok_or(Error::BadStartupHeader)?,
                    None => stored_end,
                };
                (ImageData::Borrowed(&data[..slice_end]), startup_end)
            }
            Compress::Zlib | Compress::Lzo | Compress::Ucl => {
                let region = &data[startup_end..stored_end];
                let mut decoded =
                    decompress::decompress_region(region, startup.compress, &options.limits)?;
                if let Some(size) = declared_filesystem_size {
                    if decoded.len() < size {
                        return Err(Error::Truncated);
                    }
                    decoded.truncate(size);
                }
                (ImageData::Owned(decoded.into_boxed_slice()), 0)
            }
        };

        let slice = match &filesystem {
            ImageData::Borrowed(borrowed) => *borrowed,
            ImageData::Owned(owned) => owned,
        };
        let search_start = search_start.min(slice.len());
        let relative =
            image::find_image_header(&slice[search_start..]).ok_or(Error::BadImageHeader)?;
        let header_offset = search_start.checked_add(relative).ok_or(Error::BadOffset)?;

        Self::from_parts(
            data,
            Some(startup),
            startup_offset,
            filesystem,
            header_offset,
        )
    }

    /// Parse a bare `imagefs` filesystem, searching the whole input.
    ///
    /// Accepts an `imagefs` header anywhere in `data`, e.g. inside a
    /// container with a vendor-specific prefix.
    pub fn parse_imagefs(data: &'a [u8]) -> Result<Self, Error> {
        Self::parse_imagefs_with_limits(data, &Limits::default())
    }

    /// Parse a bare `imagefs` filesystem with decompression limits.
    ///
    /// Decompression limits are only relevant to full images with a
    /// startup header; bare `imagefs` filesystems are always uncompressed.
    pub fn parse_imagefs_with_limits(data: &'a [u8], limits: &Limits) -> Result<Self, Error> {
        let _ = limits;
        let header_offset = image::find_image_header(data).ok_or(Error::BadImageHeader)?;
        Self::from_parts(data, None, 0, ImageData::Borrowed(data), header_offset)
    }

    /// Finish parsing given a filesystem buffer and header position.
    fn from_parts(
        source: &'a [u8],
        startup: Option<StartupHeader>,
        startup_offset: usize,
        filesystem: ImageData<'a>,
        header_offset: usize,
    ) -> Result<Self, Error> {
        let slice = filesystem.as_slice();
        let (image_header, endian) = image::parse_image_header(slice, header_offset)?;
        image::validate_image_header(slice, header_offset, &image_header)?;

        let dirent_start = header_offset
            .checked_add(image_header.dir_offset)
            .ok_or(Error::BadOffset)?;
        let dirent_end = header_offset
            .checked_add(image_header.hdr_dir_size)
            .ok_or(Error::BadOffset)?;
        let data_end = header_offset
            .checked_add(image_header.image_size)
            .ok_or(Error::BadOffset)?;
        let (entries, omitted_dirents) = image::parse_dirents_bounded(
            slice,
            header_offset,
            dirent_start,
            dirent_end,
            data_end,
            endian,
        )?;

        Ok(Self {
            startup,
            startup_offset,
            header_offset,
            image_header,
            endian,
            entries,
            omitted_dirents,
            filesystem,
            source,
        })
    }

    /// Content of a regular file entry.
    ///
    /// Returns `None` for non-file entries or entries whose declared
    /// contents lie outside the image.
    pub fn file_bytes(&self, entry: &Entry) -> Option<&[u8]> {
        let offset = match &entry.kind {
            EntryKind::File { offset, .. } => *offset,
            _ => return None,
        };
        let image_end = self
            .header_offset
            .checked_add(self.image_header.image_size)?;
        let begin = self.header_offset.checked_add(offset)?;
        let end = begin.checked_add(entry_file_size(entry))?;
        if end > image_end {
            return None;
        }
        self.filesystem.as_slice().get(begin..end)
    }

    /// The raw startup program section (`startup_hdr_size..startup_size`).
    ///
    /// Returns `None` for bare `imagefs` filesystems or when the recorded
    /// header size is inconsistent with the input.
    pub fn startup_bytes(&self) -> Option<&'a [u8]> {
        let startup = self.startup.as_ref()?;
        let begin = self.startup_offset.checked_add(startup.header_size)?;
        let end = self.startup_offset.checked_add(startup.startup_size)?;
        self.source.get(begin..end)
    }

    /// The complete raw input passed to the parser.
    pub const fn raw_bytes(&self) -> &'a [u8] {
        self.source
    }

    /// Total size of the image within [`Image::raw_bytes`].
    ///
    /// This is `startup_offset + stored_size` for bootable images, and
    /// `header_offset + image_size` for bare `imagefs` filesystems.
    pub const fn total_size(&self) -> usize {
        match &self.startup {
            Some(startup) => self.startup_offset.saturating_add(startup.stored_size),
            None => self
                .header_offset
                .saturating_add(self.image_header.image_size),
        }
    }

    /// Filesystem trailer checksum pair (`image_trailer`).
    ///
    /// The computed value sums the 32-bit words of the filesystem region
    /// [header, trailer) in the image's byte order and negates them, the
    /// rule the reference tool applies on little-endian images. Returns
    /// `None` when the image is too small to carry a trailer or its size
    /// is not padded to four bytes.
    pub fn image_checksum(&self) -> Option<Checksums> {
        let total = self.image_header.image_size;
        // One data word plus the trailer word must exist, and mkifs pads
        // the image to a multiple of four.
        if total < 8 || !total.is_multiple_of(4) {
            return None;
        }
        let start = self.header_offset;
        let data_end = start.checked_add(total)?.checked_sub(4)?;
        let end = data_end.checked_add(4)?;
        let bytes = self.filesystem.as_slice();

        let trailer = bytes.get(data_end..end)?;
        let stored = read_word(trailer.try_into().ok()?, self.endian);
        Some(Checksums {
            stored,
            computed: checksum_region(bytes.get(start..data_end)?, self.endian),
        })
    }

    /// Startup trailer checksum pair (`startup_trailer`).
    ///
    /// Covered region is [startup header, trailer) of the startup
    /// section, summed in the startup header's own byte order; mkifs
    /// applies the same negate-and-sum rule as for the filesystem
    /// trailer, and the reference tool only validates the filesystem one.
    /// Returns `None` for bare filesystems or when the startup section is
    /// too small or not padded to four bytes.
    pub fn startup_checksum(&self) -> Option<Checksums> {
        let startup = self.startup.as_ref()?;
        let size = startup.startup_size;
        if size < 8 || !size.is_multiple_of(4) {
            return None;
        }
        let begin = self.startup_offset;
        let data_end = begin.checked_add(size)?.checked_sub(4)?;
        let end = data_end.checked_add(4)?;
        let trailer = self.source.get(data_end..end)?;
        let stored = read_word(trailer.try_into().ok()?, startup.endian);
        Some(Checksums {
            stored,
            computed: checksum_region(self.source.get(begin..data_end)?, startup.endian),
        })
    }
}

/// Read one 32-bit word in the image's byte order.
const fn read_word(word: &[u8; 4], endian: Endian) -> u32 {
    match endian {
        Endian::Little => u32::from_le_bytes(*word),
        Endian::Big => u32::from_be_bytes(*word),
    }
}

/// Reference trailer checksum rule over an exact multiple of four bytes.
fn checksum_region(bytes: &[u8], endian: Endian) -> u32 {
    let mut sum: u32 = 0;
    for word in bytes.as_chunks::<4>().0 {
        sum = sum.wrapping_add(read_word(word, endian));
    }
    sum.wrapping_neg()
}

/// Size of a regular file entry payload.
const fn entry_file_size(entry: &Entry) -> usize {
    match &entry.kind {
        EntryKind::File { size, .. } => *size,
        _ => 0,
    }
}
