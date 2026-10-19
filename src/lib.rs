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
//!   (files, directories, symbolic links, and device nodes)
//! - Decompression of the compressed filesystem region according to
//!   `startup_hdr.flags1`:
//!     - `0x04` zlib
//!     - `0x08` LZO1X
//!     - `0x0C` UCL NRV2B *(clean-room implementation)*
//! - An in-memory entry model
//!
//! This crate performs **no filesystem I/O**. Writing entries to disk
//! (path sanitization, symlink handling, permissions, timestamps) is
//! intentionally left to callers, e.g. binwalk-ng's internal extractor
//! layer which applies them through its `Chroot` API.
//!
//! ## Licensing
//!
//! MIT. Implementations are derived from publicly documented on-disk
//! structures and black-box behaviour, not from QNX-licensed source, so
//! this crate is safe to redistribute alongside MIT code.

pub mod error;
pub mod image;
pub mod ucl;

pub use error::Error;
pub use image::{
    Entry, EntryKind, ImageHeader, find_image_header, parse_dirents, parse_image_header,
    parse_image_header as parse_imagefs_header,
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
    /// All offsets stored by [`Entry`] variants are relative to this.
    pub header_offset: usize,
    /// Parsed image filesystem header.
    pub image_header: ImageHeader,
    /// Byte order of the image filesystem structures.
    pub endian: Endian,
    /// All directory entries.
    pub entries: Vec<Entry>,
    /// Filesystem data: dirents and file contents live in this buffer.
    pub filesystem: ImageData<'a>,
    /// The complete input buffer; used to report startup program bytes.
    source: &'a [u8],
}

impl<'a> Image<'a> {
    /// Parse an IFS image with default [`Limits`].
    ///
    /// The input may start with a startup header (bootable image) or be a
    /// bare `imagefs` filesystem. Use [`Image::parse_imagefs`] when a bare
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
        let Some((startup_offset, startup)) = startup::find_startup_header(data) else {
            if data.starts_with(image::IMAGE_SIGNATURE) {
                return Self::parse_imagefs_with_limits(data, limits);
            }
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
                let mut decoded = decompress::decompress_region(region, startup.compress, limits)?;
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
        let entries = image::parse_dirents_bounded(
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
}

/// Size of a regular file entry payload.
const fn entry_file_size(entry: &Entry) -> usize {
    match &entry.kind {
        EntryKind::File { size, .. } => *size,
        _ => 0,
    }
}
