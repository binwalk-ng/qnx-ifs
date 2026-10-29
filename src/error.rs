//! Error type and message formatting for the crate.

/// Errors produced while parsing or decompressing QNX IFS images.
///
/// The enum is `#[non_exhaustive]`: new variants may be added in minor
/// releases without a breaking change, so `match` arms need a catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Data ended unexpectedly while parsing a structure.
    Truncated,
    /// The startup header signature or version number is not valid.
    BadStartupHeader,
    /// A startup header reserve/zero field contained non-zero data.
    BadStartupHeaderZeros,
    /// The image filesystem signature is not valid.
    BadImageHeader,
    /// A directory entry of the image filesystem is malformed. The
    /// offset is the byte position of the dirent in the parsed buffer.
    BadDirent {
        /// Absolute byte offset of the dirent.
        offset: usize,
    },
    /// The dirent chain ran out of data without a terminating entry.
    /// The offset is where the last dirent ended.
    UnterminatedDirents {
        /// Absolute byte offset where the chain ran out.
        offset: usize,
    },
    /// A directory entry with an unknown file type was encountered.
    UnknownDirentType {
        /// Absolute byte offset of the dirent.
        offset: usize,
    },
    /// The startup header declares an unknown compression type.
    UnknownCompression(u8),
    /// The requested backend is compiled out of this build.
    FeatureDisabled(&'static str),
    /// A decompression backend rejected the compressed data, with context.
    Decompress(String),
    /// The decompressed data exceeded a configured sanity limit.
    DecompressTooLarge,
    /// A configured [`Limits`](crate::Limits) bound was exceeded.
    LimitsExceeded,
    /// Data referenced by an offset lies outside the image.
    BadOffset,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "data truncated while parsing"),
            Self::BadStartupHeader => write!(f, "invalid QNX IFS startup header"),
            Self::BadStartupHeaderZeros => write!(f, "startup header zero fields not zero"),
            Self::BadImageHeader => write!(f, "invalid QNX IFS image filesystem header"),
            Self::BadDirent { offset } => {
                write!(
                    f,
                    "malformed image filesystem directory entry at offset {offset:#x}"
                )
            }
            Self::UnterminatedDirents { offset } => {
                write!(
                    f,
                    "dirent chain ended without terminating entry at offset {offset:#x}"
                )
            }
            Self::UnknownDirentType { offset } => {
                write!(
                    f,
                    "directory entry at offset {offset:#x} has unknown file type"
                )
            }
            Self::UnknownCompression(t) => {
                write!(f, "unknown compression flags value 0x{t:02x}")
            }
            Self::FeatureDisabled(feat) => {
                write!(f, "decompression backend \"{feat}\" is compiled out")
            }
            Self::Decompress(msg) => write!(f, "decompression failed: {msg}"),
            Self::DecompressTooLarge => {
                write!(f, "decompressed size exceeds configured limit")
            }
            Self::LimitsExceeded => write!(f, "parsing limit exceeded"),
            Self::BadOffset => write!(f, "struct field offset out of bounds"),
        }
    }
}

impl std::error::Error for Error {}
