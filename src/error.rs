//! Error type and message formatting for the crate.

/// Errors produced while parsing or decompressing QNX IFS images.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Data ended unexpectedly while parsing a structure.
    Truncated,
    /// The startup header signature or version number is not valid.
    BadStartupHeader,
    /// A startup header reserve/zeros field contained non-zero data.
    BadStartupHeaderZeros,
    /// The image filesystem signature is not valid.
    BadImageHeader,
    /// A directory entry of the image filesystem is malformed.
    BadDirent,
    /// The dirent chain ran out of data without a terminating entry.
    UnterminatedDirents,
    /// A directory entry with an unknown file type was encountered.
    UnknownDirentType,
    /// The startup header declares an unknown compression type.
    UnknownCompression(u8),
    /// The requested backend is compiled out of this build.
    FeatureDisabled(&'static str),
    /// A decompression backend rejected the compressed data.
    Decompress(&'static str),
    /// A decompression backend rejected the compressed data, with context.
    Decompression(String),
    /// The decompressed data exceeded a configured sanity limit.
    DecompressTooLarge,
    /// A string field was not NUL terminated within its declared bounds.
    UnterminatedString,
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
            Self::BadDirent => write!(f, "malformed image filesystem directory entry"),
            Self::UnterminatedDirents => {
                write!(f, "dirent chain ended without terminating entry")
            }
            Self::UnknownDirentType => write!(f, "directory entry has unknown file type"),
            Self::UnknownCompression(t) => {
                write!(f, "unknown compression flags value 0x{t:02x}")
            }
            Self::FeatureDisabled(feat) => {
                write!(f, "decompression backend \"{feat}\" is compiled out")
            }
            Self::Decompress(msg) => write!(f, "decompression failed: {msg}"),
            Self::Decompression(msg) => write!(f, "decompression failed: {msg}"),
            Self::DecompressTooLarge => {
                write!(f, "decompressed size exceeds configured limit")
            }
            Self::UnterminatedString => write!(f, "string field not NUL terminated"),
            Self::BadOffset => write!(f, "struct field offset out of bounds"),
        }
    }
}

impl std::error::Error for Error {}
