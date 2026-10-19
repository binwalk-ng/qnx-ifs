//! End-to-end tests over synthetic IFS images.
//!
//! Images are built byte by byte following the documented on-disk
//! structures (`sys/startup.h`, `sys/image.h`), then round-tripped
//! through the crate's parser. The fixtures cover the uncompressed path
//! in both byte orders, zlib, LZO and UCL compressed variants, bare
//! `imagefs` filesystems, symlinks and device nodes, plus validation
//! error cases.
#![allow(clippy::panic)] // test assertions panic by design

use qnx_ifs::{Endian, Entry, EntryKind, Error, Image};

mod common;

/// Byte order helper for building raw structures.
#[derive(Clone, Copy)]
struct E {
    be: bool,
}

impl E {
    const LE: Self = Self { be: false };
    const BE: Self = Self { be: true };

    const fn u16(self, value: u16) -> [u8; 2] {
        if self.be {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        }
    }

    const fn u32(self, value: u32) -> [u8; 4] {
        if self.be {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        }
    }
}

/// Compression variants exercised by the fixture builder.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // variants are conditionally compiled with their feature
enum TestCompress {
    None,
    Zlib,
    Gzip,
    Lzo,
    Ucl,
}

const fn align4(value: usize) -> usize {
    value.div_ceil(4) * 4
}

const fn align8(value: usize) -> usize {
    value.div_ceil(8) * 8
}

/// Build the 256 byte startup header (64 fixed bytes plus zeroed
/// `info[48]`), using the byte order selected by `endian`.
fn startup_header(
    endian: E,
    flags1: u8,
    header_size: usize,
    startup_size: usize,
    stored_size: usize,
    imagefs_size: usize,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(256);
    if endian.be {
        header.extend_from_slice(&[0x00, 0xFF, 0x7E, 0xEB]);
    } else {
        header.extend_from_slice(&[0xEB, 0x7E, 0xFF, 0x00]);
    }
    header.extend_from_slice(&endian.u16(1)); // version
    header.push(flags1);
    header.push(0); // flags2
    header.extend_from_slice(&endian.u16(header_size as u16));
    header.extend_from_slice(&endian.u16(1)); // machine (x86pc)
    header.extend_from_slice(&endian.u32(0x0010_0000)); // startup_vaddr
    header.extend_from_slice(&endian.u32(0)); // paddr_bias
    header.extend_from_slice(&endian.u32(0x0010_0000)); // image_paddr
    header.extend_from_slice(&endian.u32(0x0010_0000)); // ram_paddr
    header.extend_from_slice(&endian.u32(0x1000)); // ram_size
    header.extend_from_slice(&endian.u32(startup_size as u32));
    header.extend_from_slice(&endian.u32(stored_size as u32));
    header.extend_from_slice(&endian.u32(0)); // imagefs_paddr
    header.extend_from_slice(&endian.u32(imagefs_size as u32));
    header.extend_from_slice(&endian.u16(0)); // preboot_size
    header.extend_from_slice(&[0u8; 14]); // zero0 + zero[3]
    assert_eq!(header.len(), 64);
    header.extend(std::iter::repeat_n(0u8, 192)); // info[48]
    assert_eq!(header.len(), 256);
    header
}

/// Build the image filesystem header (`struct image_header`) including
/// the mountpoint string and its padding.
fn image_header(
    endian: E,
    image_size: usize,
    hdr_dir_size: usize,
    dir_offset: usize,
    mountpoint: &str,
) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(b"imagefs");
    header.push(if endian.be { 0x01 } else { 0x00 });
    header.extend_from_slice(&endian.u32(image_size as u32));
    header.extend_from_slice(&endian.u32(hdr_dir_size as u32));
    header.extend_from_slice(&endian.u32(dir_offset as u32));
    for _ in 0..4 {
        header.extend_from_slice(&endian.u32(0)); // boot_ino
    }
    header.extend_from_slice(&endian.u32(0)); // script_ino
    header.extend_from_slice(&endian.u32(0)); // chain_paddr
    for _ in 0..10 {
        header.extend_from_slice(&endian.u32(0)); // spare
    }
    header.extend_from_slice(&endian.u32(0)); // mountflags
    header.extend_from_slice(mountpoint.as_bytes());
    header.push(0);
    let aligned = align4(header.len());
    header.resize(aligned, 0);
    header
}

/// Build the 24 byte `struct image_attr`.
fn attr(endian: E, size: u16, ino: u32, mode: u32) -> Vec<u8> {
    let mut value = Vec::with_capacity(24);
    value.extend_from_slice(&endian.u16(size));
    value.extend_from_slice(&endian.u16(0)); // extattr_offset
    value.extend_from_slice(&endian.u32(ino));
    value.extend_from_slice(&endian.u32(mode));
    value.extend_from_slice(&endian.u32(0)); // gid
    value.extend_from_slice(&endian.u32(0)); // uid
    value.extend_from_slice(&endian.u32(1)); // mtime
    value
}

/// Size a dirent will occupy, rounded up to four bytes.
const fn dirent_size(kind_fixed: usize, path: &str, target: Option<&str>) -> usize {
    let mut raw = kind_fixed + path.len() + 1;
    if let Some(target) = target {
        raw += target.len() + 1;
    }
    align4(raw)
}

/// Build one dirent: attr, type-specific fixed fields, path, optional
/// inline symlink target, then padding to the recorded (rounded) size.
fn dirent(
    endian: E,
    kind_fixed: usize,
    extra: &[u8],
    path: &str,
    target: Option<&str>,
    ino: u32,
    mode: u32,
) -> Vec<u8> {
    let size = dirent_size(kind_fixed, path, target);
    let mut value = Vec::with_capacity(size);
    value.extend_from_slice(&attr(endian, size as u16, ino, mode));
    value.extend_from_slice(extra);
    value.extend_from_slice(path.as_bytes());
    value.push(0);
    if let Some(target) = target {
        value.extend_from_slice(target.as_bytes());
        value.push(0);
    }
    value.resize(size, 0);
    value
}

fn file_extra(endian: E, offset: usize, size: usize) -> Vec<u8> {
    let mut extra = Vec::new();
    extra.extend_from_slice(&endian.u32(offset as u32));
    extra.extend_from_slice(&endian.u32(size as u32));
    extra
}

fn device_extra(endian: E, dev: u32, rdev: u32) -> Vec<u8> {
    let mut extra = Vec::new();
    extra.extend_from_slice(&endian.u32(dev));
    extra.extend_from_slice(&endian.u32(rdev));
    extra
}

const MOUNTPOINT: &str = "/fs";
const SHELL: &[u8] = b"#!/bin/sh\n";
const LINK_TARGET: &str = "/bin/sh";
const LINK_PATH: &str = "bin/link";

/// Fixed image header plus mountpoint for [`MOUNTPOINT`].
const HEADER_LEN: usize = 92;
/// Sum of all dirent sizes in [`build_filesystem`].
const DIR_AREA: usize = 28 + 28 + 40 + 48 + 28 + 44 + 40 + 44 + 44 + 44;
/// Start offset of each dirent, relative to the start of the dirent area,
/// in the order produced by [`build_filesystem`].
const ENTRY_OFFSETS: [usize; 10] = [0, 28, 56, 96, 144, 172, 216, 256, 300, 344];

const FILE_INO: u32 = 11;
const LINK_INO: u32 = 12;
const CHAR_INO: u32 = 20;
const BLOCK_INO: u32 = 21;
const FIFO_INO: u32 = 22;
const NAMED_INO: u32 = 23;
const SOCKET_INO: u32 = 24;

/// Build a synthetic image filesystem blob: header, dirent chain with a
/// terminator, file contents and the image trailer.
fn build_filesystem(endian: E) -> Vec<u8> {
    let header_len = align4(88 + 1 + MOUNTPOINT.len());
    assert_eq!(header_len, 92);

    // Compute directory entry sizes first: the file entry needs the
    // absolute (header relative) data offset.
    let sizes = [
        dirent_size(24, "", None),                     // root directory
        dirent_size(24, "bin", None),                  // bin
        dirent_size(32, "bin/sh", None),               // bin/sh
        dirent_size(28, LINK_PATH, Some(LINK_TARGET)), // bin/link
        dirent_size(24, "dev", None),                  // dev
        dirent_size(32, "dev/console", None),
        dirent_size(32, "dev/blk", None),
        dirent_size(32, "dev/fifo", None),
        dirent_size(32, "dev/name", None),
        dirent_size(32, "dev/sock", None),
    ];
    let dir_area: usize = sizes.iter().sum();
    assert_eq!(dir_area, DIR_AREA);
    let mut cursor = 0;
    for (size, expected) in sizes.iter().zip(ENTRY_OFFSETS) {
        assert_eq!(cursor, expected);
        cursor += size;
    }
    let data_offset = header_len + dir_area + 4;
    let image_size = data_offset + SHELL.len() + 4;
    let hdr_dir_size = header_len + dir_area + 4;

    let mut filesystem = image_header(endian, image_size, hdr_dir_size, header_len, MOUNTPOINT);
    let mut push = |entry: Vec<u8>| filesystem.extend_from_slice(&entry);

    push(dirent(endian, 24, &[], "", None, 1, 0o040755));
    push(dirent(endian, 24, &[], "bin", None, 10, 0o040755));
    push(dirent(
        endian,
        32,
        &file_extra(endian, data_offset, SHELL.len()),
        "bin/sh",
        None,
        FILE_INO,
        0o100755,
    ));

    // mkifs records the path length plus NUL in `sym_offset`, then
    // stores the target inline after the path.
    let sym_offset = (LINK_PATH.len() + 1) as u16;
    let mut symlink_extra = Vec::new();
    symlink_extra.extend_from_slice(&endian.u16(sym_offset));
    symlink_extra.extend_from_slice(&endian.u16((LINK_TARGET.len() + 1) as u16));
    push(dirent(
        endian,
        28,
        &symlink_extra,
        LINK_PATH,
        Some(LINK_TARGET),
        LINK_INO,
        0o120777,
    ));

    push(dirent(endian, 24, &[], "dev", None, 13, 0o040755));
    push(dirent(
        endian,
        32,
        &device_extra(endian, 0x1234, 0x5678),
        "dev/console",
        None,
        CHAR_INO,
        0o020600,
    ));
    push(dirent(
        endian,
        32,
        &device_extra(endian, 0x0102, 0x0304),
        "dev/blk",
        None,
        BLOCK_INO,
        0o060600,
    ));
    push(dirent(
        endian,
        32,
        &device_extra(endian, 0, 0),
        "dev/fifo",
        None,
        FIFO_INO,
        0o010600,
    ));
    push(dirent(
        endian,
        32,
        &device_extra(endian, 0xAAAA, 0xBBBB),
        "dev/name",
        None,
        NAMED_INO,
        0o050600,
    ));
    push(dirent(
        endian,
        32,
        &device_extra(endian, 0, 0),
        "dev/sock",
        None,
        SOCKET_INO,
        0o140600,
    ));

    // A zero size entry terminates the chain; mkifs reserves four bytes.
    filesystem.extend_from_slice(&[0u8; 4]);
    assert_eq!(filesystem.len(), data_offset);

    filesystem.extend_from_slice(SHELL);
    filesystem.extend_from_slice(&[0u8; 4]); // image trailer
    assert_eq!(filesystem.len(), image_size);
    filesystem
}

/// Frame an LZO1X compressed blob as mkifs does: big-endian length
/// followed by block data, terminated by a zero length.
#[cfg(feature = "lzo")]
fn lzo_frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(1024) {
        let compressed = lzokay::compress::compress(chunk).expect("lzo compress");
        assert!(compressed.len() <= u16::MAX as usize);
        out.extend_from_slice(&(compressed.len() as u16).to_be_bytes());
        out.extend_from_slice(&compressed);
    }
    out.extend_from_slice(&[0, 0]);
    out
}

#[cfg(feature = "ucl")]
fn ucl_frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(1024) {
        let compressed = common::ucl_literal_block(chunk);
        assert!(compressed.len() <= u16::MAX as usize);
        out.extend_from_slice(&(compressed.len() as u16).to_be_bytes());
        out.extend_from_slice(&compressed);
    }
    out.extend_from_slice(&[0, 0]);
    out
}

#[cfg(feature = "zlib")]
fn zlib_stream(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("zlib write");
    encoder.finish().expect("zlib finish")
}

#[cfg(feature = "zlib")]
fn gzip_stream(data: &[u8]) -> Vec<u8> {
    use std::io::Write;

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Wrap a filesystem blob in a startup header and, when requested,
/// compress it exactly like `mkifs` does.
fn build_image(endian: E, compress: TestCompress) -> Vec<u8> {
    let filesystem = build_filesystem(endian);
    let startup_endian_flag = if endian.be { 0x02 } else { 0x00 };

    let (compress_flag, payload, startup_size) = match compress {
        TestCompress::None => {
            let program = b"\x7fELF";
            let startup_size = align8(256 + program.len());
            let mut payload = program.to_vec();
            payload.resize(startup_size - 256, 0);
            payload.extend_from_slice(&filesystem);
            (0x00, payload, startup_size)
        }
        TestCompress::Zlib => {
            #[cfg(feature = "zlib")]
            {
                (0x04, zlib_stream(&filesystem), 260)
            }
            #[cfg(not(feature = "zlib"))]
            {
                let _ = &filesystem;
                panic!("zlib feature disabled")
            }
        }
        TestCompress::Gzip => {
            #[cfg(feature = "zlib")]
            {
                (0x04, gzip_stream(&filesystem), 260)
            }
            #[cfg(not(feature = "zlib"))]
            {
                let _ = &filesystem;
                panic!("zlib feature disabled")
            }
        }
        TestCompress::Lzo => {
            #[cfg(feature = "lzo")]
            {
                (0x08, lzo_frame(&filesystem), 260)
            }
            #[cfg(not(feature = "lzo"))]
            {
                let _ = &filesystem;
                panic!("lzo feature disabled")
            }
        }
        TestCompress::Ucl => {
            #[cfg(feature = "ucl")]
            {
                (0x0c, ucl_frame(&filesystem), 260)
            }
            #[cfg(not(feature = "ucl"))]
            {
                let _ = &filesystem;
                panic!("ucl feature disabled")
            }
        }
    };

    let stored_size = 256 + payload.len() + usize::from(compress != TestCompress::None) * 4;
    let flags1 = startup_endian_flag | compress_flag;
    let mut image = startup_header(
        endian,
        flags1,
        256,
        startup_size,
        stored_size,
        filesystem.len(),
    );
    if compress != TestCompress::None {
        image.extend_from_slice(&[0u8; 4]); // startup trailer
    }
    image.extend_from_slice(&payload);
    assert_eq!(image.len(), stored_size);
    image
}
fn shell_entry<'a>(image: &'a Image<'_>) -> &'a Entry {
    image
        .entries
        .iter()
        .find(|entry| entry.path == "bin/sh")
        .expect("bin/sh entry")
}

fn link_entry<'a>(image: &'a Image<'_>) -> &'a Entry {
    image
        .entries
        .iter()
        .find(|entry| entry.path == LINK_PATH)
        .expect("symlink entry")
}

fn device_entry<'a>(image: &'a Image<'_>, path: &str) -> &'a Entry {
    image
        .entries
        .iter()
        .find(|entry| entry.path == path)
        .unwrap_or_else(|| panic!("{path} entry"))
}

#[test]
fn parses_uncompressed_le_image() {
    let image_bytes = build_image(E::LE, TestCompress::None);
    let parsed = Image::parse(&image_bytes).expect("parse");

    let startup = parsed.startup.expect("startup header");
    assert_eq!(startup.header_size, 256);
    assert_eq!(startup.startup_size, 264);
    assert_eq!(startup.stored_size, image_bytes.len());
    assert_eq!(startup.imagefs_size as usize, build_filesystem(E::LE).len());
    assert_eq!(parsed.startup_offset, 0);
    assert_eq!(parsed.endian, Endian::Little);
    assert_eq!(parsed.image_header.mountpoint, MOUNTPOINT);
    assert_eq!(parsed.total_size(), image_bytes.len());
    assert_eq!(parsed.entries.len(), 10);

    let startup_bytes = parsed.startup_bytes().expect("startup bytes");
    assert_eq!(startup_bytes.len(), 8);
    assert_eq!(&startup_bytes[..4], b"\x7fELF");

    let shell = shell_entry(&parsed);
    match &shell.kind {
        EntryKind::File { size, .. } => assert_eq!(size, &SHELL.len()),
        other => panic!("wrong kind: {other:?}"),
    }
    assert_eq!(parsed.file_bytes(shell).expect("file bytes"), SHELL);
    assert_eq!(shell.ino, FILE_INO);
    assert_eq!(shell.permissions(), 0o755);

    match &link_entry(&parsed).kind {
        EntryKind::Symlink { target } => assert_eq!(target, LINK_TARGET),
        other => panic!("wrong kind: {other:?}"),
    }

    let bin = parsed
        .entries
        .iter()
        .find(|entry| entry.path == "bin")
        .expect("bin entry");
    assert_eq!(bin.kind, EntryKind::Dir);
    assert_eq!(bin.permissions(), 0o755);

    match &device_entry(&parsed, "dev/console").kind {
        EntryKind::Char { dev, rdev } => {
            assert_eq!(*dev, 0x1234);
            assert_eq!(*rdev, 0x5678);
        }
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(matches!(
        device_entry(&parsed, "dev/blk").kind,
        EntryKind::Block {
            dev: 0x0102,
            rdev: 0x0304
        }
    ));
    assert!(matches!(
        device_entry(&parsed, "dev/fifo").kind,
        EntryKind::Fifo { dev: 0, rdev: 0 }
    ));
    assert!(matches!(
        device_entry(&parsed, "dev/name").kind,
        EntryKind::Named {
            dev: 0xAAAA,
            rdev: 0xBBBB
        }
    ));
    assert!(matches!(
        device_entry(&parsed, "dev/sock").kind,
        EntryKind::Socket { .. }
    ));

    assert_eq!(parsed.raw_bytes(), &image_bytes[..]);
}

#[test]
fn parses_uncompressed_be_image() {
    let image_bytes = build_image(E::BE, TestCompress::None);
    let parsed = Image::parse(&image_bytes).expect("parse");

    assert_eq!(parsed.endian, Endian::Big);
    assert_eq!(parsed.startup.expect("startup header").endian, Endian::Big);
    assert_eq!(parsed.total_size(), image_bytes.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
    match &link_entry(&parsed).kind {
        EntryKind::Symlink { target } => assert_eq!(target, LINK_TARGET),
        other => panic!("wrong kind: {other:?}"),
    }
    assert!(matches!(
        device_entry(&parsed, "dev/console").kind,
        EntryKind::Char {
            dev: 0x1234,
            rdev: 0x5678
        }
    ));
}

#[cfg(feature = "zlib")]
#[test]
fn parses_zlib_compressed_image() {
    let image_bytes = build_image(E::LE, TestCompress::Zlib);
    let parsed = Image::parse(&image_bytes).expect("parse");

    assert!(matches!(
        parsed.startup.expect("startup header").compress,
        qnx_ifs::Compress::Zlib
    ));
    assert!(matches!(parsed.filesystem, qnx_ifs::ImageData::Owned(_)));
    assert_eq!(parsed.total_size(), image_bytes.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
    match &link_entry(&parsed).kind {
        EntryKind::Symlink { target } => assert_eq!(target, LINK_TARGET),
        other => panic!("wrong kind: {other:?}"),
    }
}

#[cfg(feature = "lzo")]
#[test]
fn parses_lzo_compressed_image() {
    let image_bytes = build_image(E::LE, TestCompress::Lzo);
    let parsed = Image::parse(&image_bytes).expect("parse");

    assert!(matches!(
        parsed.startup.expect("startup header").compress,
        qnx_ifs::Compress::Lzo
    ));
    assert_eq!(parsed.total_size(), image_bytes.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
    match &link_entry(&parsed).kind {
        EntryKind::Symlink { target } => assert_eq!(target, LINK_TARGET),
        other => panic!("wrong kind: {other:?}"),
    }
}

#[cfg(feature = "ucl")]
#[test]
fn parses_ucl_compressed_image() {
    let image_bytes = build_image(E::BE, TestCompress::Ucl);
    let parsed = Image::parse(&image_bytes).expect("parse");

    assert!(matches!(
        parsed.startup.expect("startup header").compress,
        qnx_ifs::Compress::Ucl
    ));
    assert_eq!(parsed.endian, Endian::Big);
    assert_eq!(parsed.total_size(), image_bytes.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
}

#[test]
fn parses_bare_imagefs() {
    let filesystem = build_filesystem(E::LE);
    let parsed = Image::parse(&filesystem).expect("parse bare imagefs");

    assert!(parsed.startup.is_none());
    assert_eq!(parsed.startup_offset, 0);
    assert_eq!(parsed.header_offset, 0);
    assert!(parsed.startup_bytes().is_none());
    assert_eq!(parsed.total_size(), filesystem.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
}

#[test]
fn parse_imagefs_finds_header_after_prefix() {
    let filesystem = build_filesystem(E::BE);
    let mut container = vec![0xAA; 32];
    container.extend_from_slice(&filesystem);

    let parsed = Image::parse_imagefs(&container).expect("parse prefixed imagefs");
    assert!(parsed.startup.is_none());
    assert_eq!(parsed.header_offset, 32);
    assert_eq!(parsed.endian, Endian::Big);
    assert_eq!(parsed.total_size(), container.len());
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
}

#[test]
fn skips_zero_inode_entries() {
    let filesystem = build_filesystem(E::LE);
    let parsed = Image::parse(&filesystem).expect("parse");
    assert!(parsed.entries.iter().all(|entry| entry.ino != 0));
}

#[test]
fn rejects_bad_startup_header() {
    let mut data = build_image(E::LE, TestCompress::None);
    data[4] = 0x09; // version bump
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadStartupHeader);

    let mut data = build_image(E::LE, TestCompress::None);
    data[8] = 0x10; // header_size = 16, below the minimum
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadStartupHeader);
}

#[test]
fn rejects_truncated_image() {
    let data = build_image(E::LE, TestCompress::None);
    let truncated = &data[..data.len() - 1];
    assert_eq!(Image::parse(truncated).unwrap_err(), Error::Truncated);

    let short = &data[..40];
    assert_eq!(Image::parse(short).unwrap_err(), Error::BadStartupHeader);
}

#[test]
fn rejects_bad_image_header_sizes() {
    // The image filesystem starts at offset 264 for uncompressed images.
    let filesystem_offset = 264;
    let original = build_image(E::LE, TestCompress::None);

    let mut data = original.clone();
    let image_size_at = filesystem_offset + 8;
    data[image_size_at..image_size_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadImageHeader);

    let mut data = original.clone();
    let hdr_dir_size_at = filesystem_offset + 12;
    data[hdr_dir_size_at..hdr_dir_size_at + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadImageHeader);

    let mut data = original;
    let dir_offset_at = filesystem_offset + 16;
    data[dir_offset_at..dir_offset_at + 4].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadImageHeader);
}

#[test]
fn rejects_bad_dirents() {
    // First dirent begins at 264 + 92 for uncompressed images.
    let first_dirent = 264 + HEADER_LEN;
    let terminator = first_dirent + DIR_AREA;

    let mut data = build_image(E::LE, TestCompress::None);
    data[first_dirent..first_dirent + 2].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadDirent);

    // Remove the terminator so the chain runs into the file data.
    let mut data = build_image(E::LE, TestCompress::None);
    data[terminator..terminator + 2].copy_from_slice(&0x0200u16.to_le_bytes());
    assert!(matches!(
        Image::parse(&data).unwrap_err(),
        Error::UnknownDirentType | Error::BadDirent | Error::UnterminatedDirents
    ));
}

#[test]
fn rejects_file_outside_image() {
    // Patch the file offset field of bin/sh.
    let filesystem_offset = 264;
    let shell_offset_field = filesystem_offset + HEADER_LEN + 28 + 28 + 24; // root + bin + attr
    let mut data = build_image(E::LE, TestCompress::None);
    data[shell_offset_field..shell_offset_field + 4].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadOffset);
}

#[test]
fn startup_bytes_respect_recorded_header_size() {
    let data = build_image(E::LE, TestCompress::None);
    let parsed = Image::parse(&data).expect("parse");
    let startup_bytes = parsed.startup_bytes().expect("startup bytes");
    assert_eq!(startup_bytes, &data[256..264]);
}

#[test]
fn rejects_invalid_startup_sizes() {
    // startup_size (offset 32) below header_size (256).
    let mut data = build_image(E::LE, TestCompress::None);
    data[32..36].copy_from_slice(&8u32.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadStartupHeader);

    // stored_size (offset 36) below startup_size.
    let mut data = build_image(E::LE, TestCompress::None);
    data[36..40].copy_from_slice(&4u32.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadStartupHeader);
}

#[test]
fn reports_unknown_compression_from_header_parser() {
    let mut data = build_image(E::LE, TestCompress::None);
    data[6] = 0x10; // reserved compression value in flags1
    assert_eq!(
        qnx_ifs::parse_startup_header(&data, 0).unwrap_err(),
        Error::UnknownCompression(0x10)
    );
    // The full-image parser only accepts fully valid startup headers.
    assert_eq!(Image::parse(&data).unwrap_err(), Error::BadStartupHeader);
}

#[test]
fn skips_entries_with_zero_inode() {
    let mut data = build_image(E::LE, TestCompress::None);
    let fifo = 264 + HEADER_LEN + ENTRY_OFFSETS[7];
    data[fifo + 4..fifo + 8].fill(0); // attr.ino of dev/fifo

    let parsed = Image::parse(&data).expect("parse");
    assert_eq!(parsed.entries.len(), 9);
    assert!(parsed.entries.iter().all(|entry| entry.path != "dev/fifo"));
    // The chain must continue past the skipped entry.
    assert!(parsed.entries.iter().any(|entry| entry.path == "dev/sock"));
}

#[test]
fn rejects_unknown_dirent_type() {
    let mut data = build_image(E::LE, TestCompress::None);
    let fifo = 264 + HEADER_LEN + ENTRY_OFFSETS[7];
    data[fifo + 8..fifo + 12].copy_from_slice(&0o030000u32.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::UnknownDirentType);
}

#[test]
fn rejects_unterminated_dirent_chain() {
    // A filesystem with one directory entry and no zero-size terminator.
    let mut filesystem = image_header(E::LE, 128, 128, HEADER_LEN, MOUNTPOINT);
    filesystem.extend(dirent(E::LE, 24, &[], "bin", None, 10, 0o040755));
    let error = qnx_ifs::parse_dirents(&filesystem, 0, HEADER_LEN, Endian::Little).unwrap_err();
    assert_eq!(error, Error::UnterminatedDirents);
}

#[cfg(feature = "zlib")]
#[test]
fn parses_gzip_compressed_image() {
    let image_bytes = build_image(E::LE, TestCompress::Gzip);
    let parsed = Image::parse(&image_bytes).expect("parse");

    assert!(matches!(
        parsed.startup.expect("startup header").compress,
        qnx_ifs::Compress::Zlib
    ));
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
    match &link_entry(&parsed).kind {
        EntryKind::Symlink { target } => assert_eq!(target, LINK_TARGET),
        other => panic!("wrong kind: {other:?}"),
    }
}

#[cfg(feature = "zlib")]
#[test]
fn enforces_decompression_limit() {
    let image_bytes = build_image(E::LE, TestCompress::Zlib);
    let limits = qnx_ifs::Limits {
        max_decompressed: 16,
    };
    assert_eq!(
        Image::parse_with_limits(&image_bytes, &limits).unwrap_err(),
        Error::DecompressTooLarge
    );
}

#[cfg(feature = "lzo")]
#[test]
fn rejects_truncated_lzo_chunk_stream() {
    let mut data = build_image(E::LE, TestCompress::Lzo);
    data.truncate(data.len() - 2); // drop the zero-length terminator
    let stored_size = data.len() as u32;
    data[36..40].copy_from_slice(&stored_size.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::Truncated);
}

#[cfg(feature = "ucl")]
#[test]
fn rejects_truncated_ucl_chunk_stream() {
    let mut data = build_image(E::LE, TestCompress::Ucl);
    data.truncate(data.len() - 2); // drop the zero-length terminator
    let stored_size = data.len() as u32;
    data[36..40].copy_from_slice(&stored_size.to_le_bytes());
    assert_eq!(Image::parse(&data).unwrap_err(), Error::Truncated);
}
