//! End-to-end tests over synthetic IFS images.
//!
//! Images are built byte by byte following the documented on-disk
//! structures (`sys/startup.h`, `sys/image.h`), then round-tripped
//! through the crate's parser. The fixtures cover the uncompressed path
//! in both byte orders, zlib, LZO and UCL compressed variants, bare
//! `imagefs` filesystems, symlinks and device nodes, plus validation
//! error cases.
#![allow(clippy::panic)] // test assertions panic by design

use common::fixtures::*;
use qnx_ifs::{Endian, EntryKind, Error, Image};

mod common;

/// Compression variants available under the enabled features.
fn compression_cases() -> Vec<TestCompress> {
    #[allow(unused_mut)] // no pushes when every decoder feature is disabled
    let mut cases = vec![TestCompress::None];
    #[cfg(feature = "zlib")]
    {
        cases.push(TestCompress::Zlib);
        cases.push(TestCompress::Gzip);
    }
    #[cfg(feature = "lzo")]
    cases.push(TestCompress::Lzo);
    #[cfg(feature = "ucl")]
    cases.push(TestCompress::Ucl);
    cases
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
        EntryKind::Symlink { target, .. } => assert_eq!(target, LINK_TARGET),
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
        EntryKind::Symlink { target, .. } => assert_eq!(target, LINK_TARGET),
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
        EntryKind::Symlink { target, .. } => assert_eq!(target, LINK_TARGET),
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
        EntryKind::Symlink { target, .. } => assert_eq!(target, LINK_TARGET),
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
        EntryKind::Symlink { target, .. } => assert_eq!(target, LINK_TARGET),
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

#[test]
fn parses_mountless_bare_imagefs() {
    for endian in [E::LE, E::BE] {
        let filesystem = build_mountless_filesystem(endian);
        let parsed = Image::parse_imagefs(&filesystem).expect("parse");

        assert!(parsed.startup.is_none());
        assert_eq!(parsed.startup_offset, 0);
        assert_eq!(parsed.image_header.dir_offset, 88);
        // No room for a mountpoint string before the dirent area.
        assert_eq!(parsed.image_header.mountpoint, "");
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
        // The size is not padded to four bytes, so there is no computable
        // filesystem checksum.
        assert!(parsed.image_checksum().is_none());
    }
}

#[test]
fn mountpoint_scan_is_bounded_by_header_sizes() {
    let mut filesystem = build_filesystem(E::LE);
    // Inconsistent, attacker-controlled sizes: a huge `dir_offset` and a
    // dirent area that ends exactly at the header. Remove the unpacked
    // mountpoint's NUL terminator so an unbounded scan would continue
    // into the first dirent (whose size byte is 0x1c followed by NUL).
    filesystem[12..16].copy_from_slice(&(HEADER_LEN as u32).to_le_bytes());
    filesystem[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    filesystem[88..92].fill(b'A');

    let (header, _) = qnx_ifs::parse_image_header(&filesystem, 0).expect("header");
    assert_eq!(header.mountpoint, "AAAA");
    assert!(Image::parse_imagefs(&filesystem).is_err());
}

#[test]
fn exported_header_layout_matches_parser() {
    use qnx_ifs::{IMAGE_HEADER_SIZE, ImageHeader, ImageHeaderBytes};
    use zerocopy::FromBytes;
    use zerocopy::byteorder::{BE, ByteOrder, LE};

    /// The exported layout must produce the parser's field values.
    fn assert_fields_match<O: ByteOrder>(raw: &ImageHeaderBytes<O>, header: &ImageHeader) {
        assert_eq!(&raw.signature, qnx_ifs::image::IMAGE_SIGNATURE);
        assert_eq!(raw.image_size.get() as usize, header.image_size);
        assert_eq!(raw.hdr_dir_size.get() as usize, header.hdr_dir_size);
        assert_eq!(raw.dir_offset.get() as usize, header.dir_offset);
        assert_eq!(raw.boot_ino.map(|w| w.get()), header.boot_ino);
        assert_eq!(raw.script_ino.get(), header.script_ino);
        assert_eq!(raw.chain_paddr.get(), header.chain_paddr);
        assert_eq!(raw.mountflags.get(), header.mountflags);
    }

    for (endian, e) in [(Endian::Little, E::LE), (Endian::Big, E::BE)] {
        let filesystem = build_filesystem(e);

        let (header, parsed_endian) = qnx_ifs::parse_image_header(&filesystem, 0).expect("header");
        assert_eq!(parsed_endian, endian);

        match endian {
            Endian::Little => {
                let (raw, _) = ImageHeaderBytes::<LE>::ref_from_prefix(&filesystem).expect("cast");
                assert_fields_match(raw, &header);
            }
            Endian::Big => {
                let (raw, _) = ImageHeaderBytes::<BE>::ref_from_prefix(&filesystem).expect("cast");
                assert_fields_match(raw, &header);
            }
        }

        // `IMAGE_HEADER_SIZE` is where the mountpoint string starts.
        let mountpoint = &filesystem[IMAGE_HEADER_SIZE..IMAGE_HEADER_SIZE + 4];
        assert_eq!(mountpoint, b"/fs\0");
        assert_eq!(header.mountpoint, "/fs");
    }
}

#[test]
fn bare_imagefs_takes_precedence_over_embedded_startup_header() {
    let filesystem = build_filesystem(E::LE);
    let mut data = filesystem.clone();
    // Forge a structurally valid startup header after the filesystem.
    // A whole-buffer-only search would adopt it and misparse the image;
    // the bare filesystem at offset 0 takes precedence.
    data.extend_from_slice(&startup_header(E::LE, 0x00, 256, 256, 300, 0));
    data.extend_from_slice(b"LOOK-ALIKE-PAYLOAD");

    let parsed = Image::parse(&data).expect("parse");
    assert!(parsed.startup.is_none());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.total_size(), filesystem.len());

    // The standalone startup scanner is unaffected: it still finds the
    // forged header when a caller asks for one explicitly.
    assert!(qnx_ifs::find_startup_header(&data).is_some());
}

#[test]
fn parses_uncompressed_image_with_boot_prefix() {
    let mut container = vec![0x55u8; 0x40];
    container.extend_from_slice(&build_image(E::LE, TestCompress::None));
    let parsed = Image::parse(&container).expect("parse");

    assert_eq!(parsed.startup_offset, 0x40);
    assert_eq!(parsed.total_size(), container.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(
        parsed.startup_bytes().expect("startup bytes"),
        b"\x7fELF\x00\x00\x00\x00"
    );
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
}

#[cfg(feature = "zlib")]
#[test]
fn parses_zlib_image_with_boot_prefix() {
    let mut container = vec![0x55u8; 0x40];
    container.extend_from_slice(&build_image(E::LE, TestCompress::Zlib));
    let parsed = Image::parse(&container).expect("parse");

    assert_eq!(parsed.startup_offset, 0x40);
    assert_eq!(parsed.total_size(), container.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
}

#[cfg(feature = "lzo")]
#[test]
fn parses_lzo_image_with_boot_prefix() {
    let mut container = vec![0x55u8; 0x40];
    container.extend_from_slice(&build_image(E::LE, TestCompress::Lzo));
    let parsed = Image::parse(&container).expect("parse");

    assert_eq!(parsed.startup_offset, 0x40);
    assert_eq!(parsed.total_size(), container.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
}

#[cfg(feature = "ucl")]
#[test]
fn parses_ucl_image_with_boot_prefix() {
    let mut container = vec![0x55u8; 0x40];
    container.extend_from_slice(&build_image(E::LE, TestCompress::Ucl));
    let parsed = Image::parse(&container).expect("parse");

    assert_eq!(parsed.startup_offset, 0x40);
    assert_eq!(parsed.total_size(), container.len());
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);
}

#[test]
fn preserves_raw_path_bytes() {
    let image_bytes = build_image(E::BE, TestCompress::None);
    let parsed = Image::parse(&image_bytes).expect("parse");

    let file = shell_entry(&parsed);
    assert_eq!(file.path, "bin/sh");
    assert_eq!(file.raw_path, b"bin/sh");

    let link = link_entry(&parsed);
    assert_eq!(link.raw_path, LINK_PATH.as_bytes());
    match &link.kind {
        EntryKind::Symlink { target, raw_target } => {
            assert_eq!(target, LINK_TARGET);
            assert_eq!(raw_target, LINK_TARGET.as_bytes());
        }
        other => panic!("wrong kind: {other:?}"),
    }

    // The root directory stores an empty path.
    assert_eq!(parsed.entries[0].raw_path, b"");
}

#[test]
fn preserves_non_utf8_raw_paths_and_targets() {
    const RAW_PATH: &[u8] = b"bin/\xffsh";
    const RAW_TARGET: &[u8] = b"/bin/\xfeh";

    let dirent_size = align4(28 + RAW_PATH.len() + 1 + RAW_TARGET.len() + 1);
    let header_len = HEADER_LEN; // empty mountpoint, padded to 92 bytes
    let dir_area = dirent_size + 4; // plus the chain terminator
    let image_size = header_len + dir_area + 4; // plus the image trailer

    let mut filesystem = image_header(E::LE, image_size, header_len + dir_area, header_len, "");

    let mut extra = Vec::new();
    extra.extend_from_slice(&E::LE.u16((RAW_PATH.len() + 1) as u16));
    extra.extend_from_slice(&E::LE.u16((RAW_TARGET.len() + 1) as u16));

    let mut entry = attr(E::LE, dirent_size as u16, LINK_INO, 0o120777);
    entry.extend_from_slice(&extra);
    entry.extend_from_slice(RAW_PATH);
    entry.push(0);
    entry.extend_from_slice(RAW_TARGET);
    entry.push(0);
    entry.resize(dirent_size, 0);

    filesystem.extend_from_slice(&entry);
    filesystem.extend_from_slice(&[0u8; 4]); // chain terminator
    filesystem.extend_from_slice(&[0u8; 4]); // image trailer
    assert_eq!(filesystem.len(), image_size);

    let parsed = Image::parse_imagefs(&filesystem).expect("parse");
    assert_eq!(parsed.entries.len(), 1);

    let entry = &parsed.entries[0];
    assert_eq!(entry.raw_path, RAW_PATH);
    assert_eq!(entry.path, String::from_utf8_lossy(RAW_PATH).as_ref());
    match &entry.kind {
        EntryKind::Symlink { target, raw_target } => {
            assert_eq!(raw_target, RAW_TARGET);
            assert_eq!(target, String::from_utf8_lossy(RAW_TARGET).as_ref());
        }
        other => panic!("wrong kind: {other:?}"),
    }
}

#[test]
fn image_data_conversions_preserve_bytes() {
    for compress in compression_cases() {
        let image_bytes = build_image(E::LE, compress);
        let image = Image::parse(&image_bytes).expect("parse");
        let expected = image.filesystem.as_slice().to_vec();

        assert_eq!(&*image.filesystem, expected.as_slice());
        assert_eq!(image.filesystem.as_ref(), expected.as_slice());

        let owned: Vec<u8> = image.filesystem.into();
        assert_eq!(owned, expected);
    }
}

#[test]
fn quarantines_zero_inode_dirents() {
    let mut data = build_image(E::LE, TestCompress::None);
    let fifo = 264 + HEADER_LEN + ENTRY_OFFSETS[7];
    data[fifo + 4..fifo + 8].fill(0); // attr.ino of dev/fifo

    let parsed = Image::parse(&data).expect("parse");
    assert_eq!(parsed.entries.len(), 9);

    // The skipped dirent is recorded, with its position relative to the
    // image header, instead of being silently dropped.
    assert_eq!(parsed.omitted_dirents.len(), 1);
    let omitted = parsed.omitted_dirents[0];
    assert_eq!(omitted.offset, HEADER_LEN + ENTRY_OFFSETS[7]);
    assert_eq!(omitted.size, 44); // align4(32 + len("dev/fifo") + 1)
    assert_eq!(omitted.mode, 0o010600);
    assert_eq!(omitted.extattr_offset, 0);

    // The same quarantine applies to bare filesystem parsing.
    let mut filesystem = build_filesystem(E::LE);
    dirent_ino_zero(&mut filesystem, ENTRY_OFFSETS[7]);
    let bare = Image::parse_imagefs(&filesystem).expect("parse");
    assert_eq!(bare.omitted_dirents.len(), 1);
    assert_eq!(bare.omitted_dirents[0], omitted);
}

/// Zero the `ino` field of the dirent chain entry at `entry_offset`.
fn dirent_ino_zero(filesystem: &mut [u8], entry_offset: usize) {
    let start = HEADER_LEN + entry_offset + 4;
    filesystem[start..start + 4].fill(0);
}

#[test]
fn omitted_dirents_are_counted_up_to_cap() {
    // Build a dirent chain of tiny zero-inode entries that exceeds the
    // quarantine cap. Recording must stop at the cap; the chain walk and
    // error behaviour must be unaffected.
    const ENTRY_SIZE: usize = 28; // align4(24 + 1 + padding)
    let count = qnx_ifs::MAX_OMITTED_DIRENTS + 3;

    // The empty mountpoint in the helper pads to 92 bytes.
    assert_eq!(HEADER_LEN, 92);
    let dir_area = count * ENTRY_SIZE + 4; // plus the chain terminator
    let image_size = HEADER_LEN + dir_area + 4;
    let mut filesystem = image_header(E::LE, image_size, HEADER_LEN + dir_area, HEADER_LEN, "");
    for _ in 0..count {
        // A zero-inode directory entry with a one byte path.
        let mut dirent_bytes = attr(E::LE, ENTRY_SIZE as u16, 0, 0o040755);
        dirent_bytes.push(b'x');
        dirent_bytes.push(0);
        dirent_bytes.resize(ENTRY_SIZE, 0);
        filesystem.extend_from_slice(&dirent_bytes);
    }
    filesystem.extend_from_slice(&[0u8; 4]); // dirent chain terminator
    filesystem.extend_from_slice(&[0u8; 4]); // image trailer
    assert_eq!(filesystem.len(), image_size);

    let parsed = Image::parse_imagefs(&filesystem).expect("parse");
    assert_eq!(parsed.entries.len(), 0);
    assert_eq!(parsed.omitted_dirents.len(), qnx_ifs::MAX_OMITTED_DIRENTS);
}

#[test]
fn image_checksums_verify_after_patch() {
    for endian in [E::LE, E::BE] {
        let mut image_bytes = build_image(endian, TestCompress::None);
        let parsed = Image::parse(&image_bytes).expect("parse");
        let trailer_at = parsed.header_offset + parsed.image_header.image_size - 4;

        // The synthetic trailer is zeroed; the recomputation disagrees.
        let first = parsed.image_checksum().expect("filesystem checksums");
        assert!(!first.valid());

        // Patch the stored value with the recomputation; both raw
        // byte orders must verify after the patch.
        image_bytes[trailer_at..trailer_at + 4].copy_from_slice(&endian.u32(first.computed));
        let reparsed = Image::parse(&image_bytes).expect("parse");
        let second = reparsed.image_checksum().expect("filesystem checksums");
        assert!(second.valid());
        assert_eq!(second.stored, first.computed);
    }
}

#[test]
fn startup_checksums_verify_after_patch() {
    for endian in [E::LE, E::BE] {
        for compress in compression_cases() {
            let mut image_bytes = build_image(endian, compress);
            let parsed = Image::parse(&image_bytes).expect("parse");

            // The synthetic trailer is zeroed; the recomputation disagrees.
            let first = parsed.startup_checksum().expect("startup checksums");
            assert!(!first.valid());
            let trailer_at = parsed.startup_offset + parsed.startup.unwrap().startup_size - 4;
            image_bytes[trailer_at..trailer_at + 4].copy_from_slice(&endian.u32(first.computed));

            let reparsed = Image::parse(&image_bytes).expect("parse");
            let second = reparsed.startup_checksum().expect("startup checksums");
            assert!(second.valid());
            assert_eq!(second.stored, first.computed);
        }
    }
}

#[test]
fn startup_checksum_uses_startup_byte_order() {
    // Startup header little-endian, filesystem big-endian. The startup
    // trailer checksum must follow the startup header's byte order, not
    // the filesystem's.
    let be_image = build_image(E::BE, TestCompress::None);
    let filesystem = build_filesystem(E::BE);
    let startup_size = 264;
    let stored_size = 256 + 8 + filesystem.len();

    let mut image_bytes = startup_header(
        E::LE,
        0x00,
        startup_size,
        startup_size,
        stored_size,
        filesystem.len(),
    );
    image_bytes.extend_from_slice(&be_image[256..]);

    let parsed = Image::parse(&image_bytes).expect("parse");
    assert_eq!(parsed.endian, Endian::Big);
    assert_eq!(
        parsed.startup.as_ref().expect("startup header").endian,
        Endian::Little
    );

    let first = parsed.startup_checksum().expect("startup checksums");
    let trailer_at = parsed.startup_offset + startup_size - 4;
    image_bytes[trailer_at..trailer_at + 4].copy_from_slice(&first.computed.to_le_bytes());

    let reparsed = Image::parse(&image_bytes).expect("parse");
    let second = reparsed.startup_checksum().expect("startup checksums");
    assert!(second.valid());
    assert_eq!(second.stored, first.computed);
}

#[test]
fn compressed_image_checksum_uses_decompressed_filesystem() {
    let baseline_bytes = build_image(E::LE, TestCompress::None);
    let baseline = Image::parse(&baseline_bytes).expect("parse");
    let expected = baseline.image_checksum().expect("filesystem checksums");

    for compress in compression_cases() {
        let image_bytes = build_image(E::LE, compress);
        let parsed = Image::parse(&image_bytes).expect("parse");
        let checksums = parsed.image_checksum().expect("filesystem checksums");
        // The fixtures leave the trailer zeroed; the covered region is the
        // decompressed filesystem, so it must not depend on compression.
        assert_eq!(checksums.stored, 0);
        assert_eq!(checksums.computed, expected.computed);
    }
}

#[test]
fn lenient_options_accept_damaged_startup_header() {
    let options = qnx_ifs::ParseOptions {
        lenient_startup_header: true,
        ..qnx_ifs::ParseOptions::default()
    };

    // Non-zero reserve fields only: the direct parser reports the zero
    // field check, and whole-image parsing fails after the search finds
    // no acceptable header. Lenient options accept and parse normally.
    let mut data = build_image(E::LE, TestCompress::None);
    data[50..64].fill(0xAA); // zero0 + zero[3]
    assert!(matches!(
        qnx_ifs::parse_startup_header(&data, 0),
        Err(Error::BadStartupHeaderZeros)
    ));
    assert!(Image::parse(&data).is_err());
    assert!(Image::parse_imagefs(&data).is_ok());
    assert!(qnx_ifs::find_startup_header(&data).is_none());
    let parsed = Image::parse_with_options(&data, &options).expect("lenient parse");
    assert_eq!(parsed.entries.len(), 10);
    assert_eq!(parsed.file_bytes(shell_entry(&parsed)).unwrap(), SHELL);

    // A set reserved flags2 byte is also rejected strictly and accepted
    // leniently.
    let mut data = build_image(E::LE, TestCompress::None);
    data[7] = 0x80; // flags2
    assert!(matches!(
        qnx_ifs::parse_startup_header(&data, 0),
        Err(Error::BadStartupHeader)
    ));
    assert!(Image::parse(&data).is_err());
    assert!(Image::parse_with_options(&data, &options).is_ok());

    // Default options are strict, like `Image::parse`.
    assert!(Image::parse_with_options(&data, &qnx_ifs::ParseOptions::default()).is_err());
}
