# qnx-ifs

[![crates.io](https://img.shields.io/crates/v/qnx-ifs.svg)](https://crates.io/crates/qnx-ifs)

Pure-Rust parser and decompressor for QNX IFS ("Image File System") firmware
images, as produced by QNX `mkifs`/`mkxfs` — the format commonly handled with
the external `dumpifs` utility.

- `#![forbid(unsafe_code)]`, no filesystem I/O, no global state
- Little- and big-endian images
- Startup header validation (`0x00FF7EEB` signature, version, and
  zero-field checks); reserve-field leniency for damaged images is
  opt-in (`ParseOptions::lenient_startup_header`, the `dumpifs -z`
  behaviour)
- Image filesystem header and dirent chain walking; dirents the kernel
  would skip (`ino == 0`) never enter the entry list, they are recorded
  in `Image::omitted_dirents` for reporting
- zlib/gzip, LZO1X, and UCL NRV2B compressed filesystem regions,
  decompressed strictly within the extent the startup header declares
- In-memory entry model: regular files, directories, symbolic links,
  character/block devices, FIFOs, named special files, and sockets, each
  with mode/uid/gid/inode/mtime; stored path and symlink-target bytes
  are additionally exposed raw (`Entry::raw_path`) for byte-exact
  handling of non-UTF-8 names
- Trailer checksum access (`Image::image_checksum`,
  `Image::startup_checksum`) computed the way `mkifs` writes them
- Decompression limits (`Limits`) and a 64 KiB block cap to bound hostile
  inputs

## Usage

```rust
use qnx_ifs::{EntryKind, Image, Limits};

let image = Image::parse_with_limits(data, &Limits::default())?;
println!("mountpoint: {}", image.image_header.mountpoint);

for entry in &image.entries {
    let perms = entry.permissions();
    match &entry.kind {
        EntryKind::File { .. } => {
            let bytes = image.file_bytes(entry).unwrap_or(&[]);
            println!("file  {perms:04o} {} ({} bytes)", entry.path, bytes.len());
        }
        EntryKind::Dir => println!("dir   {perms:04o} {}", entry.path),
        EntryKind::Symlink { target, .. } => println!("link  {} -> {target}", entry.path),
        other => println!("other {other:?} {}", entry.path),
    }
}
```

*(error handling elided; `data` is the input byte slice)*

The input may start with a startup header (bootable image) or be a bare
`imagefs` filesystem. Resolution is deterministic: a bare `imagefs`
header at the very first byte takes precedence, otherwise the whole
buffer is scanned (strictly validating) for a startup header.
`Image::parse_imagefs` additionally searches a whole container for a
bare filesystem when the prefix is unrelated. Entry paths are stored
without a leading slash.

### API overview

| Item | Purpose |
| --- | --- |
| `Image::parse` / `parse_with_limits` | Parse a bootable image or bare filesystem from a byte slice |
| `Image::parse_with_options` | Full `ParseOptions`: decompression limits plus opt-in startup-header leniency |
| `Image::parse_imagefs` | Parse a bare `imagefs` found anywhere in a container |
| `Image::total_size` | Bytes consumed by the image (startup `stored_size`, or the bare filesystem extent) |
| `Image::file_bytes` | Contents of a regular file entry |
| `Image::startup_bytes` | The uncompressed startup program section |
| `Image::entries` | All directory entries, in image order |
| `Image::omitted_dirents` | Skipped zero-inode dirents, quarantined for reporting |
| `Image::image_checksum` / `startup_checksum` | Stored vs. recomputed trailer checksum pair (`Checksums::valid`) |
| `StartupHeader` | Startup header fields: machine, load addresses, sizes, endianness, compression |
| `ImageHeader` | Mountpoint, flags, inode metadata, chain info |
| `Entry` / `EntryKind` | Path, raw path bytes, inode, mode, uid/gid/mtime, and the type-specific payload |
| `ImageData` | Decompressed or borrowed filesystem bytes (`Deref<Target = [u8]>`) |
| `Limits` / `ParseOptions` | Decompression bounds and parsing policy knobs |

### Parsing policy

Parsing is defensive by default and mirrors the reference `dumpifs`
behaviour only where that is also the safest choice:

- A bare `imagefs` header at offset 0 wins over a deeper startup header,
  so embedded look-alike data cannot hijack the parse.
- The startup header's signature, version, size relationships and
  reserve fields are all validated before anything is decompressed.
  `ParseOptions::lenient_startup_header` relaxes only the reserve-field
  and reserved-`flags2` checks (the `dumpifs -z` scope) for damaged or
  vendor-patched images; nothing else is ever relaxed.
- Dirents with a zero inode are skipped the way the kernel skips them,
  but never silently: each is recorded in `Image::omitted_dirents`
  (position, size, mode) with recording capped at
  `MAX_OMITTED_DIRENTS`, and they never enter `Image::entries`.
- Compressed regions are decompressed strictly within the stored extent:
  a stream truncated by the end of the region is always an error, and
  bytes after a gzip member are rejected rather than ignored like the
  reference tool does after `gzread` errors out. The remaining decoders
  end where their formats do: zlib stops at the stream end, LZO at its
  zero-length terminator, and UCL rejects trailing data after the end
  marker.
- Trailer checksums are recomputed in pure Rust, summing 32-bit words
  and negating in the byte order of the structure the trailer belongs to
  (the image filesystem header for `image_checksum`, the startup header
  for `startup_checksum`); the reference tool's big-endian display is
  unreliable. Callers decide whether a mismatch is fatal.

### Features

All three compressed-region decoders are enabled by default and can be
disabled individually:

| Feature | Default | Description |
| --- | --- | --- |
| `zlib` | yes | zlib/gzip region decompression (via `flate2`) |
| `lzo` | yes | LZO1X block decompression (via `lzo`) |
| `ucl` | yes | UCL NRV2B block decompression (clean-room, no dependencies) |

Images with the corresponding compression flag but without the feature
enabled fail to parse with `Error::FeatureDisabled`.

## Extraction

This crate performs **no filesystem I/O**. Writing entries to disk (path
sanitization, symlink handling, permissions, ownership) is intentionally
left to callers. That keeps the crate safe to run on untrusted data and
reusable by other analysis tooling.

## Testing and validation

- Synthetic fixtures (`tests/synthetic.rs`) cover both byte orders, bare
  and bootable images, all dirent kinds, boot prefixes, parse
  precedence, the quarantine of skipped dirents, checksum verification
  over patched trailers (both byte orders and compressed variants),
  non-UTF-8 raw names, `ImageData` conversions, and strict vs. lenient
  startup-header options.
- Robustness tests (`tests/robust.rs`) apply a deterministic, seeded
  mutation harness over valid images in every compression format, and
  random bytes to every decoder, asserting `Err(_)` instead of panics
  plus the parser's structural invariants.
- Reference vectors:
  - LZO: `tests/common/lzo_oracle.rs`, captured from the original LZO C
    library (`lzo1x_1` and `lzo1x_999`, as vendored by QNX).
  - UCL: `tests/common/ucl_oracle.rs`, a trimmed capture from the
    reference NRV2B encoder (`ucl_nrv2b_99_compress`, the encoder `mkifs`
    uses).
  - The independent pure-Rust `lzokay` compressor cross-validates the
    chunked LZO stream format at test time.
- Cross-checked against boot images from a real QNX Neutrino 6.5 SP1
  installation (UCL-compressed, including one with a `*.boot` block
  before the startup header): identical startup header fields, identical
  entry listings (45 dirents) and byte-identical decompressed filesystem
  content relative to `dumpifs -v` / `dumpifs -u`.
- Cross-checked against QNX `dumpifs` on the same fixtures across
  `none`/`zlib`/`gzip`/`lzo`/`ucl` × LE/BE: byte-identical filesystem
  bytes in all cases, byte-identical `dumpifs -u` output on little-endian
  compressed images, and identical entry listings (paths, types,
  permissions, sizes, symlink targets, device numbers). Big-endian images
  are verified against independent synthetic fixtures because the
  patched C `dumpifs` build mishandles its startup byte-swap and crashes
  on BE input.

