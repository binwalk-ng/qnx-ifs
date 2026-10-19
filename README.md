# qnx-ifs

Pure-Rust parser and decompressor for QNX IFS ("Image File System") firmware
images, as produced by QNX `mkifs`/`mkxfs` — the format commonly handled with
the external `dumpifs` utility.

- `#![forbid(unsafe_code)]`, no filesystem I/O, no global state
- Little- and big-endian images
- Startup header validation (`0x00FF7EEB` signature, version, and
  zero-field checks)
- Image filesystem header and dirent chain walking
- zlib/gzip, LZO1X, and UCL NRV2B compressed filesystem regions
- In-memory entry model: regular files, directories, symbolic links,
  character/block devices, FIFOs, named special files, and sockets, each
  with mode/uid/gid/inode/mtime
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
        EntryKind::Symlink { target } => println!("link  {} -> {target}", entry.path),
        other => println!("other {other:?} {}", entry.path),
    }
}
```

*(error handling elided; `data` is the input byte slice)*

The input may start with a startup header (bootable image) or be a bare
`imagefs` filesystem. `Image::parse_imagefs` additionally searches a whole
container for a bare filesystem, mirroring `dumpifs`'s first search step.
Entry paths are stored without a leading slash.

### API overview

| Item | Purpose |
| --- | --- |
| `Image::parse` / `parse_with_limits` | Parse a bootable image or bare filesystem from a byte slice |
| `Image::parse_imagefs` | Parse a bare `imagefs` found anywhere in a container |
| `Image::total_size` | Bytes consumed by the image (startup `stored_size`, or the bare filesystem extent) |
| `Image::file_bytes` | Contents of a regular file entry |
| `Image::startup_bytes` | The uncompressed startup program section |
| `Image::entries` | All directory entries, in image order |
| `StartupHeader` | Startup header fields: machine, load addresses, sizes, endianness, compression |
| `ImageHeader` | Mountpoint, flags, inode metadata, chain info |
| `Entry` / `EntryKind` | Path, inode, mode, uid/gid/mtime, and the type-specific payload |

### Features

All three compressed-region decoders are enabled by default and can be
disabled individually:

| Feature | Default | Description |
| --- | --- | --- |
| `zlib` | yes | zlib/gzip region decompression (via `flate2`) |
| `lzo` | yes | LZO1X block decompression (via `lzo`) |
| `ucl` | yes | UCL NRV2B block decompression (clean-room, no dependencies) |

Images with the corresponding compression flag but without the feature
enabled are rejected with `Error::UnsupportedCompression`.

## Extraction

This crate performs **no filesystem I/O**. Writing entries to disk (path
sanitization, symlink handling, permissions, ownership) is intentionally
left to callers. That keeps this crate fuzzable and reusable
by other analysis tooling.

## Testing and validation

- Synthetic fixtures (`tests/synthetic.rs`) cover both byte orders, bare
  and bootable images, and all dirent kinds.
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

