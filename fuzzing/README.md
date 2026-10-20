# Fuzzing qnx-ifs

Fuzz testing for the parser is done through [AFL++](https://aflplus.plus),
mirroring binwalk-ng's setup.

The harness (`src/main.rs`) exercises whole-image parsing (strict and
opt-in lenient), bare filesystem carving, file content exposure, the
trailer checksum helpers, and the decompression back ends on arbitrary
bytes. A panic is a bug; parse errors are the expected outcome for
malformed input.

## Fuzzer Dependencies

You must have a C compiler and `make` installed, as well as the `cargo-afl`
crate:

```
sudo apt install build-essential
cargo install cargo-afl
```

## Building the Fuzzer

```
cargo afl build --release
```

## Running the Fuzzer

You must provide an input directory containing sample files for the fuzzer
to mutate, and an output directory for the fuzzer to save crash results to.

```
cargo afl fuzz -i input_directory -o output_directory ./target/release/fuzz
```

Sample boot images (e.g. from a QNX 6.x / 7.x installation) make good
seeds; the in-tree deterministic mutation harness in `../tests/robust.rs`
covers the same invariants on every `cargo test` run.
