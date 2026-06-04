# Salty

Salty is a lightweight command-line utility written in V for secure data encryption, deep compression, and steganographic-like format obfuscation. It converts encrypted payloads into dynamic, customized numeric sequences (such as simulated international phone numbers, credit card numbers, or postal codes) that can be embedded within benign text for covert transmission.

---

## Features

- Deep Compression: Payloads are deeply compressed using Zstandard (zstd) at level 19 before encryption.
- Secure Encryption: Encrypted with OpenSSL ChaCha20 utilizing PBKDF2.
- Leak Prevention: Passwords are dynamically passed to OpenSSL via environment variables, keeping them hidden from process sniffing (e.g., `ps aux`).
- Interactive Mode: Running the utility with no arguments starts a step-by-step interactive prompt with terminal echo disabled during password entry.
- Multi-Format Obfuscation: Supports custom prefixes and varying payload lengths.
- Deterministic Reordering: Re-sequences data chunks using a lightweight, portable Linear Congruential Generator (LCG) shuffle.

---

## Quick start (copy - paste - enter)
```bash
pkg update -y && pkg install -y git clang make openssl zstd && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/salty && cd salty && v -prod salty.v -o salty && ln -sf $(pwd)/salty $PREFIX/bin/salty
```

---

## Prerequisites

Ensure the following tools are installed on your system:

- V compiler (vlang)
- OpenSSL (CLI)
- Zstandard (zstd CLI)

---

## Compilation

Compile the source code into a binary:

```bash
v salty.v
```

For optimization on Unix systems:

```bash
v -cc clang -prod salty.v
```

---

## Usage

Salty can be run in either interactive mode or via direct command-line arguments.

### 1. Interactive Mode (Recommended)

Execute the binary without any arguments. This mode securely prompts you for inputs and masks the password during entry:

```bash
./salty
```

### 2. Command-Line Mode

#### Encryption

```bash
./salty encrypt -m "<message>" -p "<password>" -s <seed> -f "<formats>"
```

#### Decryption

```bash
./salty decrypt -t "<carrier_text>" -p "<password>" -s <seed> -f "<formats>"
```

### Formats Specification

The `-f` or `--formats` option accepts a comma-separated list of formats defined as `prefix:payload_len`. The tool cycles through these formats sequentially to chunk and obfuscate the data.

Example format string: `+1202:7,411111:10,90210:5`
- `+1202:7`: Generates a sequence starting with `+1202` followed by 7 payload digits.
- `411111:10`: Generates a sequence starting with `411111` (Visa BIN) followed by 10 payload digits.
- `90210:5`: Generates a sequence starting with `90210` (postal code structure) followed by 5 payload digits.

The last chunk is automatically padded with deterministic garbage digits if it is shorter than the specified layout length, ensuring consistent structure.

---

## License
![License](https://img.shields.io/badge/License-MIT-blue.svg)
