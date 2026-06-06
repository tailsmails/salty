# Salty

Salty is a lightweight, high-performance command-line utility written in V for secure data encryption, deep compression, and advanced steganography. It allows users to hide encrypted payloads within benign-looking data using two stealthy methods: **Fake Numeric Sequences** (Phone numbers, CCs) and **Natural Typo Injection** (Keyboard proximity-based noise).

## Features

- **Dual-Stream Steganography**:
    - **Numeric Mode**: Conceals data as international phone numbers, credit card sequences, or routing numbers.
    - **Text Mode (Typo Steganography)**: Embeds data by injecting deterministic "typos" into a cover text based on physical keyboard layouts.
- **Insertion vs. Overwrite Modes**: 
    - *Insertion (Default)*: Adds typo characters next to the original ones.
    - *Overwrite (`-o`)*: Replaces original characters with typos, maintaining the exact string length for maximum stealth.
- **Industrial-Grade Compression**: Payloads are pre-processed with Zstandard (zstd) at level 19 for maximum data density.
- **Authenticated Encryption**: Powered by OpenSSL ChaCha20 ~~-Poly1305~~ with PBKDF2 key stretching.
- **Keyboard Proximity Engine**: Features built-in **QWERTY** logic and supports **Custom Keymaps** (e.g., QWERTZ, AZERTY, or Dvorak) for realistic noise generation.
- **Mixed-Radix Encoding**: A mathematical approach to transform encrypted bits into specific typo choices, ensuring 100% error-free recovery.
- **Process Stealth**: Sensitive keys are handled via environment variables to prevent leaking credentials in process lists (e.g., `ps aux`).

---

## Quick Start (One-Liner)
```bash
pkg update -y && pkg install -y git clang make openssl zstd && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/salty && cd salty && v -prod salty.v -o salty && ln -sf $(pwd)/salty $PREFIX/bin/salty
```

---

## Prerequisites

- **V Compiler** (latest stable)
- **OpenSSL CLI** (3.0+ recommended)
- **Zstandard CLI**

---

## Usage

### 1. Interactive Mode
Run `salty` without arguments for a secure, guided experience with hidden password entry:
```bash
./salty
```

### 2. Command-Line Mode

#### Method A: Numeric Obfuscation (Fake Numbers)
**Encryption:**
```bash
./salty encrypt -m "Confidential Data" -p "StrongPass" -s 9988 -f "+1202:7,411111:10"
```
*Creates sequences mimicking US Phone numbers and Visa Credit Cards.*

**Decryption:**
```bash
./salty decrypt -t "Contact: +12025550199 Ref: 4111119876543210" -p "StrongPass" -s 9988 -f "+1202:7,411111:10"
```

#### Method B: Textual Steganography (Typo Injection)
This method hides data by simulating human typing errors. It is highly resistant to automated detection.

**Mode 1: Insertion (Adds typos next to original letters)**
```bash
# Encrypt
./salty encrypt -m "Secret" -p "Pass123" -s 550 -ti 25 -q -t "The report will be ready by tomorrow."

# Decrypt
./salty decrypt -t "The reporrt wilbl be rready bny tomorrrow." -p "Pass123" -s 550 -ti 25 -q
```

**Mode 2: Overwrite (Replaces letters - Maintains exact length)**
*Note: Decrypting in Overwrite mode requires the original reference text (`-r`) to compare and extract the overwritten typos.*
```bash
# Encrypt (add -o flag)
./salty encrypt -m "Secret" -p "Pass123" -s 550 -ti 25 -q -o -t "The report will be ready by tomorrow."

# Decrypt (requires -o and -r flags)
./salty decrypt -t "Thw repnrt wisl bw rwady by tomnrrow." -r "The report will be ready by tomorrow." -p "Pass123" -s 550 -ti 25 -q -o
```

---

## Technical Specifications / Flags

| Flag | Long Flag | Purpose |
| :--- | :--- | :--- |
| `-m` | `--message` | The secret data to be encrypted |
| `-t` | `--text` | Cover text (Enc) or Carrier text (Dec) |
| `-r` | `--ref` | Original Reference text (Required for Decrypting Overwrite mode) |
| `-p` | `--pass` | Cryptographic password |
| `-s` | `--seed` | Deterministic RNG seed for positioning / shuffling |
| `-f` | `--formats` | Layouts for Number Mode (e.g., `prefix:length`) |
| `-ti` | `--typo-intensity` | Typo frequency percentage (1-100) |
| `-km` | `--key-map` | Custom physical keyboard string map |
| `-q` | `--qwerty` | Standard US-QWERTY proximity logic |
| `-o` | `--overwrite` | Replaces characters instead of inserting them (Length preserved) |

---

## Why Salty?
Unlike traditional steganography which hides data in images or audio (often detectable by file size changes or metadata analysis), Salty hides data in **plain text**. A few typos in a long email, a Discord message, or a technical log look like a normal human error. The secret payload is mathematically woven into these "mistakes," making it invisible to the naked eye and difficult for AI filters or DLP (Data Loss Prevention) systems to flag.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
