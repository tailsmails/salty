# Salty

Salty is a lightweight, high-performance command-line utility written in V for secure data encryption, deep compression, time-locked cryptography, and advanced multi-layered evasion. It provides three distinct core engines: **Locktime** (Time-locked file encryption), **Salty Steganography** (Data hiding in text/numbers), and **Adversarial Obfuscation** (AI-blinding visual twins).

## Features

### 1. Locktime Engine (Sequential Time-Lock Cryptography)
- **Post-Quantum Default VDF**: Salty utilizes a sequential SHA-512 Hash-Chain to enforce a rigorous time-lock delay, making offline brute-force attacks computationally impractical, even against future quantum-enabled hardware.
- **Symmetric Post-Quantum Key Encapsulation**: A 256-bit symmetric session key and 12-byte nonce are derived dynamically from the solved VDF solution. The session key is encrypted using authenticated `ChaCha20-Poly1305` [1], providing robust quantum resistance with zero external C dependencies.
- **Zero-Knowledge Header Obfuscation (`Seed0`)**: Metadata parameters (memory, iterations, thread count, cipher length) are not stored as raw data. They are encoded as HMAC-SHA3-512 hashes. To reconstruct the header, the system performs a localized brute-force within logical bounds using a derived `Key_Seed0`. This renders the file header completely opaque to statistical analysis and prevents "metadata leakage" (i.e., fingerprinting the encryption settings).
- **Triple-Key Security Model (Oracle-Resistance)**: 
    - **Master Password**: Used for Argon2id derivation and payload encryption.
    - **Seed 1 (`-s1`)**: Locator key for mapping the puzzle/metadata block.
    - **Seed 2 (`-s2`)**: Locator key for mapping the encrypted payload.
    - *Why?* Decoupling configuration, puzzle location, and payload ensures that even if an attacker guesses the password, they cannot validate the guess or understand the internal configuration without the correct seeds.
- **Native ChaCha20-Poly1305 AEAD**: The entire cryptographic pipeline operates in-memory using V's native cryptography module, closing potential OpSec leaks such as arguments visible in process monitors (`ps aux`).
- **Forensic Evasion**: Includes secure shredding, active memory zeroization, and zero-disk-leakage streaming to ensure no plaintext ever touches the storage media.

### 2. Salty Steganography Engine (Triple-Stream Evasion)
- **Numeric Mode**: Conceals data inside patterns mimicking credit cards, routing numbers, or phone sequences.
- **Text Steganography**: Embeds data via deterministic typos, insertions, character overwrites (`-o`), or character transpositions (`-tr`) to mimic high-speed human typing, bypassing automated filters.

### 3. Adversarial Obfuscation (`obfuscate`)
- **Randomized Multi-Mapping**: Bypasses AI/NLP filters by replacing characters with visual homoglyphs.
- **Noise Injection**: Injects multilingual symbol noise (`-ni`, `-nc`) to blind OCR and AI tokenizers.

---

## Quick Start (One-Liner)
```bash
pkg update -y && pkg install -y git clang make zstd && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/salty && cd salty && v -prod salty.v -o salty && ln -sf $(pwd)/salty $PREFIX/bin/salty
```

---

## Usage

### 1. Locktime Mode (Time-Lock Encryption)
**Encryption:**
```bash
./salty encrypt -f secret.txt -o locked_file -t 10 -p "MasterPass" -s1 "Key1" -s2 "Key2" -sh
```

**Decryption (Automatically solves the VDF Puzzle):**
```bash
./salty decrypt -f locked_file -o restored.txt -p "MasterPass" -s1 "Key1" -s2 "Key2"
```

### 2. Salty Mode (Steganography & Obfuscation)
**Numeric Mode:**
```bash
./salty encrypt -m "Secret" -p "Pass" -s 99 -f "+1202:7,411111:10"
```

**Textual Steganography:**
```bash
./salty encrypt -m "Secret" -p "Pass" -s 1 -ti 50 -q -o -tr -t "Cover Text"
```

**Adversarial Obfuscation:**
```bash
./salty obfuscate -t "message" -map "m:ጠ:᠓:៳,e:е:ϵ" -ni 5 -s 1
```

---

## Security Model
**Salty** provides a defense-in-depth architecture:
1. **Asymmetric Sequential Delay (VDF)**: Forces a mathematical wait-time of $T$ seconds *per password guess* that cannot be bypassed by parallelization.
2. **Post-Quantum Symmetric Key Wrapping**: Derives keying material from the VDF solution, creating a temporal and cryptographic dependency.
3. **Pure-V Cryptographic Pipeline**: Mitigates risk of command-line leakage and guarantees AEAD integrity.
4. **Header Metadata Obfuscation (`Seed0`)**: By brute-forcing HMAC-based parameters, the file header remains indistinguishable from high-entropy noise, preventing attackers from verifying configuration settings or validating password guesses (Oracle Resistance).
5. **Robust Bounds Checking**: Strict size validation ensures immunity to memory allocation panics under wrong password or garbage inputs.
6. **Forensic Erasure**: Active Zeroization and Secure Shredding ensure no forensic remnants remain.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
