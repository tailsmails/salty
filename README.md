# Salty

Salty is a lightweight command-line utility written in V for data encryption, compression, time-locked cryptography, steganography, and character-mapping obfuscation. It provides three distinct core components: **Locktime** (Time-locked file encryption), **Salty Steganography** (Data hiding in text/numbers), and **Character-Mapping Obfuscation** (Visual homoglyphs and noise injection).

## Features

### 1. Locktime Engine (Sequential Time-Lock Cryptography)
- **Interleaved RSW96-SHA3 VDF**: Salty implements a step-by-step interleaved VDF combining modular squaring (RSW96) and cryptographic hashing (SHA-3-512). In each iteration of the chain, the state is squared modulo $N$ (where $N = p \cdot q$ is a product of two safe primes), and the result is immediately hashed with SHA-3-512 to produce the state for the next step.
    - *Quantum Resistance*: This interleaving destroys the multiplicative group homomorphism after every single squaring step, preventing adversaries from using a quantum computer to factor $N$ and compute the shortcut $e = 2^t \bmod \phi(N)$.
    - *ASIC/GPU Resistance*: Because each iteration requires a modular multiplication of large integers, specialized SHA-3 ASICs and parallel GPU architectures cannot effectively accelerate the computation due to the high sequential carry-propagation latency.
- **Symmetric Exponentiation-Hash Key Derivation**: A 256-bit symmetric session key and 12-byte nonce are derived dynamically from the final state of the interleaved VDF. The payload is encrypted using native `ChaCha20-Poly1305` authenticated encryption.
- **VDF-to-Header Binding**: To prevent local verification oracle attacks, the metadata decryption key (`header_key`) is cryptographically bound to the final VDF state ($w$) using PBKDF2-SHA3-512. The key to decrypt the metadata does not exist until the sequential VDF is fully resolved, forcing any attacker to perform the sequential CPU work before attempting to decrypt or verify any password/seed.
- **Header Parameter Obfuscation (`Seed0`)**: Metadata parameters (memory, iterations, thread count, cipher length) are not stored as raw data. They are encoded as HMAC-SHA3-512 hashes. Reconstructing the header parameters requires a localized brute-force within logical bounds using a derived `Key_Seed0`. This renders the file header indistinguishable from random noise to standard file-type parsers.
- **Triple-Key Security Model**: 
    - **Master Password**: Used for Argon2d derivation and payload encryption.
    - **Seed 1 (`-s1`)**: Locator key for mapping the VDF/metadata block.
    - **Seed 2 (`-s2`)**: Locator key for mapping the encrypted payload.
    - *Why?* Decoupling VDF configuration, block locations, and payload encryption ensures that guessing the password does not permit validation of the guess or structural detection of the blocks without the corresponding seeds.
- **Native Cryptography**: Built-in V cryptography modules are used to process data in-memory, avoiding OS-level leakage (such as visible CLI arguments in process monitors).
- **Forensic Erasure**: Employs secure file shredding and active memory zeroization (`memset`) to overwrite cryptographic keys.

### 2. Salty Steganography Engine (Triple-Stream Evasion)
- **Numeric Mode**: Conceals data inside patterns mimicking credit cards, routing numbers, or phone sequences.
- **Text Steganography**: Embeds data via deterministic typos, character insertions, character overwrites (`-o`), or character transpositions (`-tr`) to mimic typing patterns.

### 3. Character-Mapping Obfuscation (`obfuscate`)
- **Randomized Mapping**: Replaces characters with visual homoglyphs based on user-defined configurations.
- **Noise Injection**: Injects multilingual symbol noise (`-ni`, `-nc`) to disrupt OCR and parser tokenization.

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

**Decryption (Solves the VDF Puzzle):**
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

**Character-Mapping Obfuscation:**
```bash
./salty obfuscate -t "message" -map "m:ጠ:᠓:៳,e:е:ϵ" -ni 5 -s 1
```

---

## Security Model
1. **Interleaved Sequential Delay**: Forces a sequential execution time of $T$ seconds that cannot be bypassed by parallel processing or algebraic shortcuts.
2. **Mathematical Key Binding**: Deriving the metadata decryption key from the VDF state prevents bypasses via binary modification.
3. **Transparent VDF Parameters**: $N$ and $t$ are stored as standard, unencrypted parameters at the beginning of the file, preserving the mathematical hardness of the work without relying on security-by-obscurity.
4. **Local Oracle Mitigation**: By requiring localized brute-forcing of HMAC-based parameters, the header does not leak configuration details or permit instant validation of guessed passwords.
5. **Strict Bounds Checking**: Validates size inputs to prevent memory allocation panics when processing wrong passwords or corrupted inputs.
6. **Active Zeroization**: Clears keys from memory using secure memset wrappers after use.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
