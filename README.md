# Salty

Salty is a lightweight, high-performance command-line utility written in V for secure data encryption, deep compression, time-locked cryptography, and advanced multi-layered evasion. It provides three distinct core engines: **Locktime** (Time-locked file encryption), **Salty Steganography** (Data hiding in text/numbers), and **Adversarial Obfuscation** (AI-blinding visual twins).

## Features

### 1. Locktime Engine (Sequential Time-Lock Cryptography)
- **Post-Quantum Default VDF**: By default, Salty utilizes a sequential SHA-512 Hash-Chain to enforce a rigorous time-lock delay. This design is completely immune to Grover's and Shor's algorithms, preventing quantum computers from bypassing the sequential delay.
- **Lattice-Based Key Encapsulation (LWE-KEM)**: Secures the 256-bit symmetric session key using a lightweight Ring-LWE style Learning with Errors (LWE) post-quantum scheme. The LWE secret is derived dynamically from the solved VDF, adding quantum-resistant hardness to the key wrapping.
- **Classical RSW96 Fallback (`--classic`)**: Optional fallback mode using sequential modular squarings ($x_{i+1} = x_i^2 \pmod N$) with Pietrzak VDF verification proof. The starting base $a$ is dynamically derived from the Master Password and the file salt ($a = \text{Hash}(\text{MasterPassword} + \text{salt}) \pmod N$) to neutralize offline parallelized brute-force attacks.
- **Triple-Key Security Model (Oracle-Resistance)**: 
    - **Master Password**: Used for ChaCha20/Argon2id encryption.
    - **Seed 1 (`-s1`)**: Independent locator key used to shuffle and hide the Time-Lock puzzle blocks.
    - **Seed 2 (`-s2`)**: Independent locator key used to map the encrypted payload.
    - *Why?* By separating the puzzle location (`Seed 1`) from the Master Password, even if an attacker guesses the password, they cannot instantly verify it. They are forced to solve the Time-Lock puzzle first, making brute-force mathematically impossible.
- **Hardened Key Derivation**: The header encryption key and the secondary payload seed are strengthened using the user-configured stretching parameter (`pbkdf2_iter` which defaults to 200,000 rounds) instead of weak default iterations.
- **Forensic Evasion & OpSec**:
    - **Zero-Disk-Leakage**: Decryption streams directly through OS pipes (`|`) between `openssl` and `zstd`. Plaintext never touches the disk.
    - **Secure Shredding (`-sh`)**: Built-in support to wipe original files using Linux `shred`, macOS `rm -P`, or a multi-pass zero-overwrite fallback.
    - **Active Zeroization**: Clears sensitive keys from RAM immediately after use.

### 2. Salty Steganography Engine (Triple-Stream Evasion)
- **Numeric Mode**: Conceals data inside patterns mimicking credit cards, routing numbers, or phone sequences.
- **Text Steganography**: Embeds data via deterministic typos based on keyboard proximity.
    - *Insertion*: Adds characters.
    - *Overwrite (`-o`)*: Replaces characters (preserves exact string length).
    - *Transposition (`-tr`)*: Swaps adjacent letters to mimic high-speed human typing.

### 3. Adversarial Obfuscation (`obfuscate`)
- **Randomized Multi-Mapping**: Bypasses AI/NLP filters by replacing characters with visual homoglyphs. 
- **Syntax**: `char:twin1:twin2:twinN`. Salty randomly chooses one of the twins for each occurrence, shattering fixed tokenization models.
- **Noise Injection**: Injects multilingual symbol noise (`-ni`, `-nc`) to further blind OCR and AI classifiers.

---

## Quick Start (One-Liner)
```bash
pkg update -y && pkg install -y git clang make openssl zstd && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/salty && cd salty && v -prod salty.v -o salty && ln -sf $(pwd)/salty $PREFIX/bin/salty
```

---

## Usage

### 1. Locktime Mode (Time-Lock Encryption)
**Encryption (PQ default, 10s lock, Shred Original):**
```bash
./salty encrypt -f secret.txt -o locked_file -t 10 -p "MasterPass" -s1 "Key1" -s2 "Key2" -sh
```

**Encryption in Classical Mode (reverts to RSW96/Pietrzak VDF, 1024-bit Modulus):**
```bash
./salty encrypt -f secret.txt -o locked_file -t 10 -p "MasterPass" -s1 "Key1" -s2 "Key2" --classic -sh
```

**Decryption (Sequential Solving - Automatically Detects PQ or Classical Mode):**
```bash
./salty decrypt -f locked_file -o restored.txt -p "MasterPass" -s1 "Key1" -s2 "Key2"
```

### 2. Salty Mode: Numeric Obfuscation (Fake Numbers)
**Encryption:**
```bash
./salty encrypt -m "Secret" -p "Pass" -s 99 -f "+1202:7,411111:10"
```

### 3. Salty Mode: Textual Steganography (Swaps/Typos)
**Overwrite & Transposition (`-o`, `-tr`):**
```bash
# Encrypt
./salty encrypt -m "Secret" -p "Pass" -s 1 -ti 50 -q -o -tr -t "The quick brown fox."

# Decrypt (Requires -r reference text)
./salty decrypt -t "<carrier>" -r "The quick brown fox." -p "Pass" -s 1 -ti 50 -q -o -tr
```

### 4. Adversarial Obfuscation (Blinding AI)
**Randomized Mapping + Noise:**
```bash
# 'm' will be randomly replaced by ጠ, ᠓, or ៳
./salty obfuscate -t "message" -map "m:ጠ:᠓:៳,e:е:ϵ,s:ѕ:ｓ,a:🄐,g:ց,e:ϵ" -ni 5 -s 1
```

---

## Technical Specifications / Flags

| Flag | Long Flag | Purpose | Engine |
| :--- | :--- | :--- | :--- |
| `-f` | `--file` | Input file path | Locktime |
| `-o` | `--out` | Output file path | Locktime / Salty |
| `-t` | `--time` | Time-lock duration in seconds | Locktime |
| `-s1`| `--seed1`| **Puzzle Locator Key** (Oracle Prevention) | Locktime |
| `-s2`| `--seed2`| **Payload Locator Key** | Locktime |
| `-sh`| `--shred` | Securely wipe original file after success | Locktime |
| `--prime`| — | Prime size (Default: 512, yields 1024-bit N) | Locktime |
| `--classic`| — | Disable default PQ VDF mode (reverts to RSW96/Pietrzak VDF) | Locktime |
| `-m` | `--message` | Secret data to be hidden | Salty |
| `-t` | `--text` | Cover text or Text to obfuscate | Salty / Obf |
| `-r` | `--ref` | Original Reference text (Required for -o/-tr) | Salty |
| `-p` | `--pass` | Master Password | All |
| `-s` | `--seed` | Deterministic RNG seed | Salty / Obf |
| `-ti`| `--typo-intensity`| Typo frequency (1-100) | Salty |
| `-tr`| `--transpose`| Swaps adjacent letters | Salty |
| `-map`| `--mapping` | Multi-choice mapping (`from:to1:to2`) | Obfuscate |
| `-ni`| `--noise-intensity`| Noise frequency (0-100) | Obfuscate |
| `-d` | `--deobfuscate`| Reverse visual mapping | Obfuscate |

---

## Security Model
**Salty** provides a defense-in-depth architecture:
1. **Asymmetric Sequential Delay (VDF)**: By default, using a SHA-512 Sequential Hash-Chain VDF forces a mathematical wait-time of $T$ seconds *per password guess* that cannot be bypassed by quantum computers or highly parallelized hardware, rendering offline dictionary attacks computationally impractical.
2. **Post-Quantum Key Wrapping**: Secures the symmetric session key with a Learning with Errors (LWE) lattice-based key encapsulation mechanism, ensuring metadata confidentiality even under post-quantum scrutiny.
3. **Oracle Resistance**: Decoupling the physical file structure (`Seed 1`) from the Master Password prevents attackers from instantly validating guesses or even locating the encrypted metadata block.
4. **Stretched Key Derivation**: Replaces low-iteration PBKDF2 layers with configurable high-entropy stretching (default: 200,000 rounds) to further secure the secondary key and seed derivation pipelines.
5. **Robust Bounds Checking**: The metadata deserialization parsers enforce strict size and boundary validation, ensuring graceful error reporting and immunity to memory allocation panics under wrong password or garbage inputs.
6. **Forensic Erasure**: Zero-Disk Leakage and Active Zeroization ensure no plaintext or decrypted keys are leaked to the disk or left in memory for forensic recovery.
7. **NLP Evasion**: Hides data in "human noise" (typos/visual twins) that AI filters cannot reliably tokenize or detect.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
