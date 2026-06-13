# Salty

Salty is a lightweight command-line utility written in V for data encryption, compression, time-locked cryptography, steganography, and character-mapping obfuscation. It provides three distinct core components: **Locktime** (Time-locked file encryption), **Salty Steganography** (Data hiding in text/numbers), and **Character-Mapping Obfuscation** (Visual homoglyphs and noise injection).

## Features

### 1. Locktime Engine (Sequential Time-Lock Cryptography)
- **Sequential Cryptographic Hash Chain (SCHC) Time-Lock**: Salty implements a pure, highly optimized sequential cryptographic delay chain using SHA-3-512. The time-lock duration $T$ is translated into $t$ sequential SHA-3-512 iterations, where the output of each iteration is immediately fed as the input to the next.
    - *No-Trapdoor Security*: By resolving the mathematical inconsistencies of hybrid RSW96 VDFs, Salty avoids the slow, minutes-long generation of safe primes ($p, q$) entirely, enabling instant file encryption. Since there is no algebraic trapdoor, even the creator of the file must compute the sequential delay, enforcing a strict, unbreakable mathematical timeline.
    - *ASIC/GPU/Supercomputer Resistance*: Chaining SHA-3-512 sequentially is inherently non-parallelizable. A supercomputer with millions of cores or a specialized GPU cluster cannot compute state $i+1$ without computing state $i$. The execution speed is strictly bounded by the single-core sequential latency of the CPU.
- **Symmetric Hash-Chain Key Derivation**: A 256-bit symmetric session key and 12-byte nonce are derived dynamically from the final state of the sequential hash chain. The payload is encrypted using native `ChaCha20-Poly1305` authenticated encryption.
- **Delay-to-Header Binding**: To prevent local verification oracle attacks, the metadata decryption key (`header_key`) is cryptographically bound to the final state of the hash chain ($w$) using PBKDF2-SHA3-512. The key to decrypt the metadata does not exist until the sequential delay is fully resolved, forcing any attacker to perform the sequential CPU work before attempting to decrypt or verify any password/seed.
- **Header Parameter Obfuscation & Bruteforce Trap (`Seed0`)**: Metadata parameters (duration $t$, Argon2 iterations, memory, thread count, cipher length) are encoded as HMAC-SHA3-512 hashes using a key derived from a dedicated, independent `Seed0`.
    - *Infinite Bruteforce Honey Pot*: To reconstruct the header, Salty scans the full 32-bit (`0xFFFFFFFF` or 4.2 billion) search space. If an attacker inputs an incorrect `Seed0`, the program will not fail instantly. Instead, it gets trapped in an endless loop of up to 4.2 billion HMAC-SHA3-512 calculations, effectively acting as a CPU-melting tar-pit. Correct seeds bypass this trap instantly by matching the exact parameter values.
- **Quad-Key Security Model**: 
    - **Master Password**: Used for Argon2d derivation and native payload encryption.
    - **Seed 0 (`-s0`)**: Dedicated key for encrypting and obfuscating the metadata parameters (header brute-force trap).
    - **Seed 1 (`-s1`)**: Locator key for mapping the metadata/VDF block inside the mixed random block.
    - **Seed 2 (`-s2`)**: Locator key for mapping the encrypted payload chunks inside the mixed random block.
    - *Why?* Decoupling configuration parameters, block locations, and payload encryption ensures that guessing the password does not permit validation of the guess or structural detection of the blocks without the corresponding seeds.
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
./salty encrypt -f secret.txt -o locked_file -t 10 -p "MasterPass" -s0 "Key0" -s1 "Key1" -s2 "Key2" -sh
```

**Decryption (Solves the Delay Chain):**
```bash
./salty decrypt -f locked_file -o restored.txt -p "MasterPass" -s0 "Key0" -s1 "Key1" -s2 "Key2"
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
1. **Sequential Hash Chain Delay**: Forces a sequential execution time of $T$ seconds that cannot be bypassed by parallel processing or algebraic shortcuts.
2. **Mathematical Key Binding**: Deriving the metadata decryption key from the sequential state prevents bypasses via binary modification.
3. **No-Overhead Parameters**: Only the iteration count $t$ is stored, removing the mathematical and performance overhead of Safe Prime generation while preserving the computational hardness of the work.
4. **Local Oracle Mitigation & Honey Pot**: By requiring localized brute-forcing of HMAC-based parameters across a full 32-bit space, the header does not leak configuration details and actively punishes incorrect parameter guesses with massive computational latency.
5. **Strict Bounds Checking**: Validates size inputs to prevent memory allocation panics when processing wrong passwords or corrupted inputs.
6. **Active Zeroization**: Clears keys from memory using secure memset wrappers after use.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
