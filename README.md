# Salty

Salty is a lightweight command-line utility written in V for data encryption, compression, time-locked cryptography, steganography, and character-mapping obfuscation. It provides three distinct core components: **Locktime** (Time-locked file encryption), **Salty Steganography** (Data hiding in text/numbers), and **Character-Mapping Obfuscation** (Visual homoglyphs and noise injection).

## Features

### 1. Locktime Engine (Memory-Hard Time-Lock Cryptography)
- **Memory-Hard Sequential Cryptographic Delay Chain**: Salty implements a sequential delay chain utilizing memory-hard SHA-3-512 to prevent ASIC bypasses.
    - *ASIC/GPU Resistance via Memory Latency Bounds*: Standard, fixed-circuit SHA-3 sequential chains can be parallelized or pipelined heavily on custom ASICs or FPGA clusters. By routing the sequential chain through a data-dependent random walk on a 1 MB buffer (16,384 hashes, optimized for CPU L2 cache size), the execution speed is strictly bounded by hardware memory/cache latency (Memory Latency Bottleneck). This minimizes the performance gap between specialized custom silicon and consumer-grade CPUs.
    - *No-Trapdoor Security*: Salty avoids the slow, minutes-long generation of safe primes ($p, q$) required by hybrid RSW96 VDFs, enabling instant file encryption. Since there is no algebraic trapdoor, even the creator of the file must compute the sequential delay, enforcing a strict, unbreakable mathematical timeline.
    - *Two-Point Calibration*: Salty utilizes an advanced two-point calibration routine (measuring the delta time between 50 steps and 2,050 steps) to mathematically isolate and cancel out the constant initialization and memory allocation overhead of the memory-hard array buffer, calculating the CPU's pure execution speed with high precision.
- **Symmetric Hash-Chain Key Derivation**: A 256-bit symmetric session key and 12-byte nonce are derived dynamically from the final state of the sequential hash chain. The payload is encrypted using native `ChaCha20-Poly1305` authenticated encryption.
- **Delay-to-Header Binding**: To prevent local verification oracle attacks, the metadata decryption key (`header_key`) is cryptographically bound to the final state of the hash chain ($w$) using PBKDF2-SHA3-512. The key to decrypt the metadata does not exist until the sequential delay is fully resolved, forcing any attacker to perform the sequential CPU work before attempting to decrypt or verify any password/seed.
- **Constant-Time $O(1)$ Parameter Masking (`Seed0`)**: Metadata parameters (duration $t$, Argon2 iterations, memory, thread count, cipher length) are masked in constant time. 
    - *Oracle-Free Security Model*: Each metadata parameter is masked using a dedicated keystream derived from `Seed0` mixed with unique parameter index contexts. Unlike brute-force HMAC parameter matching, which leaks configuration timing (acting as an offline dictionary-attack oracle on `Seed0`), Salty decrypts parameters in constant $O(1)$ time. A wrong seed simply produces garbage metadata that fails authenticated payload decryption at the very end, eliminating timing side-channels.
- **Memory-Hard Seed Derivation**: Secondary locator seeds (`seed1` and `seed2`) are stretched using memory-hard **Argon2d** instead of standard PBKDF2, heavily penalizing dictionary attacks on secondary secrets.
- **Quad-Key Security Model**: 
    - **Master Password**: Used for Argon2d derivation and native payload encryption.
    - **Seed 0 (`-s0`)**: Dedicated key for obfuscating and masking the metadata parameters.
    - **Seed 1 (`-s1`)**: Locator key for mapping the VDF metadata block inside the mixed random block.
    - **Seed 2 (`-s2`)**: Locator key for mapping the encrypted payload chunks inside the mixed random block.
    - *Why?* Decoupling configuration parameters, block locations, and payload encryption ensures that guessing the password does not permit validation of the guess or structural detection of the blocks without the corresponding seeds.
- **Active OS Memory Pinning**: To mitigate hardware-level attacks, Salty uses POSIX `mlock` and Windows `VirtualLock` to lock critical cryptographic secrets (passwords, session keys, nonces, and seeds) in physical RAM. This prevents the OS virtual memory manager from writing sensitive key material to disk pagefiles/swap partitions and excludes them from core dumps.
- **Forensic Erasure & Non-Elidable Memory Zeroization**: Overwrites keys and sensitive buffers using a compiler-safe zeroization routine. The loop writes zeros and validates them via post-write checks (`b[0] != 0`), guaranteeing that compilers cannot optimize away the zeroing steps through Dead-Store Elimination (DSE).

### 2. Salty Steganography Engine (Triple-Stream Evasion)
- **Square-Root Law Compliance**: In textual steganography, typo intensity is dynamically capped at 25% to preserve the linguistic and statistical naturalness of the cover text. This prevents detection from modern machine-learning and NLP-based steganalysis classifiers.
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
./salty encrypt -m "Secret" -p "Pass" -s 1 -ti 25 -q -o -tr -t "Cover Text"
```

**Character-Mapping Obfuscation:**
```bash
./salty obfuscate -t "message" -map "m:ጠ:᠓:៳,e:е:ϵ" -ni 5 -s 1
```

---

## Security Model
1. **Memory-Hard VDF Delay**: Forces a single-threaded sequential execution time of $T$ seconds that cannot be bypassed by parallel processing, GPU/ASIC pipelines, or algebraic shortcuts.
2. **Mathematical Key Binding**: Deriving the metadata decryption key from the sequential state prevents bypasses via binary modification.
3. **No-Overhead Parameters**: Only the masked metadata parameters are stored, removing the mathematical and performance overhead of Safe Prime generation while preserving the computational hardness of the work.
4. **Local Oracle Mitigation**: Decrypting parameter blocks in constant time eliminates timing side-channels and prevents early confirmation of dictionary attacks on `Seed0`.
5. **Strict Bounds Checking**: Validates size inputs to prevent memory allocation panics when processing wrong passwords or corrupted inputs.
6. **Active Memory Hardening**: Uses RAM pinning (`mlock`) and compiler-safe non-DSE memory zeroization to limit the lifetime of secret keys in hardware.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
