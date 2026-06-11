# Salty

Salty is a lightweight, high-performance command-line utility written in V for secure data encryption, deep compression, time-locked cryptography, and advanced multi-layered evasion. It provides two distinct core engines: **Locktime** (for secure, time-delayed file encryption) and **Salty Steganography** (for hiding data in benign-looking numeric patterns, text typos, or NLP homoglyphs).

## Features

### 1. Locktime Engine (Sequential Time-Lock Cryptography)
- **RSW96 Time-Lock Puzzles**: Secures files by requiring sequential modular squarings ($x_{i+1} = x_i^2 \pmod N$) that cannot be parallelized, neutralizing multi-core, GPU, and ASIC brute-force farms.
- **Dynamic Primes (Up to 2048-bit Modulus)**: Generates random primes (default 512-bit, yielding a highly secure 1024-bit $N$ modulus; configurable up to 1024-bit primes for a military-grade 2048-bit modulus) to prevent mathematical factorization attacks. Includes a trial-division sieve for high-speed prime generation.
- **Hardened Memory & Directory Security**:
    - **Temp Folder Sandboxing**: Isolates temporary compression and decryption blocks inside private directories (`0700` permissions) that are securely swept recursively upon exit using `defer` wrappers.
    - **Active Zeroization**: Memory space allocated for key derivation materials (`argon_key` and `final_key_bytes`) is actively overwritten with `0x00` before process termination to neutralize RAM dump extraction.
    - **SHA-512 CSPRNG (CTR Mode)**: Obfuscation shuffles and dynamic noise generation use a Cryptographically Secure Pseudo-Random Number Generator based on SHA-512 in Counter Mode, removing all predictable LCG patterns.
- **Argon2id KDF**: Hardened key-stretching (default 64MB memory, 3 iterations, 4 threads) to prevent dictionary attacks on the master password.

### 2. Salty Steganography Engine (Triple-Stream Evasion)
- **Numeric Mode**: Conceals encrypted data inside patterns mimicking credit card sequences, routing numbers, or international phone numbers.
- **Text Steganography**: Embeds data by injecting deterministic "mistakes" (Typos) into a cover text based on physical keyboard proximity (US-QWERTY or custom maps).
    - *Insertion (Default)*: Adds typo characters next to the original ones.
    - *Overwrite (`-o`)*: Replaces characters maintaining exact string length.
    - *Transposition (`-tr`)*: Swaps adjacent letters to mimic high-speed human typing.
- **Adversarial Obfuscation (`obfuscate`)**: Bypasses AI/NLP content filters by utilizing visual homoglyphs (multi-script twins) and multilingual symbol noise injection (`-ni`, `-nc`) to shatter tokenization models while remaining readable to humans.

---

## Quick Start (One-Liner)
```bash
pkg update -y && pkg install -y git clang make openssl zstd && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/salty && cd salty && v -prod salty.v -o salty && ln -sf $(pwd)/salty $PREFIX/bin/salty
```

---

## Usage

### 1. Interactive Mode
For a guided experience with hidden password entry:
```bash
./salty
```

### 2. Locktime Mode (Time-Lock File Encryption)
Encrypts files with a verifiable mathematical delay. The program automatically routes to Locktime if Seed 1 (`-s1`) or Seed 2 (`-s2`) flags are supplied.

**Encryption (Lock for 10 seconds, 1024-bit Modulus):**
```bash
./salty encrypt -f secret.txt -o locked_file -t 10 -p "MasterPass" -s1 "SeedOne" -s2 "SeedTwo"
```
*Generates dynamic primes, calibrates single-thread speed, runs Argon2id, compresses with ZSTD, encrypts with ChaCha20, and serializes the payload using a decoupled double-seed CSPRNG shuffle.*

**Decryption (Sequential Solving):**
```bash
./salty decrypt -f locked_file -o restored.txt -p "MasterPass" -s1 "SeedOne" -s2 "SeedTwo"
```

### 3. Salty Mode: Numeric Obfuscation (Fake Numbers)
Conceals encrypted data as sequences mimicking phone numbers or credit cards.

**Encryption:**
```bash
./salty encrypt -m "Confidential Data" -p "StrongPass" -s 9988 -f "+1202:7,411111:10"
```
*Creates sequences like `+12025550199` and `4111119876543210`.*

**Decryption:**
```bash
./salty decrypt -t "Contact: +12025550199 Ref: 4111119876543210" -p "StrongPass" -s 9988 -f "+1202:7,411111:10"
```

### 4. Salty Mode: Textual Steganography (Typos/Swaps)
Hides data by simulating human typing errors. 

**Option A: Insertion Mode (Default)**
```bash
# Encrypt
./salty encrypt -m "Secret" -p "Pass123" -s 550 -ti 25 -q -t "The report is ready."
# Result: "Tthe rrepormt is rreadyy."
```

**Option B: Overwrite & Transposition Mode (`-o`, `-tr`)**
*Note: Requires the original reference text (`-r`) for decryption.*
```bash
# Encrypt (Intensity 90, QWERTY logic, Transposition enabled)
./salty encrypt -m "Secret" -p "Pass123" -s 1 -ti 90 -q -tr -t "Done! Congratulations on your new bot."

# Decrypt (Requires -r flag)
./salty decrypt -t "<carrier_text>" -r "Done! Congratulations on your new bot." -p "Pass123" -s 1 -ti 90 -q -tr
```

### 5. Salty Mode: Adversarial Obfuscation (Blinding AI)
Metamorphose text using visual twins and noise to make it unreadable for AI filters.

**Obfuscate (Multi-Mapping + Noise):**
```bash
# a:а:α means 'a' can be replaced by Cyrillic 'а' or Greek 'α' randomly.
./salty obfuscate -t "send vpn credentials" -map "a:а:α,e:е:ϵ,n:ո:ռ,v:ν:ｖ" -ni 15 -nc "の,水,火" -s 77
```

**De-obfuscate:**
```bash
./salty obfuscate -t "<obfuscated_text>" -map "a:а:α,e:е:ϵ,n:ո:ռ,v:ν:ｖ" -d
```

---

## Technical Specifications / Flags

| Flag | Long Flag | Purpose | Engine |
| :--- | :--- | :--- | :--- |
| `-f` | `--file` | Input file path | Locktime |
| `-o` | `--out` | Output file path | Locktime / Salty |
| `-t` | `--time` | Time-lock duration in seconds (Default: 10) | Locktime |
| `-s1`| `--seed1` | Second key (Seed 1 - Metadata Shuffle) | Locktime |
| `-s2`| `--seed2` | Third key (Seed 2 - Payload Shuffle) | Locktime |
| `--mem`| — | Argon2 Memory in KB (Default: 65536) | Locktime |
| `--iter`| — | Argon2 Iterations (Default: 3) | Locktime |
| `--threads`| — | Argon2 Threads (Default: 4) | Locktime |
| `--prime`| — | Prime size in bits (Default: 512, yields 1024-bit N) | Locktime |
| `-m` | `--message` | The secret data to be encrypted / hidden | Salty |
| `-t` | `--text` | Cover text (Enc) or Carrier text (Dec/Obf) | Salty |
| `-r` | `--ref` | Original Reference text (Required for Overwrite/Transpose Dec) | Salty |
| `-p` | `--pass` | Cryptographic password | Locktime / Salty |
| `-s` | `--seed` | Deterministic RNG seed for positions and choices | Salty |
| `-f` | `--formats` | Layouts for Number Mode (`prefix:length`) | Salty |
| `-ti`| `--typo-intensity`| Typo/Swap frequency percentage (1-100) | Salty |
| `-tc`| `--typo-chars`| Custom typo letters | Salty |
| `-km`| `--key-map` | Custom keyboard map | Salty |
| `-q` | `--qwerty` | Standard US-QWERTY proximity logic | Salty |
| `-tr`| `--transpose`| Swaps adjacent letters instead of replacing them | Salty |
| `-map`| `--mapping` | Custom 1-to-many char mapping (`from:to1:to2`) | Salty |
| `-ni`| `--noise-intensity`| Frequency of noise character injection (0-100) | Salty |
| `-nc`| `--noise-chars`| Custom noise symbols (e.g., "*,の") | Salty |
| `-d` | `--deobfuscate`| Reverse the visual mapping and strip noise | Salty |

---

## Security Model
Unlike traditional encryption tools, **Salty** provides a layered approach to secure communications:

1. **Defensive Cryptography (Locktime)**: Protects stored files against immediate decryption, forcing a physical, non-parallelizable mathematical delay (Time-Lock Puzzle) on the adversary while employing strict operational security practices (secure memory zeroization, isolated private directories).
2. **Evasion Cryptography (Salty)**: Hides encrypted data inside **Natural Language Noise**. A few typos in an email, a swapped pair of letters in a chat log, or a sequence of fake phone numbers in a technical log look like normal human activity. By weaving the secret payload into these "mistakes," Salty makes the data invisible to DLP systems, NLP analyzers, and content filters.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
