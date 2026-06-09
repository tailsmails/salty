# Salty

Salty is a lightweight, high-performance command-line utility written in V for secure data encryption, deep compression, and advanced multi-layered evasion. It allows users to hide or obfuscate data within benign-looking text using three stealthy methods: **Numeric Steganography**, **Natural Typo/Transposition Injection**, and **Adversarial Visual Obfuscation**.

## Features

- **Triple-Stream Evasion**:
    - **Numeric Mode**: Conceals data as international phone numbers, credit card sequences, or routing numbers.
    - **Text Steganography**: Embeds data by injecting deterministic "mistakes" (Typos) into a cover text based on physical keyboard proximity.
    - **Adversarial Obfuscation (`obfuscate`)**: Bypasses AI/NLP filters by using visual homoglyphs (multi-script twins) and deterministic noise injection.
- **Advanced Typo Engine**: 
    - *Insertion (Default)*: Adds typo characters next to the original ones.
    - *Overwrite (`-o`)*: Replaces original characters with typos, maintaining exact string length.
    - *Transposition (`-tr`)*: Swaps adjacent characters to mimic high-speed human typing errors.
- **Multi-Script Visual Mapping**: Supports 1-to-many character mapping (e.g., mapping 'a' to a list of Cyrillic, Greek, or Latin look-alikes), choosing the replacement randomly based on your seed.
- **Noise Injection (`-ni`, `-nc`)**: Injects random multi-lingual characters or symbols to shatter tokenization for AI models while remaining readable to humans.
- **Industrial-Grade Security**: 
    - **Encryption**: OpenSSL ChaCha20 with **PBKDF2** key stretching (10,000 iterations).
    - **Compression**: Zstandard (zstd) at level 19 for maximum data density.
    - **Process Stealth**: Temporary files are handled in-memory or cleaned up immediately using `defer` blocks. Sensitive keys are passed via environment variables.

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

### 2. Method 1: Numeric Obfuscation (Fake Numbers)
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

### 3. Method 2: Textual Steganography (Typos/Swaps)
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

### 4. Method 3: Adversarial Obfuscation (Blinding AI)
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

| Flag | Long Flag | Purpose |
| :--- | :--- | :--- |
| `-m` | `--message` | The secret data to be encrypted |
| `-t` | `--text` | Cover text (Enc) or Carrier text (Dec/Obf) |
| `-r` | `--ref` | Original Reference text (Required for Overwrite/Transpose) |
| `-p` | `--pass` | Cryptographic password |
| `-s` | `--seed` | Deterministic RNG seed for positions and random choices |
| `-f` | `--formats` | Layouts for Number Mode (`prefix:length`) |
| `-ti` | `--typo-intensity` | Typo/Swap frequency percentage (1-100) |
| `-q` | `--qwerty` | Standard US-QWERTY proximity logic |
| `-o` | `--overwrite` | Replaces characters instead of inserting (Length preserved) |
| `-tr` | `--transpose` | Swaps adjacent letters instead of replacing them |
| `-map` | `--mapping` | Custom 1-to-many char mapping (`from:to1:to2`) |
| `-ni` | `--noise-intensity`| Frequency of noise character injection (0-100) |
| `-nc` | `--noise-chars` | Custom noise symbols (e.g., "*,の") |
| `-d` | `--deobfuscate` | Reverse the visual mapping and strip noise |

---

## Why Salty?
Unlike traditional steganography that hides data in images or audio (often detectable by file size changes or metadata analysis), **Salty** hides data in **Natural Language Noise**. 

A few typos in an email, a swapped pair of letters in a Discord message, or a sequence of fake phone numbers in a technical log look like normal human activity. By weaving the secret payload into these "mistakes," Salty makes the data invisible to the naked eye and extremely difficult for AI filters, NLP analyzers, or DLP (Data Loss Prevention) systems to flag.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
