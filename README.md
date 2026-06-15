# Salty

Salty is a lightweight, low-level command-line cryptographic utility written in V. It provides a highly unified suite for memory-hard time-locked container virtualization, recursive directory packing, textual/numerical steganography, and homoglyph-based visual obfuscation. 

Designed for strict forensic security, Salty utilizes UNIX RAM-backed file structures, host/namespace bind-propagation, active memory pinning, and compiler-safe non-elidable zeroization to eliminate cold-boot and persistent storage leaks.

---

## Features

### 1. Locktime VFS Container Engine
- **Memory-Hard Sequential Cryptographic Delay Chain**: Implements a sequential delay chain utilizing memory-hard SHA-3-512 to prevent ASIC bypasses.
    - *ASIC/GPU Resistance via Memory Latency Bounds*: Standard SHA-3 sequential chains can be parallelized or pipelined heavily on custom FPGAs. By routing Salty's chain through a data-dependent random walk on a 1 MB buffer (16,384 hashes, optimized for CPU L2 cache size), the execution speed is strictly bounded by hardware memory/cache latency. This minimizes the performance gap between specialized custom silicon and consumer-grade CPUs.
    - *No-Trapdoor Security*: Salty avoids the slow generation of safe primes ($p, q$) required by RSW96 VDFs, enabling instant encryption. Since there is no algebraic trapdoor, even the creator of the container must compute the sequential delay, enforcing a strict mathematical timeline.
    - *Constant-Time $O(1)$ Parameter Masking (`Seed0`)*: Metadata parameters (duration $t$, Argon2 iterations, memory, thread count, cipher length) are decrypted in constant $O(1)$ time. A wrong seed simply produces garbage metadata that fails authenticated payload decryption at the very end, eliminating timing side-channels and oracle leaks.
- **Delay-to-Header Binding**: To prevent local verification oracle attacks, the metadata decryption key (`header_key`) is cryptographically bound to the final state of the hash chain ($w$) using PBKDF2-SHA3-512.
- **Quad-Key Security Model**: Decouples config parameters, block locations, and payload encryption via four distinct keys (**Master Password**, **Seed 0**, **Seed 1**, **Seed 2**).
- **Virtual VFS Packer (Directory Cryptography)**: Recursively walks any target directory tree, compiling all directory structures, files, metadata, and contents into a unified virtual filesystem structure (VFS) compressed with in-memory **Zstd** before encryption.

### 2. RAM-Mounted Sandbox & Unix Bind-Mount
- **In-Memory tmpfs Allocation (`/dev/shm`)**: Decrypted payloads are written exclusively to `/dev/shm` (backed by UNIX `tmpfs`), guaranteeing that unencrypted bytes never touch persistent SSD/HDD platters. This eliminates forensic leakage risks introduced by hardware-level wear-leveling algorithms in modern flash storages.
- **Host & Namespace Bind-Mounting**: Leverages native UNIX `mount --bind` and `nsenter -t 1 -m` to expose the sandboxed RAM directory to `./mnt/<container_name>_salty` on both the host system and running container/pod namespaces without leaving persistent traces.
- **Heap-Allocation-Free Signal Handling (Async-Signal-Safe)**: To prevent local memory residue on sudden termination (e.g. `Ctrl+C`, `SIGTERM`, `SIGHUP`, `SIGQUIT`), a custom Unix signal handler is registered.
    - *Deadlock Prevention via Stack Arrays*: Dynamic memory allocation (`malloc`) is not async-signal-safe. If a signal interrupts the memory allocator, running allocations inside the signal handler causes a deadlock. Salty’s emergency cleanup routine uses static stack arrays and `snprintf` to securely unmount and run recursive shredding in a completely heap-free manner.
- **Manual Orphan Unmounting (`unmount`)**: Provides a dedicated, low-level unmount mode to safely lazy-unmount (`umount -l`) and shred leftover directories if the mounting environment or terminal emulator is forcefully killed.

### 3. Salty Steganography Engine (Triple-Stream Evasion)
- **Square-Root Law Compliance**: Typo intensity is dynamically capped at 25% in textual steganography to preserve the linguistic and statistical naturalness of the cover text, rendering NLP-based steganalysis classifiers ineffective.
- **Textual Mode**: Conceals data inside cover texts via deterministic typing pattern mimicry: character insertions, overwrites (`-o`), transpositions (`-tr`), or standard US-QWERTY proximity keyboard typos.
- **Numeric Mode**: Conceals payload data inside patterns mimicking credit cards, routing numbers, or phone sequences.

### 4. Character-Mapping Obfuscator (`obfuscate`)
- **Randomized Homoglyph Translation**: Replaces characters with visual homoglyphs based on user-defined custom mapping strings.
- **Noise Injection**: Injects multilingual symbol noise to disrupt Optical Character Recognition (OCR) systems and parser tokenizations.

### 5. System Pre-flight Validation & Diagnostics
- **Early Write-Permission Assertions**: To prevent wasting CPU cycles during VDF calculations, Salty proactively verifies write permissions on the target paths before initiating the sequential delay chain.
- **mlock Capability Checks**: Evaluates system security constraints (e.g., `ulimit -l` or memory-locking restrictions) at startup, warning the user if the kernel restricts RAM pinning.

---

## Quick Start (One-Liner)
*Note: V global variables are utilized to safely handle asynchronous Unix signals. You must compile Salty with the `-enable-globals` flag.*

```bash
pkg update -y && pkg install -y git clang make zstd && if ! command -v v >/dev/null 2>&1; then git clone --depth=1 https://github.com/vlang/v && cd v && make && ./v symlink && cd ..; fi && git clone --depth=1 https://github.com/tailsmails/salty && cd salty && v -enable-globals -prod salty.v -o salty && ln -sf $(pwd)/salty $PREFIX/bin/salty
```

---

## Usage

### 1. Locktime Mode (Time-Lock Encryption)

**Encrypt a Directory or File recursively:**
```bash
sudo ./salty encrypt -f ./my_project -o secure.container -t 100000 -p "MasterPass" -s0 "Key0" -s1 "Key1" -s2 "Key2" -sh
```
*(Use `-sh` or `--shred` to securely shred the original files after successful encryption)*

**Mount/Load a Container to RAM (Expose Files on `./mnt/`):**
```bash
sudo ./salty mount -f secure.container -t 100000 -p "MasterPass" -s0 "Key0" -s1 "Key1" -s2 "Key2"
```
*(Simply press **ENTER** when finished to automatically serialize modifications back to the container, lazy-unmount, and shred RAM files)*

**Decrypt/Extract a Container to Disk:**
```bash
sudo ./salty decrypt -f secure.container -o ./restored_project -p "MasterPass" -s0 "Key0" -s1 "Key1" -s2 "Key2"
```

**Force Unmount & Clean Orphan Mounts:**
```bash
sudo ./salty unmount -f ./mnt/secure_salty
```

---

### 2. Steganography Mode

**Conceal message inside Numeric sequences:**
```bash
./salty encrypt -m "Secret payload data" -p "CryptPass" -s "SeedString" -f "+98912:7,6037:10"
```

**Conceal message inside Textual carrier via typos/transpositions:**
```bash
./salty encrypt -m "Secret payload data" -p "CryptPass" -s "Seed123" -ti 25 -q -o -tr -t "This is a normal looking cover text used to hide sensitive payloads."
```

**Extract message from Textual carrier:**
```bash
./salty decrypt -t "Carrier text with typos inserted" -r "Original cover text without typos" -p "CryptPass" -s "Seed123" -ti 25 -q -o -tr
```

---

### 3. Character-Mapping Obfuscator

**Obfuscate Text with homoglyphs & noise injection:**
```bash
./salty obfuscate -t "target message" -map "m:ጠ:᠓:៳,e:е:ϵ" -ni 5 -s "RngSeed"
```

---

### 4. Interactive Mode
Launches a quiet, step-by-step CLI setup wizard guiding you through numeric obfuscation, typo stego, manual homoglyph mappings, or VFS RAM container mounting:
```bash
./salty interactive
```

---

## Security Model
1. **Memory-Hard VDF Delay**: Forces a single-threaded sequential execution time of $T$ seconds that cannot be bypassed by parallel processing, GPU/ASIC pipelines, or algebraic shortcuts.
2. **Mathematical Key Binding**: Deriving the metadata decryption key from the sequential state prevents bypasses via binary modification.
3. **Paging Protection**: Uses active OS memory pinning (`mlock`) to limit the lifetime of secret keys in hardware and prevent disk paging.
4. **Physical Write Evasion**: Storing temporary unencrypted files strictly inside a randomly-allocated `/dev/shm` path mitigates forensic discovery risks on physical SSD flash storage.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
