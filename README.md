# Salty

Salty is a lightweight, low-level command-line cryptographic utility written in V. It provides a highly unified suite for memory-hard time-locked container virtualization, recursive directory packing, textual/numerical steganography, and homoglyph-based visual obfuscation. 

Designed for strict forensic security, Salty utilizes UNIX RAM-backed file structures, host/namespace bind-propagation, active memory pinning, and compiler-safe non-elidable zeroization to eliminate cold-boot and persistent storage leaks.

---

## Features

### 1. Locktime VFS Container Engine
- **Memory-Hard Sequential Cryptographic Delay Chain**: Implements a sequential delay chain utilizing memory-hard SHA-3-512 to prevent ASIC bypasses.
    - *ASIC/GPU Resistance via Memory Latency Bounds*: Standard SHA-3 sequential chains can be parallelized or pipelined heavily on custom FPGAs. By routing Salty's chain through a data-dependent random walk on a 1 MB buffer (16,384 hashes, optimized for CPU L2 cache size), the execution speed is strictly bounded by hardware memory/cache latency. This minimizes the performance gap between specialized custom silicon and consumer-grade CPUs.
    - *No-Trapdoor Security*: Salty avoids the slow generation of safe primes ($p, q$) required by RSW96 VDFs, enabling instant encryption. Since there is no algebraic trapdoor, even the creator of the container must compute the sequential delay, enforcing a strict mathematical timeline.
    - *Constant-Time $O(1)$ Parameter Masking (`Seed0`)*: Metadata parameters (duration $t$, Argon2 iterations, memory, thread count, cipher length) are decrypted in constant $O(1)$ time. A wrong key simply produces garbage metadata that fails authenticated payload decryption at the very end, eliminating timing side-channels and oracle leaks.
- **Double-Layer Cascade Encryption**: Payloads are processed through a two-layer cryptographic pipeline. The compressed virtual filesystem is first encrypted with **AES-256-CTR** (inner layer) and then enveloped inside **ChaCha20-Poly1305** (outer AEAD layer), deriving independent cryptographically-hashed keys for each layer. This dual-cipher design ensures mathematical resistance even if a theoretical vulnerability is discovered in either cipher.
- **Delay-to-Header Binding**: To prevent local verification oracle attacks, the metadata decryption key (`header_key`) is cryptographically bound to the final state of the hash chain ($w$) using PBKDF2-SHA3-512.
- **Unified Master Key-Binding Model**: Config parameters, block locations, and payload encryption are securely decoupled using four distinct keys (**Master Password**, **Seed 0**, **Seed 1**, **Seed 2**). However, to eliminate manual input fatigue and prevent multi-prompt workflows, **Seed 0, Seed 1, and Seed 2 are deterministically and securely derived** from the **Master Password** under the hood using PBKDF2-SHA3-512 with cryptographically isolated salts. This binds the entire cryptographic pipeline exclusively to the master key.
- **Virtual VFS Packer (Directory Cryptography)**: Recursively walks any target directory tree, compiling all directory structures, files, metadata, and contents into a unified virtual filesystem structure (VFS) compressed with in-memory **Zstd** before encryption.

### 2. RAM-Mounted Sandbox & Unix Bind-Mount
- **Dedicated & Private `tmpfs` RAM-Disk**: Instead of relying on a shared public `/dev/shm` path, Salty creates an isolated directory and explicitly mounts a private `tmpfs` RAM-disk with strict Unix permissions (`mode=0700`). This isolates decrypted files from other local users, prevents persistent storage leaks on physical SSDs/HDDs, and bypasses standard Shared Memory size constraints.
- **Host & Namespace Bind-Mounting**: Leverages native UNIX `mount --bind` and `nsenter -t 1 -m` to expose the sandboxed RAM directory to `./mnt/<container_name>_salty` on both the host system and running container/pod namespaces without leaving persistent traces.
- **Heap-Allocation-Free Signal Handling (Async-Signal-Safe)**: To prevent local memory residue on sudden termination (e.g. `Ctrl+C`, `SIGTERM`, `SIGHUP`, `SIGQUIT`), a custom Unix signal handler is registered.
    - *Deadlock Prevention via Stack Arrays*: Dynamic memory allocation (`malloc`) is not async-signal-safe. If a signal interrupts the memory allocator, running allocations inside the signal handler causes a deadlock. Salty’s emergency cleanup routine uses static stack arrays and `snprintf` to securely unmount and run recursive shredding in a completely heap-free manner.
- **Order-Preserved Safe Unmounting**: Implements a strict unmounting sequence. The virtual RAM-disk filesystem is cleanly unmounted (`umount`) prior to the removal of empty directory nodes. This prevents the kernel from triggering `Device or resource busy` lockups during active or orphan cleanups.

### 3. Salty Steganography Engine (Triple-Stream Evasion)
- **Square-Root Law Compliance**: Typo intensity is dynamically capped at 25% in textual steganography to preserve the linguistic and statistical naturalness of the cover text, rendering NLP-based steganalysis classifiers ineffective.
- **Textual Mode**: Conceals data inside cover texts via deterministic typing pattern mimicry: character insertions, overwrites (`-o`), transpositions (`-tr`), or standard US-QWERTY proximity keyboard typos.
- **Numeric Mode**: Conceals payload data inside highly audited and censored serial sequences, national registry formats, or state-controlled telecommunication networks. This includes exact patterns mimicking the **Chinese Resident Identity Card (SFZ)**, **Iranian National ID (Melli Code)**, and regional financial or telco routing lines associated with strictly monitored jurisdictions.

### 4. Character-Mapping Obfuscator (`obfuscate`)
- **Randomized Homoglyph Translation**: Replaces characters with visual homoglyphs based on user-defined custom mapping strings.
- **Noise Injection**: Injects multilingual symbol noise to disrupt Optical Character Recognition (OCR) systems and parser tokenizations.

### 5. System Pre-flight Validation & Diagnostics
- **Early Write-Permission Assertions**: To prevent wasting CPU cycles during VDF calculations, Salty proactively verifies write permissions on the target paths before initiating the sequential delay chain.
- **Android & Adaptive Termux-API Engine**:
    - *Privilege-Aware Command Routing*: Supports deployment on **both unrooted and rooted Android/Termux environments**. Salty uses native C-level privilege detection (`C.getuid()`) to safely evaluate the current runtime user. If executed under root (e.g., via `tsu` or inside a root shell), it dynamically drops execution privileges back to the target Termux UID using `su ${uid} -c` for all Termux API commands, ensuring Binder IPC communications can be established without deadlocking.
    - *Defensive Timeout Protections*: To prevent the utility from freezing indefinitely due to missing or denied Android Runtime permissions (such as Sensors, Location, or Battery), all external Android CLI and Termux API queries are protected by robust `timeout` boundaries.
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
sudo ./salty encrypt -f ./my_project -o secure.container -t 100000 -p "MasterPass" -sh
```
*(Use `-sh` or `--shred` to securely shred the original files after successful encryption. Seed parameters are derived securely and automatically under the hood)*

**Mount/Load a Container to RAM (Expose Files on `./mnt/`):**
```bash
sudo ./salty mount -f secure.container -t 100000 -p "MasterPass"
```
*(Simply press **ENTER** when finished to automatically serialize modifications back to the container, lazy-unmount, and shred RAM files)*

**Decrypt/Extract a Container to Disk:**
```bash
sudo ./salty decrypt -f secure.container -o ./restored_project -p "MasterPass"
```

**Force Unmount & Clean Orphan Mounts:**
```bash
sudo ./salty unmount -f ./mnt/secure_salty
```

*(Note: On Android/Termux, you can run commands without `sudo` if you are using it in an unrooted environment).*

---

### 2. Steganography Mode

**Conceal message inside Numeric sequences (mimicking Chinese SFZ, Iranian Melli ID, and state-monitored phone routing):**
```bash
./salty encrypt -m "Secret payload data" -p "CryptPass" -s "SeedString" -f "SFZ:18,MELLI:10,+86139:11,+98912:7"
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
2. **Mathematical Key Binding**: Deriving the metadata decryption key and block-shuffling seeds (`Seed0`, `Seed1`, `Seed2`) directly from the master password prevents verification bypasses and isolates cryptographic layers without exposing parameters on-disk.
3. **Paging Protection**: Uses active OS memory pinning (`mlock`) to limit the lifetime of secret keys in hardware and prevent disk paging.
4. **Physical Write Evasion**: Storing temporary unencrypted files strictly inside a private, restricted `tmpfs` RAM-disk eliminates forensic discovery risks on physical SSD/HDD flash storage.

## License
![License](https://img.shields.io/badge/License-MIT-green.svg)
