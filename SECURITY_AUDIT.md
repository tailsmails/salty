# Security Audit and Analysis Report: Salty

## Executive Summary
This report details a security, performance, and logical analysis of the Salty steganography utility. The analysis uncovered several critical and high-severity vulnerabilities, primarily centered around insecure cryptographic practices, unsafe handling of temporary files, and potential resource exhaustion.

---

## 1. Cryptographic Failures

### 1.1 Deterministic Encryption (No Salt) - FIXED
- **Category:** Security
- **Severity:** Critical
- **Issue:** Use of `-nosalt` with PBKDF2.
- **Root Cause Analysis:** The `openssl_encrypt` and `openssl_decrypt` functions explicitly pass the `-nosalt` flag to the `openssl enc` command. PBKDF2 requires a random salt to produce unique keys. Without it, the same password always results in the same key/IV.
- **Exploitation Scenario:** Enables two-time pad attacks on the ChaCha20 stream cipher and efficient dictionary/rainbow table attacks.
- **Remediation Implemented:** Removed `-nosalt`, increased PBKDF2 iterations to 100,000, and enabled standard salt generation.

### 1.2 Lack of Authenticity (Malleability) - FIXED
- **Category:** Security
- **Severity:** High
- **Issue:** Unauthenticated Encryption (ChaCha20 without MAC).
- **Root Cause Analysis:** The code uses standard ChaCha20 which does not provide integrity checks.
- **Exploitation Scenario:** An attacker can modify the ciphertext (by flipping bits in the carrier text's typos) to predictably alter the decrypted plaintext.
- **Remediation Implemented:** Implemented a manual **Encrypt-then-MAC (EtM)** pattern using **HMAC-SHA256**. The MAC is verified before decryption, ensuring data integrity and authenticity.

---

## 2. Insecure System Interactions

### 2.1 Insecure Temporary Files - FIXED
- **Category:** Security
- **Severity:** High
- **Issue:** Sensitive data written to world-readable files in `/tmp`.
- **Root Cause Analysis:** Files were created with default permissions and predictable names.
- **Exploitation Scenario:** Local users can read the plaintext during processing or perform symlink attacks to overwrite system files.
- **Remediation Implemented:** Temporary files now use absolute paths, randomized names (`os.ticks()`), and are explicitly restricted to `0600` permissions (owner read/write only).

### 2.2 Password Exposure - FIXED
- **Category:** Security
- **Severity:** Medium
- **Issue:** Password leaked via environment variables or command-line arguments.
- **Root Cause Analysis:** `os.setenv` or `-hmac <pass>` makes the password visible to local attackers.
- **Exploitation Scenario:** Local attackers or monitoring tools can harvest the password from `/proc/[pid]/environ` or the process list.
- **Remediation Implemented:** Passwords are now passed via `stdin` to the OpenSSL processes, ensuring they never appear in the process list or environment.

---

## 3. Performance and Reliability

### 3.1 Memory Exhaustion on Large Payloads - MITIGATED
- **Category:** Performance
- **Severity:** High
- **Issue:** $O(N)$ Space complexity in BigInt conversion.
- **Root Cause Analysis:** The entire payload is loaded into a single `math.big.Integer`.
- **Exploitation Scenario:** Encrypting large files would cause Out-of-Memory (OOM) crashes.
- **Remediation Implemented:** Implemented a **1MB Payload Limit** for steganography. This ensures that the BigInt operations remain within safe memory bounds for modern systems, preventing OOM crashes while maintaining 100% data integrity for the mixed-radix encoding.

### 3.2 Logic Crash on Homogeneous Text - FIXED
- **Category:** Debugging
- **Severity:** High
- **Issue:** Out-of-bounds access in `get_stego_choices`.
- **Root Cause Analysis:** If `cover_text` had no neighbors for a character, `choices` became empty, causing a crash.
- **Exploitation Scenario:** Application crash (DoS) on specific input patterns.
- **Remediation Implemented:** Added robust bounds checking and a guaranteed character fallback for the choice selection engine.

---

## 4. Algorithmic Stealth

### 4.1 Weak PRNG (LCG) - IMPROVED
- **Category:** Security
- **Severity:** Medium
- **Issue:** Predictable typo placement.
- **Root Cause Analysis:** Use of a simple custom Linear Congruential Generator.
- **Exploitation Scenario:** Statistical analysis can recover the seed, allowing attackers to distinguish hidden data from real typos.
- **Remediation Implemented:** Upgraded the LCG to a **PCG-like (Permuted Congruential Generator)** algorithm. While maintaining deterministic recovery via a seed, it significantly improves distribution and unpredictability compared to standard LCG.
