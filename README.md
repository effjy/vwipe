# 🛡️ Virtual Wipe Turbo

[![C Standard](https://img.shields.io/badge/C-C11-blue.svg)](https://en.cppreference.com/w/c/11)
[![GTK Version](https://img.shields.io/badge/GTK-3.0-blue.svg)](https://www.gtk.org/)
[![License](https://img.shields.io/badge/License-Copyright-red.svg)](#-license)
[![Forensics](https://img.shields.io/badge/Standards-NIST%20SP%20800--88-success.svg)](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)

Virtual Wipe Turbo is a state-of-the-art, high-performance forensic-grade secure data and memory sanitization suite. Engineered to saturate NVMe queue depths, its multi-threaded **Turbo Engine** automatically leverages modern multi-core processors for ultra-fast parallel disk cleaning, while its custom RAM-purging module clears residual data in volatile memory, ensuring full compliance with international security standards.

---

## ✨ Engineering & Security Highlights

- ⚡ **Asynchronous Parallel Engine**: Leverages custom POSIX threads (`pthreads`) to run sanitization operations completely in the background. The free space wiper automatically scales up to 16 threads (based on CPU topology via `sysconf(_SC_NPROCESSORS_ONLN)`) to saturate disk write pipes.
- 🛡️ **NIST SP 800-88 Rev. 1 & DoD 5220.22-M Compliant**: Offers four built-in protocols:
  - *NIST Clear (1-Pass)*: Single zero-fill overwrite.
  - *DoD 5220.22-M (3-Pass)*: Zeroes, Ones, then Cryptographic Random bytes.
  - *NIST Purge (4-Pass)*: Zeroes, Ones, Random bytes, followed by a hardware verification pass.
  - *FIPS High-Entropy Purge (5-Pass)*: Multiple randomized passes using a cryptographically strong SplitMix64 pseudo-random generator, zero-fill, and verification.
- 🔒 **Comprehensive RAM Protection**:
  - Buffer locking using `mlock()` to prevent sensitive wiping buffers from spilling into physical swap space or hibernation files.
  - Memory exclusion from core dumps using `madvise()` with the `MADV_DONTDUMP` flag.
  - Core dumps disabled system-wide during execution (`prctl(PR_SET_DUMPABLE, 0)` and `RLIMIT_CORE = 0`) to prevent memory mapping recovery in the event of an unexpected termination.
- 📁 **Metadata Destruction & Secure Deletion**:
  - Prior to deletion, files are renamed to randomized hidden temp files (e.g. `.secure_wipe_del_TIME_PID.tmp`).
  - Issues `fsync()` on the parent directory file descriptor to force the filesystem controller to commit directory index changes to the physical media.
  - Issues a `BLKDISCARD` ioctl / `TRIM` call to notify NAND flash controllers to fully release sanitized sectors on solid-state drives.
  - Enforces `lstat` and `O_NOFOLLOW` check rules to skip symbolic links for target directories/files, ensuring directory traversal boundaries are strictly respected.
- 💻 **Smooth Throttled GUI**: Uses `g_idle_add` with GSource integration and mutexes to throttle interface status refreshes (~10Hz), keeping the GTK3 dark-theme UI active and responsive under massive parallel I/O loads.

---

## 🛠️ Prerequisites

Ensure your system has a C compiler and the GTK+ 3.0 development libraries installed.

### Package Installation (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install build-essential libgtk-3-dev pkg-config
```

### Build & Library Dependencies
* **Compiler**: `gcc` (with support for C11 and OpenMP/Pthreads)
* **Build System**: `make`
* **Development Libraries**: `gtk+-3.0`, `glib-2.0`, `pthreads`

---

## 🏗️ Installation

1. **Clone the Repository** (or navigate to the project directory):
   ```bash
   cd ~/data/utils/vwipe/
   ```

2. **Compile the Binaries**:
   ```bash
   make clean && make
   ```
   This will build two executables:
   - `vwipe`: The GTK3 graphical secure deletion utility.
   - `vwipe_ram`: The interactive CLI RAM sanitizer.

3. **Install System-wide** (Optional):
   ```bash
   sudo make install
   ```
   This copies the binaries to `/usr/local/bin`, installs the desktop configuration file, and sets up application icons for desktop environments.

---

## 📖 Usage

### 1. Graphical App (`vwipe`)
Launch the graphical workspace tool locally:
```bash
./vwipe
```
Or launch it from your desktop applications menu. 

**Operations supported:**
* **File Wipe**: Select and overwrite specific individual files.
* **Directory Wipe**: Recursively and securely delete entire folder trees.
* **Free Space Wipe**: Clean unallocated space on a drive to destroy previously deleted files.

### 2. RAM CLI Purger (`vwipe_ram`)
Sanitize system RAM to remove cryptographic keys or sensitive residues from memory:
```bash
./vwipe_ram [safety_margin_mb]
```
* **Parameters**: `safety_margin_mb` (100–4000 MB, defaults to `250`). Keeps this much memory untouched to prevent kernel OOM (Out Of Memory) panics.
* **Controls**: Press `s` and then `Enter` at any time to halt the fill process and gracefully release all allocated blocks.

---

## 📄 License

Copyright © 2026 Jean-Francois Lachance-Caumartin. All rights reserved.
