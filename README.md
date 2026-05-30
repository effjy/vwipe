# Virtual Wipe Turbo v2.6.0

**Virtual Wipe Turbo** is a state-of-the-art secure data sanitization tool designed for high-performance forensic-grade wiping. Engineered to leverage modern multi-core processors, it utilizes a parallel "Turbo Engine" to saturate NVMe throughput, ensuring the fastest possible sanitization while maintaining strict compliance with international security standards.

## 🚀 Key Features

- ⚡ **8-Core Turbo-Wipe Engine**: Automatically detects CPU topology and launches parallel worker threads to maximize I/O throughput on SSDs and NVMe drives.
- 🛡️ **NIST SP 800-88 Rev. 1 Aligned**: Supports Baseline (Clear) and Multi-Pass (Purge) schemes used by federal and international agencies.
- 🧬 **FIPS 140-3 High-Entropy Sanitization**: Utilizes high-speed cryptographic PRNGs to ensure data on disk is mathematically indistinguishable from random noise (IND-RND).
- 🔒 **RAM Protection (mlock)**: Sensitive wiping buffers are locked into physical RAM to prevent data leakage to swap space or hibernation files.
- 🌑 **Premium Dark Aesthetic**: A sophisticated charcoal-and-teal interface designed for modern forensic workstations.
- 📁 **Comprehensive Operations**:
    *   **File Wipe**: Targeted secure deletion of individual files.
    *   **Directory Wipe**: Recursive sanitization of entire folder structures.
    *   **Free Space Wipe**: Multi-threaded sanitization of unallocated disk space.
    *   **RAM Fill**: Dedicated module to clear residual data from system memory.

## 🛠️ Prerequisites

Ensure you have the following dependencies installed before building:

### Build Tools
- `gcc` (support for C11 and OpenMP/Pthreads)
- `make`
- `pkg-config`

### Required Libraries
- `gtk+-3.0` (GTK3 Development Headers)
- `glib-2.0`
- `pthreads`

### Installation Command (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install build-essential libgtk-3-dev pkg-config
```

## 🏗️ Installation

### 1. Build the Application
```bash
make clean && make
```

### 2. System-wide Install (Optional)
```bash
sudo make install
```
This will install `vwipe` to `/usr/local/bin` and add a desktop entry with the official icon.

## 📖 Usage

### Running Locally
```bash
./vwipe
```

### Sanitization Schemes
1.  **NIST Clear**: Single-pass zero fill (fastest).
2.  **DoD 5220.22-M**: 3-pass overwrite (Standard).
3.  **NIST Purge**: 4-pass high-security sanitization with verification.
4.  **FIPS High-Entropy**: 5-pass strongest purge using multiple random patterns.

## ⚖️ Forensic Note
On **Copy-on-Write (CoW)** filesystems like Btrfs, ZFS, or APFS, individual file wiping may be bypassed by the filesystem controller. In these cases, **Free Space Sanitization** is the recommended method to ensure data destruction.

## 🔄 Release Updates & Bug Fixes (v2.6.0)

Version 2.6.0 resolves multiple logic bugs, thread safety data races, and potential vulnerabilities:
- **Directory Metadata Purging**: Wipes access/modification times and issues parent directory `fsync` calls to ensure directory entry removals are committed to disk.
- **Wipe TRIM Fix**: Re-ordered deletion sequence to call `attempt_trim` before unlinking files so storage TRIM works properly.
- **Thread Safety & Atomicity**: Isolated active scheme parameters in worker contexts and upgraded progress metric counters to atomic structures.
- **RAM Module Safety**: Patched incorrect `mlock` capability checking, async-signal safety bugs in handler routines, and seeded random passes cryptographically.

For the full detailed breakdown of fixes, see [UPDATE.md](file:///home/user/data/utils/vwipe/UPDATE.md).

## 📄 License
This project is licensed under the MIT License. See the LICENSE file for details.

Copyright © 2026 Jean-Francois Lachance-Caumartin. All rights reserved.
