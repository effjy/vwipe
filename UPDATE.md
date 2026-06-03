# Virtual Wipe (vWipe) Update Release Notes

---

# v2.7.0

This release updates **Virtual Wipe** from version **2.6.0** to **2.7.0**. It documents the data-sanitization hardening, I/O, and verification work that landed in `vwipe.c` and `vwipe_ram.c` after the 2.6.0 notes were written, bringing the release documentation back in line with the shipped binary.

## 🔐 Security & Sanitization Enhancements

### 1. CSPRNG Seeding Extended to the GUI Wiper (vwipe.c)
* In 2.6.0, cryptographically secure seeding was applied only to the RAM sanitizer (`vwipe_ram.c`). The GUI wiper now also seeds its patterns from the kernel via `get_secure_random()`/`getrandom()`:
  * File wipe seed — `vwipe.c:682-683`
  * Per-thread free-space base seed — `vwipe.c:903-906`
  * Surfaced in the compliance reporting row — `vwipe.c:2097`

### 2. Per-Block Unique Pattern Derivation (`splitmix64`)
* Random data is re-derived per chunk/block so it never repeats within or across files (`vwipe.c:691`, `vwipe.c:956`).

### 3. Verification Pass Support (`PASS_VERIFY`)
* `wipe_file()` can read back and `memcmp` a pass against the previously written pattern, aborting on mismatch (`vwipe.c:695-725`).

### 4. Anti-Forensic Buffer Hardening
* Wipe buffers are now protected with `madvise(MADV_DONTDUMP)`, `secure_memzero`, and `mlock` (`vwipe.c:672-678`, `767-776`).

## ⚡ I/O & Durability Changes (vwipe.c)

### 5. `O_DIRECT` with Graceful Fallback + Per-Tail Toggling
* Aligned I/O via `O_DIRECT`, with an `EINVAL` fallback and temporary disabling for unaligned file tails (`vwipe.c:640-648`, `705-719`, `731-745`).

### 6. `O_SYNC` Removed From the Parallel Free-Space Writer
* The free-space worker no longer opens temp files with `O_SYNC`; durability is instead provided by a single `fsync()` at file completion, avoiding a UI freeze on every `write()` (`vwipe.c:923-925`, `980`).
* **Note:** `wipe_file()` intentionally still uses `O_SYNC` (`vwipe.c:640,647`).

## ⚙️ RAM Module Robustness (vwipe_ram.c)

### 7. Mid-Run `mlock` Degradation Handling
* If `mlock` begins failing partway through a fill, `g_mlock_supported` is cleared and previously locked pages are unlocked during cleanup (`vwipe_ram.c:175-176`, `282`).

---

# v2.6.0

This release updated **Virtual Wipe** from version **2.5.5** to **2.6.0**. This release includes major security enhancements, robustness bug fixes, signal safety compliance, and transitions the project to a clean open-source licensing model.

---

## 🛠️ Summary of Bug Fixes & Improvements

### 1. Directory Metadata & Entry Sanitization (vwipe.c)
* **Problem (v2.5.5):** Directory recursive sanitization only overwrote individual files but left directory metadata (access/modification times) and deleted directory entry records in parent directories readable on disk.
* **Fix (v2.6.0):** 
  * Now explicitly zeroes out directory timestamps (`atime`, `mtime` to epoch `0`) via `utimensat` (with `AT_SYMLINK_NOFOLLOW`) right before deletion.
  * Triggers synchronous `fsync` calls on parent directories immediately after directory renaming and deletion, ensuring the entries are purged from metadata pages on disk.

### 2. TRIM Execution Sequence (`attempt_trim`) (vwipe.c)
* **Problem (v2.5.5):** Wiping cleanup deleted (`unlinked`) the temporary files before calling `attempt_trim()`. Because the file no longer existed, `attempt_trim` failed to open the path, rendering SSD block discarding (`BLKDISCARD`) a no-op.
* **Fix (v2.6.0):** Re-ordered the sequence. `attempt_trim` is now executed on the active path (`new_name` or `path` depending on rename success) *before* `unlink` is called, ensuring the TRIM operation runs successfully.

### 3. Thread Safety: Sanitization Scheme Choice (vwipe.c)
* **Problem (v2.5.5):** Spun worker threads read the global, non-atomic variable `current_scheme_idx` directly. If the user changed the active scheme in the GUI combo box while a wipe was in progress, it caused a data race and undefined behavior.
* **Fix (v2.6.0):** Redefined `ThreadData` to encapsulate a complete local copy of the selected `WipeScheme`. Sanitization worker functions now accept a pointer to this local copy.

### 4. Progress Tracking Atomicity (vwipe.c)
* **Problem (v2.5.5):** Progress updates accessed `g_target_bytes` as a standard `volatile size_t`, which does not provide atomic access guarantees under modern compiler standards.
* **Fix (v2.6.0):** Promoted `g_target_bytes` to `atomic_size_t` and refactored all references to use `atomic_store` and `atomic_load`.

### 5. GUI Thread Creation Checking (vwipe.c)
* **Problem (v2.5.5):** Return codes of `pthread_create` were not checked when spawning workers. If a thread failed to launch (e.g. system resource exhaustion), the UI became locked in a permanent "busy" state.
* **Fix (v2.6.0):** Checked return values for all thread creation tasks. In case of failure, resource cleanup is run, an error is logged to telemetry logs, and the UI is immediately reset (`idle_reset_ui`).

---

## ⚡ vwipe_ram.c Fixes (CLI Memory Sanitizer)

### 1. Robust `mlock` Capability Checking
* **Problem (v2.5.5):** Tested memory locking availability by locking a hardcoded address `0x1000` (page 1). Because page 1 is typically unmapped, this call failed with `ENOMEM`, meaning the check set `g_mlock_supported = 1` even if the user lacked permissions.
* **Fix (v2.6.0):** Refactored to allocate a dummy page via `mmap`, lock it using `mlock`, unlock, and clean up. This reliably detects user capability configurations.

### 2. Async-Signal-Safe Signal Handler
* **Problem (v2.5.5):** The signal handler called `printf()` and `restore_terminal()`. Since `printf` is not async-signal-safe, it risked deadlocking the program if interrupted during a logging loop.
* **Fix (v2.6.0):** The signal handler now strictly updates the volatile atomic flags `g_stop_flag` and `fill_keep_running`. Telemetry logging and terminal restoration are deferred to the main execution thread.

### 3. Cryptographically Secure PRNG Seeding
* **Problem (v2.5.5):** Seeded the `splitmix64` generator in the random pass with low-entropy values (`time(NULL)`).
* **Fix (v2.6.0):** Obtains a high-entropy seed using the `getrandom()` system call from the kernel before commencing the random pass.

### 4. Clear Leftover Input on Exit Prompt
* **Problem (v2.5.5):** Users typing `s` and pressing `Enter` to interrupt left a trailing `\n` in the input buffer, instantly triggering the final `getchar()` confirmation prompt and skipping the exit screen.
* **Fix (v2.6.0):** Non-blockingly polls and purges leftover input characters in the buffer before presenting the exit prompt.

---

## 📄 Open Source Licensing Transition
* **Unused Licensing Code:** Completely deleted over 500 lines of unused proprietary licensing dialog loops, validation checkers, activation checks, and context-checking SHA-256 implementation code from `vwipe.c`.
* **Licensing Model:** Fully moved the project to the standard **MIT License**, creating a dedicated `LICENSE` file in the root folder.
