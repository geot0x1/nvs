# NVS Internals: Flash Layout and Data Storage

This document explains how the NVS (Non-Volatile Storage) library organises data on flash memory — how sectors are structured, how entries are laid out, how the state machines work, and how reads, writes, and garbage collection operate.

---

## 1. Architecture Overview

NVS is a **log-structured, append-only key-value store** designed for NOR flash memory. Key design properties:

- All flash I/O is abstracted behind an injected driver (`nvs_flash_driver_t`), making the core hardware-agnostic.
- Data is never overwritten in place. Updates append a new entry and invalidate the old one.
- State transitions are always bit-flip monotonic (1 → 0 only), exploiting NOR flash's write semantics.
- CRC32 guards both sector headers and individual entries against corruption.

**Source files:**

| File | Purpose |
|---|---|
| [nvs/nvs.c](../nvs/nvs.c) | Core implementation |
| [nvs/nvs.h](../nvs/nvs.h) | Public API and constants |
| [nvs/nvs_internal.h](../nvs/nvs_internal.h) | On-flash format constants |
| [crc32/crc32.c](../crc32/crc32.c) | CRC32 computation |
| [flash_mem/flash_mem.c](../flash_mem/flash_mem.c) | RAM-backed NOR flash simulator |

---

## 2. Flash Geometry

The flash geometry is provided at mount time via the `nvs_flash_driver_t` struct. The simulator uses:

| Parameter | Value |
|---|---|
| Sector size | 4096 bytes |
| Sector count | 3 |
| Total flash | 12,288 bytes |

Sector `i` occupies flash addresses `[i * sector_size, (i+1) * sector_size)`. With the default 4096-byte sector size:

```
Address 0x0000 – 0x0FFF  →  Sector 0
Address 0x1000 – 0x1FFF  →  Sector 1
Address 0x2000 – 0x2FFF  →  Sector 2
```

---

## 3. Sector Layout

Each sector is divided into a fixed 16-byte header followed by a sequence of variable-length entries growing toward the end of the sector:

```
┌─────────────────────────────────┐  ← sector base address
│        Sector Header            │  16 bytes  (NVS_SECTOR_HDR_SIZE)
├─────────────────────────────────┤  ← offset 0x10
│  Entry 0 (header + key + data)  │
├─────────────────────────────────┤
│  Entry 1                        │
├─────────────────────────────────┤
│  Entry 2                        │
├─────────────────────────────────┤
│  ...                            │
├─────────────────────────────────┤  ← write_offset (next free byte)
│  Erased space (0xFF bytes)      │
└─────────────────────────────────┘  ← sector base + sector_size
```

---

## 4. Sector Header (16 bytes)

Every sector begins with a 16-byte header that identifies it and tracks its lifecycle state.

```
Byte offset   Size   Field      Description
0x00          4      magic      0x4E565321  ("NVS!" little-endian)
0x04          4      seq_num    Monotonically increasing sequence number
0x08          4      state      Lifecycle state (see §5)
0x0C          4      crc32      CRC32 over bytes 0x00–0x0B (magic + seq + initial state)
```

**CRC coverage:** The CRC is computed over the first 12 bytes only (magic + seq_num + state) at header write time. After state transitions, the state field is overwritten in-place via a bit-flip write, so the stored CRC no longer matches — this is intentional. The mount scan accepts a CRC mismatch as long as the state field is not `0xFFFFFFFF` (i.e., the header was previously written and then transitioned). A CRC mismatch with state still equal to all-ones (`0xFFFFFFFF`) is the signature of a torn initial write and is rejected.

---

## 5. Sector State Machine

Sector states use bit-flip-only progression, exploiting the fact that NOR flash can only clear bits (1 → 0) without an erase. Each state transition writes a value with more zero bits than the previous one.

```
  Erased (all 0xFF)
       │
       │  write_sector_hdr(seq, ACTIVE)
       ▼
  ACTIVE   (0xFFFFFF00)   ← current write target
       │
       │  set_sector_state(FULL)
       ▼
  FULL     (0xFFFF0000)   ← no more writes, eligible for GC
       │
       │  set_sector_state(FREEING)  [during GC]
       ▼
  FREEING  (0xFF000000)   ← live entries being evacuated
       │
       │  erase_sector()
       ▼
  Erased (all 0xFF)
```

State constants from [nvs_internal.h](../nvs/nvs_internal.h):

```c
#define NVS_SECTOR_ACTIVE   (0xFFFFFF00U)
#define NVS_SECTOR_FULL     (0xFFFF0000U)
#define NVS_SECTOR_FREEING  (0xFF000000U)
```

A state transition is a single 4-byte write to offset `+8` in the sector header. Because NOR flash only clears bits, these transitions are irreversible without an erase.

---

## 6. Entry Layout

Each key-value pair is stored as a single entry. All entries are 4-byte aligned. The format is:

```
Byte offset    Size     Field       Description
0x00           1        state       Entry lifecycle (see §7)
0x01           1        key_len     Key length in bytes (1–15)
0x02           1        data_len    Data length in bytes (0–128)
0x03           1        reserved    Always 0xFF
0x04           4        crc32       CRC32 (see below)
0x08           key_len  key[]       Key bytes (not null-terminated)
0x08+key_len   data_len data[]      Value bytes
               0–3      padding     0xFF bytes to 4-byte-align total size
```

**Total entry size** (from [nvs.c:568](../nvs/nvs.c#L568)):

```c
align4(NVS_ENTRY_HDR_SIZE + key_len + data_len)
```

For example, a key of 5 bytes and data of 10 bytes:

```
align4(8 + 5 + 10) = align4(23) = 24 bytes
```

**CRC coverage:** The CRC covers `key_len` (1 byte) + `data_len` (1 byte) + `key[]` + `data[]`. It does not cover the state byte, so the state can be independently flipped without invalidating the CRC.

---

## 7. Entry State Machine

Entry states also use bit-flip-only progression:

```
  WRITING  (0xFF)   ← initial state; indistinguishable from erased flash
       │
       │  set_entry_state(VALID)   [1-byte write: 0xFF → 0xFE]
       ▼
  VALID    (0xFE)   ← committed, readable
       │
       │  set_entry_state(DELETED) [1-byte write: 0xFE → 0x00]
       ▼
  DELETED  (0x00)   ← superseded or explicitly deleted
```

State constants from [nvs_internal.h](../nvs/nvs_internal.h):

```c
#define NVS_ENTRY_WRITING  (0xFFU)
#define NVS_ENTRY_VALID    (0xFEU)
#define NVS_ENTRY_DELETED  (0x00U)
```

**Power-loss safety of WRITING state:** Because `WRITING` (0xFF) is identical to erased flash, a torn write — power lost before the commit byte is flipped — is invisible to the mount scan. The scan stops at any entry whose state is 0xFF, treating it as the boundary between written and free space. The torn entry body is simply overwritten by the next write after recovery.

---

## 8. Write Path

Writing a key-value pair ([nvs.c:285](../nvs/nvs.c#L285)):

1. **Validate** key length (1–15) and data length (0–128).
2. **Check space:** if `write_offset + entry_size > sector_size`, mark the active sector FULL and call `activate_next_sector()` (which may trigger GC).
3. **Build the entry in RAM** with state = `NVS_ENTRY_WRITING` (0xFF):
   - Compute CRC over `key_len + data_len + key[] + data[]`.
   - Fill the 8-byte header (state, key_len, data_len, reserved=0xFF, CRC).
   - Append key bytes and data bytes, then pad to 4-byte alignment with 0xFF.
4. **Write the full entry to flash** at `active_sector_addr + write_offset`.
5. **Commit:** write a single byte `0xFE` (VALID) to the entry's state field. This is the atomic commit point.
6. **Advance** `write_offset` by the entry's total size.
7. **Invalidate old copies:** scan every sector for other VALID entries with the same key and flip their state to `0x00` (DELETED).

The two-phase write (body then commit byte) ensures that a power failure before step 5 leaves the entry in the WRITING state, which the mount scan discards.

---

## 9. Read Path

Reading a key ([nvs.c:343](../nvs/nvs.c#L343)):

1. Sort all sectors by sequence number, descending (newest first).
2. For each sector, walk entries front-to-back, recording the last VALID entry whose key matches.
3. On the first sector that contains a match, re-read the entry header and full payload from flash.
4. Recompute CRC and compare against the stored CRC. Return `NVS_ERR_CRC` on mismatch — no fallback to older copies.
5. Copy payload to the caller's buffer and return `NVS_OK`.

**CRC policy:** If the newest copy of a key fails CRC verification, the error is surfaced immediately. Returning stale data silently when corruption is detected is considered more dangerous than letting the caller handle the failure.

---

## 10. Delete Path

Deleting a key ([nvs.c:481](../nvs/nvs.c#L481)):

1. Scan every sector.
2. For each VALID entry whose key matches, write a single `0x00` byte to its state field (DELETED).
3. Return `NVS_OK` if at least one entry was found, `NVS_ERR_NOT_FOUND` otherwise.

---

## 11. Sector Sequence Numbers and Wear Leveling

Each sector is assigned a monotonically increasing sequence number when it becomes ACTIVE. The global `seq_counter` in `NvsContext` tracks the next value to assign.

Sequence numbers serve two purposes:

- **Chronological ordering:** sectors with higher sequence numbers contain newer data. Reads walk sectors in descending sequence order so the newest copy of a key is found first.
- **Wear leveling:** GC always targets the FULL sector with the **lowest** sequence number (the oldest). This ensures all sectors rotate through the write cycle roughly equally.

**Wrap-around handling ([nvs.c:563](../nvs/nvs.c#L563)):**

```c
static inline uint32_t seq_sort_key(uint32_t seq)
{
    return (seq == 0) ? 0xFFFFFFFFU : seq;
}
```

If the 32-bit counter wraps to zero, it is mapped to the highest possible sort key so it is treated as the most recent sector, not the oldest.

---

## 12. Garbage Collection

GC is triggered by `activate_next_sector()` when no erased sector is available ([nvs.c:1098](../nvs/nvs.c#L1098)).

### GC Algorithm (`nvs_gc`, [nvs.c:1036](../nvs/nvs.c#L1036))

1. Find the FULL sector with the lowest sequence number (the GC victim/source).
2. Call `nvs_gc_resume()` with that sector as the target.

### GC Resume (`nvs_gc_resume`, [nvs.c:971](../nvs/nvs.c#L971))

This function does the actual work and is also called at mount time to resume interrupted GC:

1. Mark the source sector state as `FREEING` (0xFF000000).
2. Walk every entry in the source sector:
   - If the entry is not VALID, skip it.
   - Call `newer_copy_exists()`: does any sector with a higher sequence number contain a VALID entry for the same key?
   - If yes: the entry is stale — skip it.
   - If no: the entry is live — copy it to the active sector using the normal write-and-commit protocol.
   - If the active sector fills during copying, mark it FULL and activate a new empty sector.
3. If all live entries were successfully copied, erase the source sector.
4. If the active sector filled and no empty sector was available (step 2 sub-case), abort and return `NVS_ERR_NO_SPACE`. The source remains in FREEING state for the next mount to resume.

### Power-Loss Safety During GC

If power is lost while the source sector is in FREEING state, the next `nvs_mount()` detects it (step at [nvs.c:270](../nvs/nvs.c#L270)) and calls `nvs_gc_resume()` again. Live entries already copied to the newer sector are skipped because `newer_copy_exists()` finds them. The operation is idempotent.

---

## 13. Mount Initialization

`nvs_mount()` ([nvs.c:138](../nvs/nvs.c#L138)) reconstructs the in-RAM context from flash:

1. Validate the driver struct (non-null callbacks, non-zero geometry, sector count ≤ 16).
2. Scan all sector headers:
   - Track the highest sequence number seen → initializes `seq_counter`.
   - Find the ACTIVE sector with the highest sequence number → becomes `active_sector_addr`.
   - Count sectors with the NVS magic word but a bad CRC → `corrupt_sector_count`.
3. **If no ACTIVE sector exists:**
   - If FULL sectors exist, call `activate_next_sector()` (which runs GC).
   - Otherwise, format sector 0 as ACTIVE with sequence number 1.
4. **If an ACTIVE sector was found:**
   - Walk its entries to determine `write_offset` (the next free byte):
     - Advance through valid entries using `entry_total_size()`.
     - Stop at state=0xFF (WRITING/erased boundary), or at out-of-range key/data lengths, or at a size that would exceed the sector boundary.
     - **Torn write recovery:** if an entry in WRITING state has valid-looking lengths, it is explicitly marked DELETED (0x00) before skipping past it.
5. Check all sectors for FREEING state and resume any interrupted GC.

---

## 14. CRC32 Implementation

**File:** [crc32/crc32.c](../crc32/crc32.c)

| Parameter | Value |
|---|---|
| Polynomial | 0xEDB88320 (reflected Ethernet CRC-32) |
| Initial value | 0xFFFFFFFF |
| XOR-out | 0xFFFFFFFF |
| Table | 256-entry pre-computed lookup table |

```c
uint32_t crc32_gen(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFU;
    while (len--)
        crc = (crc >> 8) ^ crc32_table[(crc ^ *p++) & 0xFFU];
    return crc ^ 0xFFFFFFFFU;
}
```

**Sector header CRC** covers 12 bytes: magic (4) + seq (4) + initial state (4).

**Entry CRC** covers: `key_len` (1) + `data_len` (1) + `key[]` (key_len bytes) + `data[]` (data_len bytes).

---

## 15. Power-Loss Tolerance Summary

| Failure scenario | On-flash evidence | Recovery |
|---|---|---|
| Power lost during entry body write, before commit | state = 0xFF (same as erased) | Mount scan stops at 0xFF state; next write overwrites it |
| Power lost after commit, before old-copy invalidation | Two VALID entries for the same key | Read walks newest sector first; both copies are valid; old one is invalidated on next write |
| Power lost after source sector marked FREEING, before erase | Source sector state = 0xFF000000 | Next mount detects FREEING and resumes GC |
| Power lost during sector erase | Magic check fails on re-read | Sector treated as blank on next mount |
| Torn sector header write | Magic present but CRC bad and state = 0xFFFFFFFF | Sector counted as corrupt, skipped |

---

## 16. Constants Reference

| Constant | Value | Defined in |
|---|---|---|
| `NVS_MAGIC_WORD` | 0x4E565321 ("NVS!") | [nvs_internal.h:5](../nvs/nvs_internal.h#L5) |
| `NVS_SECTOR_ACTIVE` | 0xFFFFFF00 | [nvs_internal.h:8](../nvs/nvs_internal.h#L8) |
| `NVS_SECTOR_FULL` | 0xFFFF0000 | [nvs_internal.h:9](../nvs/nvs_internal.h#L9) |
| `NVS_SECTOR_FREEING` | 0xFF000000 | [nvs_internal.h:11](../nvs/nvs_internal.h#L11) |
| `NVS_ENTRY_WRITING` | 0xFF | [nvs_internal.h:14](../nvs/nvs_internal.h#L14) |
| `NVS_ENTRY_VALID` | 0xFE | [nvs_internal.h:15](../nvs/nvs_internal.h#L15) |
| `NVS_ENTRY_DELETED` | 0x00 | [nvs_internal.h:16](../nvs/nvs_internal.h#L16) |
| `NVS_SECTOR_HDR_SIZE` | 16 bytes | [nvs_internal.h:19](../nvs/nvs_internal.h#L19) |
| `NVS_ENTRY_HDR_SIZE` | 8 bytes | [nvs_internal.h:22](../nvs/nvs_internal.h#L22) |
| `NVS_MAX_KEY_LEN` | 15 bytes | [nvs.h:12](../nvs/nvs.h#L12) |
| `NVS_MAX_DATA_LEN` | 128 bytes | [nvs.h:15](../nvs/nvs.h#L15) |
| `NVS_MAX_SECTORS` | 16 | [nvs.h:18](../nvs/nvs.h#L18) |
