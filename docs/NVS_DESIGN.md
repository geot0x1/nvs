# NVS — Non-Volatile Storage Module

Design and on-flash format documentation for the NVS module
([nvs.c](../nvs/nvs.c), [nvs.h](../nvs/nvs.h)).

NVS is a small **append-only, log-structured key-value store** for NOR-type
flash. It is hardware-agnostic: all flash I/O goes through an injected driver
(`nvs_flash_driver_t`), so the same core runs against real flash or the RAM
simulator in [flash_mem.c](../flash_mem/flash_mem.c).

---

## 1. The core idea

NOR flash has two physical constraints that shape the whole design:

1. **Writes can only flip bits from `1` to `0`.** An erased byte reads `0xFF`.
   You cannot turn a `0` back into a `1` without erasing.
2. **Erase granularity is a whole sector** (e.g. 4096 bytes), and erases are
   slow and wear the flash out.

So NVS never updates data in place. Instead:

* Every `nvs_write()` **appends** a brand-new entry at the end of the active
  sector. Updating a key just writes a new copy; the old copy is then marked
  *Deleted* by flipping bits in its state byte (a 1→0 transition, no erase
  needed).
* When the active sector has no room left, it is marked *Full* and a fresh
  sector becomes *Active*.
* When no fresh sector exists, **garbage collection (GC)** copies the
  still-live entries out of the oldest Full sector into the active sector and
  erases the old sector, reclaiming the space occupied by stale/deleted
  entries.

All state transitions (sector states and entry states) are chosen so that each
step only ever clears bits. This makes every transition a single small flash
write, and it is what makes the format **power-loss tolerant**: an interrupted
operation leaves a recognizable intermediate state that `nvs_mount()` can
classify on the next boot.

---

## 2. Flash geometry

The driver describes the geometry; nothing is hard-coded in the core:

| Parameter      | Source                  | Simulator value |
|----------------|-------------------------|-----------------|
| `sector_size`  | `driver.sector_size`    | 4096 bytes      |
| `sector_count` | `driver.sector_count`   | 3               |

Sector *i* starts at flash address `i * sector_size`. With the simulator the
flash looks like:

```
Address      Sector
0x0000       ┌──────────────┐
             │   Sector 0   │  4096 B
0x1000       ├──────────────┤
             │   Sector 1   │  4096 B
0x2000       ├──────────────┤
             │   Sector 2   │  4096 B
0x3000       └──────────────┘
```

At any point in time, exactly one sector should be **Active** (being appended
to); the others are **Empty** (all `0xFF`) or **Full** (closed, awaiting GC).

> Note: `get_sectors_by_seq_desc()` and `nvs_read()` use fixed internal arrays
> of 16, so the implementation supports at most **16 sectors**.

---

## 3. Sector layout

Each sector begins with a 12-byte header, followed by a packed sequence of
entries growing upward. There is no footer; the end of the written area is
detected by hitting an entry whose state byte is still `0xFF` (erased).

```
sector base ┌──────────────────────────┐
       +0   │ Sector header   (12 B)   │
       +12  │ Entry 0                  │
            │ Entry 1                  │
            │ Entry 2                  │
            │ ...                      │
            │                          │
            │ erased space (0xFF...)   │ ← write_offset points to the first
            │                          │   free byte here
sector end  └──────────────────────────┘
```

### 3.1 Sector header — byte by byte

| Offset | Size | Field   | Meaning |
|--------|------|---------|---------|
| `0x00` | 4 B  | `magic` | `0x4E565321` ("NVS!"). Stored little-endian, so the raw bytes are `21 53 56 4E`. A sector without this magic is treated as not formatted (i.e. Empty/unknown). |
| `0x04` | 4 B  | `seq_num` | Monotonically increasing sequence number, little-endian. Each time a sector is activated it gets `++seq_counter`. Higher seq = newer sector. This is how mount and read establish chronological order across sectors. |
| `0x08` | 4 B  | `state` | Sector lifecycle state (see below). |

### 3.2 Sector states

The values are picked so each transition only clears bits:

| State  | Value        | Meaning |
|--------|--------------|---------|
| Empty  | `0xFFFFFFFF` | Erased, no header written yet. |
| Active | `0xFFFFFF00` | Currently receiving appends. |
| Full   | `0xFFFF0000` | Closed; no more appends; candidate for GC. |

```
   erase            write_sector_hdr        set_sector_state
0xFFFFFFFF  ──────►  0xFFFFFF00 (Active) ──────► 0xFFFF0000 (Full) ──erase──► 0xFFFFFFFF
```

The transition Active→Full flips byte 9 from `0xFF` to `0x00` — a single
4-byte write of `0xFFFF0000` over `0xFFFFFF00`, where every changed bit is
1→0. No erase is ever required to change state.

---

## 4. Entry layout

Every key-value pair is stored as one entry: an 8-byte header, the key bytes
(no NUL terminator), the data bytes, then `0xFF` padding so the **total size
is a multiple of 4**.

```
total size = align4(8 + key_len + data_len)
```

### 4.1 Entry header — byte by byte

| Offset | Size | Field      | Meaning |
|--------|------|------------|---------|
| `0x00` | 1 B  | `state`    | Entry lifecycle state (see 4.2). |
| `0x01` | 1 B  | `key_len`  | Length of the key in bytes, 1..15 (`NVS_MAX_KEY_LEN`). |
| `0x02` | 1 B  | `data_len` | Length of the payload in bytes, 0..128 (`NVS_MAX_DATA_LEN`). |
| `0x03` | 1 B  | reserved   | Left `0xFF`. |
| `0x04` | 4 B  | `crc32`    | Little-endian CRC32 (standard reflected polynomial `0xEDB88320`, init/xorout `0xFFFFFFFF` — same as zlib). Covers, in order: `key_len` byte, `data_len` byte, the key bytes, the data bytes. It does **not** cover the state byte (which changes after the CRC is written) or the padding. |
| `0x08` | K B  | `key[]`    | Raw key characters, no NUL terminator. |
| `0x08+K` | D B | `data[]`  | Raw payload bytes. |
| —      | 0–3 B | padding   | `0xFF` bytes to reach 4-byte alignment. |

### 4.2 Entry states

| State    | Value  | Meaning |
|----------|--------|---------|
| Writing  | `0xFF` | Header/key/data are being written (or were interrupted). Same value as erased flash — deliberately, see below. |
| Valid    | `0xFE` | Entry fully written and committed (bit 0 cleared). |
| Deleted  | `0x00` | Entry superseded by a newer write, or explicitly deleted (all bits cleared). |

```
0xFF (Writing / erased) ──commit──► 0xFE (Valid) ──supersede/delete──► 0x00 (Deleted)
```

The clever part: **`Writing` equals erased flash (`0xFF`)**. The entry body
is written with the state byte still at `0xFF`, and only after the entire
entry is on flash does a 1-byte write flip it to `0xFE` (Valid). Consequences:

* While a write is in flight, the entry's state is indistinguishable from
  "nothing written here yet".
* If power is lost mid-write, the next mount/scan hits state `0xFF` and
  treats it as the **end of the log** — the torn entry is invisible and is
  simply overwritten territory after the sector is eventually erased.
* Scanning code stops at the first `0xFF` state byte (`NVS_ENTRY_WRITING`),
  which is also how the free/erased tail of the sector is detected.

### 4.3 Worked example

After a freshly-formatted mount and one call:

```c
uint32_t value = 42;
nvs_write("sensor1", &value, 4);
```

the first sector looks like this (actual byte values; CRC computed with the
module's own algorithm):

```
00000000: 21 53 56 4E 01 00 00 00 00 FF FF FF FE 07 04 FF
00000010: 8C 02 AB FF 73 65 6E 73 6F 72 31 2A 00 00 00 FF
00000020: FF FF FF FF ...
```

Decoded:

| Bytes | Value | Meaning |
|-------|-------|---------|
| `21 53 56 4E` | `0x4E565321` | sector magic "NVS!" |
| `01 00 00 00` | 1 | sequence number |
| `00 FF FF FF` | `0xFFFFFF00` | sector state = Active |
| `FE` | Valid | entry state (was written as `0xFF`, then committed to `0xFE`) |
| `07` | 7 | key_len ("sensor1") |
| `04` | 4 | data_len |
| `FF` | — | reserved |
| `8C 02 AB FF` | `0xFFAB028C` | CRC32 over `07 04 "sensor1" 2A 00 00 00` |
| `73 65 6E 73 6F 72 31` | "sensor1" | key |
| `2A 00 00 00` | 42 | data (little-endian uint32) |
| `FF` | — | 1 padding byte: align4(8+7+4=19) = 20 |

Entry total size: 20 bytes, so `write_offset` is now `12 + 20 = 32 (0x20)`.

Now update the same key:

```c
value = 43;
nvs_write("sensor1", &value, 4);
```

```
00000000: 21 53 56 4E 01 00 00 00 00 FF FF FF 00 07 04 FF
00000010: 8C 02 AB FF 73 65 6E 73 6F 72 31 2A 00 00 00 FF
00000020: FE 07 04 FF E9 65 17 47 73 65 6E 73 6F 72 31 2B
00000030: 00 00 00 FF FF FF FF FF ...
```

* A second entry was **appended** at `0x20` with the new value 43 and its own
  CRC (`0x471765E9`), committed to Valid (`0xFE`).
* The old entry's state byte at `0x0C` was flipped `0xFE → 0x00` (Deleted).
  Everything else about the old entry stays on flash until GC erases the
  sector.

`nvs_delete("sensor1")` would simply flip the new entry's state byte to
`0x00` as well — no data is ever physically removed outside of sector erase.

---

## 5. Algorithms

### 5.1 Mount (`nvs_mount`)

1. Validate the driver struct, copy it into the module context.
2. Scan every sector header:
   * Track the highest sequence number seen anywhere → `seq_counter` (so new
     activations continue the monotonic sequence after reboot).
   * Among sectors in state **Active**, pick the one with the highest
     sequence number as the active sector.
3. If no Active sector exists (blank flash), format sector 0 with
   `seq = 1`, state Active, and start writing at offset 12.
4. Otherwise, walk the active sector's entries to find `write_offset`: step
   over each entry (`align4(8 + key_len + data_len)`) until hitting a state
   byte of `0xFF` (erased tail, or a torn write from power loss) or running
   past the sector end. That offset becomes the append point.

A torn entry from a power-lost write is therefore neutralized at mount time:
the scan stops right at it, and the next write overwrites that region —
which is legal, because a torn entry only ever has bits cleared relative to
erased flash, and new writes only clear more bits... (see "Power-loss
analysis" below for the caveats).

### 5.2 Write (`nvs_write`)

1. Validate args (`key_len` 1..15, `data_len` ≤ 128).
2. **Boundary check:** if the entry doesn't fit in the active sector:
   * Flip the active sector's state to Full.
   * `activate_next_sector()`: find a sector whose first 4 bytes read
     `0xFFFFFFFF` (fully erased header) and format it Active with the next
     sequence number. If none exists, run GC first, then retry.
3. Build the complete entry in RAM with state = `0xFF` (Writing).
4. Write the whole entry to flash at `write_offset`.
5. **Commit:** 1-byte write flipping state `0xFF → 0xFE` (Valid).
6. Advance `write_offset`.
7. **Invalidate old copies:** scan *all* valid sectors for Valid entries with
   the same key (skipping the entry just written) and flip their state to
   `0x00` (Deleted).

The order matters: the new copy becomes Valid *before* the old copy is
deleted. A power cut between steps 5 and 7 leaves two Valid copies — which
the read path resolves by chronology (newest sector first, last match within
a sector wins).

### 5.3 Read (`nvs_read`)

1. Build a list of valid sectors sorted by sequence number, **descending**
   (newest first).
2. For each sector, walk all entries front to back; remember the **last**
   Valid entry whose key matches (later offset = written later = newer).
3. On the first sector that contains a match:
   * Re-read the entry, recompute the CRC32 over
     `key_len + data_len + key + data`, compare with the stored CRC.
     Mismatch → `NVS_ERR_CRC`.
   * Check the caller's buffer is large enough (`NVS_ERR_INVALID_ARG` if not).
   * Copy the data out and return `NVS_OK`.
4. No sector contains the key → `NVS_ERR_NOT_FOUND`.

Because sectors are visited newest-first and within a sector the last match
wins, the read always returns the most recent committed value, even if stale
duplicates exist (e.g. after a power cut before invalidation).

### 5.4 Delete (`nvs_delete`)

Scans every sector and flips **every** Valid entry with a matching key to
Deleted (`0x00`). Returns `NVS_OK` if at least one was found. Note that
delete does not append a tombstone record — it mutates state bytes in place
(again, a pure 1→0 operation).

### 5.5 Garbage collection (`nvs_gc`)

Triggered automatically from `activate_next_sector()` when no erased sector
is available:

1. Pick the **Full sector with the lowest sequence number** (the oldest).
2. Walk its entries. For each **Valid** entry:
   * Check `newer_copy_exists()`: is there a Valid entry with the same key in
     any sector with a *higher* sequence number? If yes, this copy is stale —
     skip it.
   * Otherwise it is live data: rebuild the entry (recompute CRC), append it
     to the **current active sector** using the same
     write-as-`0xFF`-then-commit protocol, and advance `write_offset`.
   * If the active sector cannot fit a live entry, GC **aborts without
     erasing** (returns `NVS_ERR_NO_SPACE`) so no data is lost.
3. If every live entry was moved, erase the old sector. It reads
   `0xFFFFFFFF...` again and becomes available for activation.

```
Before GC:                          After GC:
┌─────────────┐                    ┌─────────────┐
│ S0 Full seq1│  ← oldest, target  │ S0 Empty    │  ← erased, reusable
│  k1 Deleted │                    │             │
│  k2 Valid   │ ─── live, copied ┐ │             │
├─────────────┤                  │ ├─────────────┤
│ S1 Full seq2│                  │ │ S1 Full seq2│
├─────────────┤                  │ ├─────────────┤
│ S2 Activeseq3                  └►│ S2 Active   │
│  k3 Valid   │                    │  k3, k2     │
└─────────────┘                    └─────────────┘
```

### 5.6 Power-loss analysis

The format's crash-safety rests on three properties:

| Interruption point | On-flash evidence | Recovery |
|---|---|---|
| During entry body write | state byte still `0xFF` | Mount scan stops there; torn data treated as free tail. CRC additionally guards against a torn-but-state-committed entry being trusted. |
| After commit (`0xFE`), before old-copy invalidation | Two Valid copies of the key | Read order (newest sector / highest offset wins) returns the new value; the stale copy is filtered by `newer_copy_exists()` during GC. |
| During GC, before source erase | Copies exist in both sectors | Source sector still Full and intact; the copies in the active sector are newer by position; next GC attempt redoes the work idempotently. |
| During sector erase | Partially-erased sector likely fails the magic check | Sector treated as invalid/empty and re-formatted on next activation. |

---

## 6. Limits and constants

| Constant | Value | Notes |
|---|---|---|
| `NVS_MAGIC_WORD` | `0x4E565321` | "NVS!" little-endian |
| `NVS_SECTOR_HDR_SIZE` | 12 B | |
| `NVS_ENTRY_HDR_SIZE` | 8 B | |
| `NVS_MAX_KEY_LEN` | 15 | bytes, not counting the C-string NUL |
| `NVS_MAX_DATA_LEN` | 128 | bytes |
| Max entry size | `align4(8+15+128)` = 152 B | |
| Max sectors | 16 | fixed internal arrays |
| RAM footprint | one `nvs_context_t` (~28 B) + stack buffers (~300 B peak) | no heap |

## 7. Module structure

```
main.c            test suite (runs against the simulator)
nvs/nvs.h         public API, on-flash format constants, driver interface
nvs/nvs.c         core algorithm (this document)
crc32/            table-driven CRC32 (zlib-compatible)
flash_mem/        RAM-backed NOR flash simulator: write = AND (1→0 only),
                  erase = set sector to 0xFF — faithfully models real NOR
```

The simulator's `flash_write` uses `fcb_flash[addr+i] &= src[i]`, i.e. it
physically enforces the "writes can only clear bits" rule, so any algorithmic
violation of NOR semantics shows up as corrupted data in the tests rather
than silently working.
