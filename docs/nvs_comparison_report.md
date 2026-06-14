# NVS Implementation Comparison: Custom NVS vs. ESP-IDF NVS

**Date:** 2026-06-14
**Scope:** Technical audit across robustness, memory footprint, portability, and testability.
**Implementations compared:**
- **Custom NVS** — `c:\Users\George\Desktop\workspace\development\nvs`
- **ESP-IDF NVS** — `c:\Users\George\Desktop\workspace\development\esp-idf\components\nvs_flash`

---

## Table of Contents

1. [Robustness, Data Corruption & Power-Loss Handling](#1-robustness-data-corruption--power-loss-handling)
2. [Memory Footprint](#2-memory-footprint)
3. [Portability](#3-portability)
4. [Testability](#4-testability)
5. [Summary Table](#5-summary-table)
6. [Open Audit Items](#6-open-audit-items)

---

## 1. Robustness, Data Corruption & Power-Loss Handling

### 1.1 Custom NVS

#### Write Atomicity

Two-phase commit (`nvs.c:539–561`):

1. Write full entry to flash with `state = WRITING (0xFF)`
2. Flip the single state byte to `VALID (0xFE)`

The state-byte flip is the sole atomic commit point. Bit-flip-only semantics are exploited — states only progress `0xFF → 0xFE → 0x00`, which is valid for NOR flash. If power is lost before the flip, the entry remains as `WRITING` and is skipped on remount.

#### CRC Scheme

- **Algorithm:** CRC32, Ethernet polynomial `0xEDB88320` (`crc32.c:7`), table-driven with lazy init.
- **Protected scope:** `key_len (1B) + data_len (1B) + key[] + data[]` (`nvs.c:108–128`).
- **NOT protected:** Entry header state byte, reserved fields, and the entire sector header (`magic`, `seq_num`, sector state).
- **Verification:** Computed on-the-fly at read time (`nvs.c:673–687`) before returning data to caller.

> **Critical gap:** The sector header has zero redundancy. A torn write or bit-flip in `seq_num` or sector state cannot be detected, leading to Issues B and E below.

#### Torn-Write Detection & Recovery

- Detection relies solely on the state byte being `0xFF` (`nvs.c:479–482`).
- On remount, the write offset is set to the first `0xFF`-state entry. Partially written entries whose state byte was already flipped are caught by CRC on the next read but are not proactively cleaned up — they persist until GC reclaims the sector.

#### Garbage Collection

- **Trigger:** Active sector overflows and no free sector is available (`nvs.c:371–415`).
- **Algorithm (`nvs.c:244–358`):**
  1. Select the `FULL` sector with the lowest sequence number.
  2. Iterate entries; copy only those with no newer version in higher-sequence sectors (`nvs.c:299`).
  3. If an entry cannot fit in the active sector during copy → abort GC, return `NO_SPACE`, leave source sector intact.
- **Interrupted GC:** No explicit in-progress state is committed to flash. If power is lost mid-GC, the source sector remains `FULL` and GC is retried on the next mount. Partial copies in the destination sector are not cleaned up, creating orphan entries.

#### Confirmed Failure Modes

All issues below are documented and reproduced by `tests/test_nvs_issues.c`:

| ID | Description | Impact |
|----|-------------|--------|
| **A** | `data_len > 128` in a committed entry → stack buffer overflow on `nvs_read` (no validation before use) | **Memory safety / crash** |
| **B1** | All sectors `FULL` on remount → no `ACTIVE` sector created → next write destroys old data | **Data loss** |
| **B2** | Single sector marked `FULL` with no successor sector | **Data loss** |
| **C** | Torn write leaves a `0xFF` state residue in flash; next write overwrites a live entry before CRC can protect it | **Silent data corruption** |
| **D** | GC cannot relocate a live entry → `NO_SPACE` returned even though space should be reclaimable | **Availability** |
| **E** | Torn sector header poisons `seq_counter` → sequence number wraps to 0 → read-order inversion returns stale data | **Wrong value returned** |
| **F** | `sector_count > 16` → overflow of fixed 16-element stack arrays `seqs[16]`, `valid[16]` (`nvs.c:149–150`) | **Crash** |

---

### 1.2 ESP-IDF NVS

#### Write Atomicity

Multi-phase writes with an explicit page-level state machine (`nvs_constants.h:15–18`, `nvs_page.cpp:97–124`):

- **Entry states:** `EMPTY (0x3) → WRITTEN (0x1) → ERASED (0x0)`
- **Page states:** `UNINITIALIZED → ACTIVE → FULL → FREEING → CORRUPT`

Each state transition is a discrete, independently atomic flash operation. Entries left in `EMPTY` during load are skipped (`nvs_page.cpp:42–65`). Pages stuck in `FREEING` (interrupted GC) are detected on mount and either completed or aborted safely (`nvs_pagemanager.cpp:96–128`).

#### CRC Scheme

Three levels of CRC32 (little-endian, `esp_rom_crc32_le`):

1. **Page header CRC** — over `seq_number` through state fields (`nvs_page.cpp:18–23`).
2. **Item CRC** — over key, datatype, namespace, and fixed-length data per entry.
3. **Variable-data CRC** — separate CRC32 over blob chunk payloads.

Pages with a failed header CRC are marked `CORRUPT` and isolated; the system continues operation with reduced capacity. Item CRC mismatches return an error to the caller — no silent pass-through.

#### Torn-Write Detection & Recovery

- `pagemanager.load()` detects duplicate items (old entry not erased before new write completed) and removes the stale copy automatically (`nvs_pagemanager.cpp:59–93`).
- Pages in `FREEING` state trigger GC resumption or rollback on next mount.
- No reliance on a single byte — recovery is driven by the page state machine.

#### Garbage Collection

- Source page transitions to `FREEING` *before* any data is copied (`nvs_pagemanager.cpp:139–150`).
- Only after all live entries are successfully copied is the source page erased.
- Power loss with the source page in `FREEING` → next mount detects and completes or reverts GC. No live data can be lost.

---

### 1.3 Robustness Comparison

| Attribute | Custom NVS | ESP-IDF NVS |
|-----------|-----------|-------------|
| Atomic commit mechanism | Single state-byte flip | Page state machine (multi-step) |
| Sector header protection | None | CRC32 |
| Item protection | CRC32 on payload | CRC32 on header + payload + chunks |
| Torn-write recovery | State byte = `0xFF` check | Duplicate removal + page state |
| GC interruption safety | Retry on remount (orphan entries possible) | `FREEING` state; safe completion/abort |
| Corrupt page handling | Not handled | Isolated as `CORRUPT`; system continues |
| Confirmed silent corruption bugs | 6+ (Issues A–F) | None documented |

---

## 2. Memory Footprint

### 2.1 Custom NVS

**Global RAM:**
- One `nvs_context_t` global (`nvs.c:10`): 3 × `uint32` + embedded `nvs_flash_driver_t` (4 function pointers + 2 ints) ≈ **40 bytes**.
- No per-key state; entries are found by sequential scan at runtime.

**Stack per operation:**
- `nvs_read()`: 145-byte CRC buffer + key/data temp buffers (up to 128 + 15 bytes) ≈ **280 bytes peak**.
- `nvs_write()`: 145-byte CRC buffer + entry construction buffer ≈ **300+ bytes**.
- `nvs_mount()`: Two 16-element fixed arrays (`seqs[16]`, `valid[16]`) + temp sector reads ≈ **200+ bytes**. **Hard limit: crashes above 16 sectors** (Issue F).

**Heap:** None. All allocation is static or on the stack.

**Code size (estimated):** ~3–4 KB. Five main entry points, sequential scan logic, no C++ overhead.

**Scalability:** Constant RAM regardless of key count or sector count — but crashes above 16 sectors.

---

### 2.2 ESP-IDF NVS

**Heap per partition:**
- One `Page` object per sector (`nvs_pagemanager.cpp:22`): ~100+ bytes per page (base address, seq number, entry counts, state, version, indices). Total: **~100 × sector_count bytes**.
- Item hash list (`nvs_item_hash_list.hpp`): dynamic blocks of ~128 bytes, 30 keys per block. Scales with unique key count.
- Namespace tracking: intrusive linked list, ~60+ bytes per namespace.
- **Minimum total:** Several KB for a typical 3–10 sector partition.

**Stack per operation:** Bounded; large buffers use heap. No fixed-size array overflow risk.

**Code size (estimated):** ~15–20 KB. C++ with intrusive lists, `std::find_if`, `std::any_of`, exception-less allocators, encryption support.

**Scalability:** Linear with sector count and namespace/key count. SPIRAM allocation supported (`CONFIG_NVS_ALLOCATE_CACHE_IN_SPIRAM`).

---

### 2.3 Footprint Comparison

| Metric | Custom NVS | ESP-IDF NVS |
|--------|-----------|-------------|
| Static RAM | ~40 bytes | N/A (heap-based) |
| Heap per partition | None | ~100 × sector_count + namespace overhead |
| Stack per operation | ~280–300 bytes; crashes > 16 sectors | Bounded; no hard sector limit |
| Code size (est.) | ~3–4 KB | ~15–20 KB |
| Heap dependency | None | Required |
| Per-key RAM overhead | None | ~4 bytes/key in hash list |

> **Verdict:** Custom NVS wins on footprint for severely constrained targets (< 4 KB RAM, no heap). ESP-IDF NVS is appropriate when RAM is available and scalability matters.

---

## 3. Portability

### 3.1 Custom NVS

**OS dependencies:** None. Pure C99, no RTOS primitives, no threading, no dynamic allocation.

**Flash HAL** (`nvs.h:59–75`): Three function pointers injected at mount:
```c
int (*read)(uint32_t addr, void *buf, size_t len);
int (*write)(uint32_t addr, const void *buf, size_t len);
int (*erase_sector)(uint32_t sector_index);
```

**Implicit assumptions:**
- NOR flash write semantics (AND-masking; only `1→0` bit flips).
- Sector size ≥ layout constraints (12-byte header + 8-byte entries).
- Write granularity compatible with single-byte state flips (must support byte-level writes).

**ESP32 specificity:** None in core `nvs.c`. `flash_mem.c` is a test-only RAM simulator.

**Thread safety:** Not implemented. Single-threaded use only.

**Porting effort:** ~1–2 hours to implement three flash ops for a new MCU.

**Known portability constraint:** `sector_count` is functionally limited to 16 due to fixed stack arrays.

---

### 3.2 ESP-IDF NVS

**OS dependencies:** Deep coupling to ESP-IDF:
- `esp_pthread` (mutex/threading)
- `heap_caps_malloc_prefer` (SPIRAM-aware allocation)
- `esp_partition.h` (partition table)
- `esp_log.h` (structured logging)
- `esp_rom_crc32_le` (ROM CRC function)
- `esp_efuse.h` (encryption key storage)

**Flash HAL:** Abstract `Partition` C++ virtual class (`nvs_partition.hpp`) with `read_raw`, `write`, `erase`, and optional `mmap` methods. Well-designed interface, but requires implementing a non-trivial C++ class.

**ESP32 specificity:** High. Partition table format, eFuse-based key storage, ROM CRC API, and heap capabilities are all ESP-IDF specific.

**Thread safety:** Full mutex protection per handle (`nvs_handle_locked.hpp`).

**Porting effort:** 1–2 days minimum — requires reimplementing the `Partition` interface, replacing threading primitives, and substituting logging and CRC dependencies.

---

### 3.3 Portability Comparison

| Attribute | Custom NVS | ESP-IDF NVS |
|-----------|-----------|-------------|
| OS / RTOS dependency | None | FreeRTOS + ESP-IDF primitives |
| Flash abstraction | 3 function pointers | C++ virtual `Partition` class |
| Thread safety | Not implemented | Full mutex protection |
| Heap dependency | None | Required |
| ESP32 specificity | None | High |
| Porting effort (new MCU) | ~1–2 hours | ~1–2 days |
| Max sectors (practical) | 16 | Unlimited (heap-backed) |

---

## 4. Testability

### 4.1 Custom NVS

**Test files:**
- `tests/main.c` — 27 functional test cases
- `tests/test_nvs_issues.c` — 8 dedicated bug-reproduction tests (Issues A–F + G, H)

**Infrastructure:**
- Native C; compiles and runs on host (Linux/Windows) without any MCU.
- Flash simulator: `flash_mem.c` backs sectors with heap-allocated RAM.
- Issue A test: wraps the flash driver to intercept oversized reads (`test_issue_A.c:44–55`).
- No external test framework dependencies.

**Scenarios covered:**
- Basic write/read/delete correctness
- Sector boundary and GC cycles
- Remount persistence across power-cycle simulation
- Torn writes (incomplete entries)
- CRC corruption detection
- Stress: 3200 consecutive writes with GC

**Scenarios NOT covered:**
- Thread safety (no synchronization code exists)
- Flash write/erase failures (no error injection)
- `sector_count > 16` (would crash before test runs)
- Multiple partitions
- Namespace isolation (feature not present)

**Test philosophy:** Issue tests document and reproduce confirmed bugs. A passing issue test means the bug is fixed; a failing one confirms the defect still exists. Tests are specifications.

---

### 4.2 ESP-IDF NVS

**Test files (host_test/nvs_host_test):**
- `test_nvs.cpp` — 150+ test cases
- `test_nvs_cxx_api.cpp` — C++ API surface tests
- `test_nvs_storage.cpp` — Storage layer tests
- `nvs_page_test.cpp` — Low-level page state machine tests
- `test_partition_manager.cpp` — Multi-partition tests
- `test_nvs_initialization.cpp` — Partition init scenarios
- `bdl_ramdisk.cpp` — Block device abstraction layer tests

**Infrastructure:**
- Catch2 framework.
- `NVSPartitionTestHelper` fixture abstracts partition I/O (`test_fixtures.cpp`).
- Host-compiled; runs in ESP-IDF CI/CD pipeline on Linux/macOS/Windows.
- Parameterized across multiple partition configurations (3-sector, 10-sector, etc.).

**Scenarios covered:**
- CRC32 validation on all items and page headers
- Page state machine transitions (all valid progressions)
- GC interruption and `FREEING` state recovery
- Duplicate entry detection (power-loss mid-write simulation)
- Namespace and type enforcement
- Multi-page variable-length blobs
- Handle lifecycle (open, read, write, commit, close)
- Mutex/thread-safety paths
- Encryption key management
- Partition table parsing

**Scenarios NOT covered:**
- Real hardware flash failures (write that fails mid-operation, erase that hangs)
- Physical power-loss (all simulation is software-level mocking)
- Endianness edge cases (little-endian assumed throughout)

---

### 4.3 Testability Comparison

| Attribute | Custom NVS | ESP-IDF NVS |
|-----------|-----------|-------------|
| Total test cases | ~35 | 150+ |
| Test framework | None (hand-rolled) | Catch2 |
| Host-native tests | Yes | Yes |
| Flash simulator | Yes (RAM-backed) | Yes (fixture-backed) |
| CI integration | Not configured | Yes (ESP-IDF CI) |
| GC interruption tested | Partially | Yes (FREEING state) |
| Power-loss scenarios | Yes (torn writes) | Yes (duplicate entry detection) |
| Thread-safety tests | No | Yes |
| Multi-partition tests | No | Yes |
| Bug-reproduction tests | Yes (8 confirmed bugs) | No documented regressions |

---

## 5. Summary Table

| Dimension | Custom NVS | ESP-IDF NVS |
|-----------|-----------|-------------|
| **Atomic commit** | Single state-byte flip | Page state machine (multi-step) |
| **Sector header protection** | None | CRC32 |
| **Silent corruption risk** | HIGH (6+ confirmed bugs) | LOW (comprehensive CRC coverage) |
| **GC interruption safety** | Retried on remount; orphans possible | `FREEING` state; safe completion |
| **Static RAM** | ~40 bytes | N/A |
| **Heap per partition** | None | ~100 × sector_count bytes |
| **Code size** | ~3–4 KB | ~15–20 KB |
| **Stack (worst case)** | Unbounded; crashes > 16 sectors | Bounded; dynamic allocation |
| **OS dependency** | None | FreeRTOS + ESP-IDF |
| **Flash HAL** | 3 function pointers | C++ virtual `Partition` class |
| **Thread safety** | Not implemented | Full mutex protection |
| **Porting effort** | ~1–2 hours | ~1–2 days |
| **Max sectors (practical)** | 16 | Unlimited |
| **Test coverage** | ~35 cases, bug-focused | 150+ cases, regression-focused |
| **CI integration** | No | Yes |

---

## 6. Open Audit Items

The following issues are confirmed by the test suite and require resolution before any production use of the custom NVS. Each item references the reproducing test.

| Priority | ID | Location | Description | Recommended Fix |
|----------|----|----------|-------------|-----------------|
| **Critical** | A | `nvs.c` read path | `data_len` from flash used without bounds check → stack overflow | Validate `data_len ≤ MAX_DATA_LEN` before buffer use |
| **Critical** | E | `nvs.c` mount | Torn sector header poisons `seq_counter` → stale value returned | Add CRC32 to sector header; reject header on mismatch |
| **Critical** | F | `nvs.c:149–150` | Fixed `seqs[16]`, `valid[16]` arrays crash above 16 sectors | Heap-allocate or enforce `sector_count ≤ 16` with a hard assert |
| **High** | B1/B2 | `nvs.c` mount | All-FULL remount creates no ACTIVE sector | Add sector state recovery path in `nvs_mount` |
| **High** | C | `nvs.c` write | Torn-write residue causes next write to overwrite live entry | Validate destination range is erased before writing; add sector header CRC |
| **High** | D | `nvs.c` GC | GC aborts with `NO_SPACE` when live entry cannot fit, leaving reclaimable space stranded | Retry GC with sector compaction or return a more specific error |
| **Medium** | — | `nvs.c` | No thread safety | Add a critical-section wrapper (or document single-threaded constraint explicitly) |
| **Medium** | — | `nvs.c` | No validation of `flash_driver` fields at each operation | Guard `NULL` function pointer before each call |
| **Low** | — | `nvs.c:149` | `sector_count` stored as `uint8`; max 255 sectors but array limit is 16 | Enforce limit with `static_assert` or runtime assert at mount |
