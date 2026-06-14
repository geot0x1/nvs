# NVS Correctness & Reliability Plan

**Goal:** Eliminate every confirmed defect in the NVS module and bring its correctness
and reliability to production grade.
**Strategy:** Each step is atomic — one logical change, one verifiable check. The
codebase is in a working state after every step. Steps are ordered simplest-first;
later steps are larger, higher-impact, or depend on earlier ones.

References:
- `docs/nvs_comparison_report.md` — full gap analysis vs. ESP-IDF NVS
- `tests/test_nvs_issues.c` — executable specifications for each confirmed bug
- `tests/test_issue_A.c`, `tests/test_issue_F.c` — crash-type issues (child processes)

---

## Confirmed Bug Inventory

Results from the latest test run used to drive this plan:

| ID | Status | Description |
|----|--------|-------------|
| A | **CONFIRMED** | `data_len` from flash used without bounds check → stack overflow in `nvs_read` |
| B1 | **CONFIRMED** | All sectors `FULL` → remount + write destroys all committed data |
| B2 | **CONFIRMED** | Single sector marked `FULL` with no successor → remount reformats it |
| C | **CONFIRMED** | Torn-write residue (state = `0xFF`) causes next committed write to be corrupted |
| D | **CONFIRMED** | GC returns `NO_SPACE` while reclaimable sectors exist (live entry cannot fit) |
| E | **CONFIRMED** | Torn sector header poisons `seq_counter` → read-order inversion, stale value returned |
| F | **CONFIRMED** | `sector_count > 16` → stack overflow in fixed 16-element arrays |
| G | **AMBIGUOUS** | No fallback to older intact copy when newest copy fails CRC (design policy) |
| H | **PASSING** | Undersized read buffer returns `NVS_ERR_INVALID_ARG`, `out_len` untouched |

---

## Steps

---

### Step 3 — Bounds-check `key_len` and `data_len` in the `nvs_mount()` scan

**Fixes:** Corrupt-entry crash in mount scan; pre-condition for Step 8

**Description:** `entry_total_size(kl, dl)` is called in the mount scan with values read
directly from flash. Corrupt values make `esz` arbitrarily large, causing `write_offset`
to advance past the end of the sector or wrap around, then either crash or silently skip
valid entries.

**File:** `nvs/nvs.c` — `nvs_mount()`, entry-scan loop (~line 477)

**Action:** After `read_entry_hdr(...)`, add before calling `entry_total_size`:
```c
if (kl == 0 || kl > NVS_MAX_KEY_LEN || dl > NVS_MAX_DATA_LEN)
{
    break; /* treat corrupt sizes as end of written area */
}
```

**Test:** New test in `tests/test_nvs_issues.c` — write one valid entry then plant a
corrupt entry (`key_len = 0xFF`, `data_len = 0xFF`). After mount, `write_offset` must
equal the offset of the corrupt entry. No crash, no wrap-around, no skip of the valid entry.

---

### Step 3 — Replace `16` array literals with `NVS_MAX_SECTORS` and enforce at mount

**Fixes:** Issue F

**Description:** `get_sectors_by_seq_desc()` declares `seqs[16]` and `valid[16]`.
`nvs_read()` declares `indices[16]`. When `sector_count > 16` these arrays overflow.
There is no check that rejects an out-of-range `sector_count` before the overflow occurs.

**File:** `nvs/nvs.c` and `nvs/nvs.h`

**Action:** Add the constant to `nvs.h` alongside the other size limits:
```c
#define NVS_MAX_SECTORS     (16U)
```

Then in `nvs/nvs.c`, replace all three literal `16` array sizes with `NVS_MAX_SECTORS`. In
`nvs_mount()`, add after the existing null checks:
```c
if (driver->sector_count > NVS_MAX_SECTORS)
{
    return NVS_ERR_INVALID_ARG;
}
```

**Test:** `tests/test_issue_F.c` must exit with status 0 (clean rejection). The test
calls `nvs_mount()` with `sector_count = 255` and expects `NVS_ERR_INVALID_ARG`.

---

### Step 4 — Write the sector header CRC in `write_sector_hdr()`

**Fixes:** Ensures every newly written header is CRC-protected

**Description:** New sector headers must carry a CRC so that the verifier added in Step 5
can detect torn writes. This is the write side of the header integrity pair.

**File:** `nvs/nvs.c` — `write_sector_hdr()` (~line 64)

**Action:** After writing the three existing fields, compute CRC32 over the 12-byte body
and write it at offset `+12`:
```c
static void write_sector_hdr(uint32_t base, uint32_t seq, uint32_t state)
{
    uint32_t magic = NVS_MAGIC_WORD;
    DRV_WRITE(base + 0,  &magic, sizeof(magic));
    DRV_WRITE(base + 4,  &seq,   sizeof(seq));
    DRV_WRITE(base + 8,  &state, sizeof(state));

    uint8_t body[12];
    memcpy(body + 0, &magic, 4);
    memcpy(body + 4, &seq,   4);
    memcpy(body + 8, &state, 4);
    uint32_t crc = crc32_gen(body, 12);
    DRV_WRITE(base + 12, &crc, sizeof(crc));
}
```

**Test:** New assertion — format a sector, read back all 16 header bytes, recompute
CRC32 over bytes 0–11, assert it equals the value at bytes 12–15.

---

### Step 5 — Verify the sector header CRC in `read_sector_hdr()`

**Fixes:** Issue E (seq_counter poisoning), Issue B partial (state corruption). Depends on Step 4

**Description:** `read_sector_hdr()` currently returns true on magic match alone. A torn
write that landed `magic` but left `seq_num` or `state` at `0xFFFFFFFF` is silently
accepted, poisoning `seq_counter` and corrupting mount state.

**File:** `nvs/nvs.c` — `read_sector_hdr()` (~line 52)

**Action:** Read all 16 bytes into a single buffer. After the magic check, read the stored
CRC from bytes 12–15, compute `crc32_gen(buf, 12)`, and return `0` if they differ:
```c
static int read_sector_hdr(uint32_t base,
                           uint32_t *magic,
                           uint32_t *seq,
                           uint32_t *state)
{
    uint8_t buf[NVS_SECTOR_HDR_SIZE];
    DRV_READ(base, buf, NVS_SECTOR_HDR_SIZE);

    memcpy(magic, buf + 0, 4);
    memcpy(seq,   buf + 4, 4);
    memcpy(state, buf + 8, 4);

    if (*magic != NVS_MAGIC_WORD)
    {
        return 0;
    }

    uint32_t stored_crc;
    memcpy(&stored_crc, buf + 12, 4);
    uint32_t calc_crc = crc32_gen(buf, 12);

    return (calc_crc == stored_crc) ? 1 : 0;
}
```

**Test:** New test — write key `"k"`, corrupt byte 5 of sector 0's header (inside
`seq_num`), call `nvs_mount()`. Assert the corrupt sector is not used as ACTIVE and
`nvs_read("k")` returns either `NVS_OK` or `NVS_ERR_NOT_FOUND` (no crash, no stale value).

---

### Step 6 — Verify Issue E is closed

**Description:** After Steps 7 and 8, a torn zombie sector header must no longer accept a
`0xFFFFFFFF` seq_num as valid, so `seq_counter` cannot be poisoned and read-order
inversion cannot occur.

**File:** `tests/test_nvs_issues.c` — `test_issue_E_seq_poisoning()`

**Action:** No code change. Run the test and confirm both assertions report `[PASS]`.

**Test:** `seq_counter` must not be poisoned (newly activated sector must not get `seq = 0`).
`nvs_read("dup")` must return the newest value `999`, not the stale value `111`.

---

### Step 7 — Detect all-FULL flash in `nvs_mount()` and run GC before formatting

**Fixes:** Issues B1, B2

**Description:** When no ACTIVE sector is found (power loss after the last sector was
marked FULL but before a new one was activated), the current code formats sector 0
immediately, destroying all committed data. This fix depends on `read_sector_hdr()`
reliably rejecting torn headers (Steps 4–5).

**File:** `nvs/nvs.c` — `nvs_mount()`, the `if (best_idx < 0)` branch (~line 459)

**Action:** Before the format path, scan for any FULL sectors. If found, the flash is not
blank — call `activate_next_sector()` (which runs GC) instead of formatting:
```c
if (best_idx < 0)
{
    int has_full = 0;
    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t magic, seq, state;
        if (read_sector_hdr(sector_addr(i), &magic, &seq, &state)
            && state == NVS_SECTOR_FULL)
        {
            has_full = 1;
            break;
        }
    }

    if (has_full)
    {
        return activate_next_sector();
    }

    /* Truly blank flash — first-time format. */
    g_nvs.seq_counter = 1;
    write_sector_hdr(sector_addr(0), 1, NVS_SECTOR_ACTIVE);
    g_nvs.active_sector_addr = sector_addr(0);
    g_nvs.write_offset       = NVS_SECTOR_HDR_SIZE;
    return NVS_OK;
}
```

**Test:** `test_issue_B1_all_full_remount` and `test_issue_B2_full_no_active` in
`tests/test_nvs_issues.c` must both report `[PASS]`.

---

### Step 8 — Invalidate torn-write slots during `nvs_mount()` scan

**Fixes:** Issue C

**Description:** On encountering `NVS_ENTRY_WRITING`, mount currently does a plain
`break`, leaving `write_offset` at the torn slot. The next `nvs_write` AND's its new data
into the partially-cleared bits of the torn slot — the entry passes CRC before the write
but fails on the next read. Depends on the `kl`/`dl` bounds check from Step 3 and Step 2.

**File:** `nvs/nvs.c` — `nvs_mount()`, entry-scan loop (~line 479)

**Action:** Replace the `break` with a validate-and-invalidate path:
```c
if (st == NVS_ENTRY_WRITING)
{
    if (kl == 0 || kl > NVS_MAX_KEY_LEN || dl > NVS_MAX_DATA_LEN)
    {
        break; /* cannot determine extent — rest of sector unusable */
    }

    /* Plausible sizes: zero the state byte to prevent AND-corruption. */
    uint8_t del = NVS_ENTRY_DELETED;
    DRV_WRITE(g_nvs.active_sector_addr + off, &del, 1);

    off += entry_total_size(kl, dl);
    continue; /* keep scanning; multiple torn slots are possible */
}
```

**Test:** `test_issue_C_torn_residue` in `tests/test_nvs_issues.c` must report `[PASS]`.
The test writes `"vict"` (111), plants a torn slot, remounts, writes `"vict"` (222),
then reads it back — must return `NVS_OK` and value `222`.

---

### Step 9 — Extract `nvs_gc_resume()` helper from `nvs_gc()`

**Fixes:** Structural pre-condition for Steps 11–14

**Description:** The entry-copy loop inside `nvs_gc()` must be callable from two places:
`nvs_gc()` itself (normal path) and `nvs_mount()` (interrupted-GC recovery, Step 13).
Extracting it now keeps both call sites DRY.

**File:** `nvs/nvs.c`

**Action:** Move the entry-copy-and-erase body from `nvs_gc()` into:
```c
static nvs_err_t nvs_gc_resume(uint32_t target_base, uint32_t target_seq);
```
Have `nvs_gc()` call `nvs_gc_resume()` after selecting the target sector. All entry-copy,
size-check, and erase logic moves into the helper.

**Test:** All existing passing tests continue to pass unchanged (pure refactor).

---

### Step 10 — Add `NVS_SECTOR_FREEING` state constant and transition to it before GC copy

**Fixes:** Power-loss safety during GC

**Description:** Depends on `NVS_SECTOR_FREEING` constant added in Step 1.
A `FREEING` marker written before the copy loop lets `nvs_mount()` detect and resume
interrupted GC. If power is lost after some entries have been copied to the destination
but before the source sector is erased, the source sector stays `FULL` forever. On
remount, GC is retried blindly with no knowledge of which entries were already copied,
potentially creating duplicate `VALID` entries.

**File:** `nvs/nvs.h` and `nvs/nvs.c`

**Action:** First, add the constant to `nvs.h` after `NVS_SECTOR_FULL`:
```c
/** Source sector being reclaimed by GC. Bit-flip reachable from FULL. */
#define NVS_SECTOR_FREEING  (0xFF000000U)
```

Then in `nvs/nvs.c` — `nvs_gc_resume()` (extracted in Step 10), at the very start before the copy loop:
```c
set_sector_state(target_base, NVS_SECTOR_FREEING);
```

**Test:** Manually set a sector's state to `FREEING`, partially copy one entry to the
active sector, then call `nvs_mount()`. All keys written before the simulated power loss
must be readable. The `FREEING` sector must be erased after mount.

---

### Step 11 — Extract `activate_empty_sector_only()` helper

**Fixes:** Structural pre-condition for Step 13

**Description:** Depends on Step 9. `nvs_gc_resume()` needs to activate a new empty sector when the active
sector fills mid-GC, but it must not call `nvs_gc()` (which would cause infinite
recursion). Extract the scan-and-format path from `activate_next_sector()` as a
standalone, no-GC helper.

**File:** `nvs/nvs.c`

**Action:** Create:
```c
static nvs_err_t activate_empty_sector_only(void);
```
It scans for an erased sector (first word `== 0xFFFFFFFF`) and formats it ACTIVE. It
must NOT call `nvs_gc()`. Have `activate_next_sector()` call it for its first-pass scan,
keeping the existing GC fallback in `activate_next_sector()` for the normal write path.

**Test:** All existing passing tests continue to pass unchanged.

---

### Step 12 — Allow active-sector rotation in `nvs_gc_resume()` instead of aborting

**Fixes:** Issue D

**Description:** Depends on Step 11. When a live entry cannot fit in the remaining space of the current active
sector, `nvs_gc_resume()` aborts and returns `NVS_ERR_NO_SPACE`, leaving the source
sector in `FREEING` state permanently. Space is genuinely reclaimable but GC gives up.

**File:** `nvs/nvs.c` — `nvs_gc_resume()`, inside the capacity-check block

**Action:** Instead of aborting, mark the active sector `FULL` and activate the next
empty sector using the helper from Step 12:
```c
if (g_nvs.write_offset + esz > SECTOR_SIZE)
{
    set_sector_state(g_nvs.active_sector_addr, NVS_SECTOR_FULL);
    nvs_err_t rc = activate_empty_sector_only();
    if (rc != NVS_OK)
    {
        return NVS_ERR_NO_SPACE; /* genuinely out of space */
    }
}
```

**Test:** `test_issue_D_gc_cannot_relocate` in `tests/test_nvs_issues.c` must report
`[PASS]`. The churn test must run 4000 iterations without hitting `NVS_ERR_NO_SPACE`,
and `"LIVE"` must remain readable throughout.

---

### Step 13 — Detect and resume `FREEING` sectors in `nvs_mount()`

**Fixes:** Safe recovery from interrupted GC; closes Step 11 verification

**Description:** Depends on Step 9 and Step 10. `nvs_mount()` currently ignores `FREEING` state. A sector stuck in
`FREEING` is neither ACTIVE nor FULL, so it is skipped. The space it occupies is
permanently lost until the next erase cycle.

**File:** `nvs/nvs.c` — `nvs_mount()`, after `write_offset` setup

**Action:** Add a second pass after the main sector scan:
```c
for (uint8_t i = 0; i < SECTOR_COUNT; i++)
{
    uint32_t magic, seq, state;
    if (read_sector_hdr(sector_addr(i), &magic, &seq, &state)
        && state == NVS_SECTOR_FREEING)
    {
        nvs_gc_resume(sector_addr(i), seq);
        break; /* at most one FREEING sector can exist at a time */
    }
}
```

**Test:** Step 15 regression test must pass.

---

### Step 14 — Write regression test: interrupted GC completes safely on remount

**Fixes:** Verifies Steps 11 + 14 together

**Description:** Depends on Steps 9, 10, 12, and 13. An automated test that exercises the exact interrupted-GC scenario:
data is partially relocated, power is lost, and the next mount must complete the GC
with no data loss.

**File:** `tests/test_nvs_issues.c` — new function `test_interrupted_gc_resume()`

**Action:** Test scenario:
1. Write keys `"A"`, `"B"`, `"C"` to sector 0 until it becomes `FULL`.
2. Write key `"D"` to sector 1 (now `ACTIVE`).
3. Simulate power loss mid-GC:
   - Set sector 0's state to `FREEING` via `flash_write`.
   - Copy only key `"A"` to sector 1 via `th_craft_valid_entry`.
   - Do NOT erase sector 0.
4. Call `nvs_mount()`.
5. Assert all four keys are readable with correct values.
6. Assert sector 0's first word is `0xFFFFFFFF` (fully erased — GC completed).

Wire the new function into `main()`.

**Test:** `test_interrupted_gc_resume` reports `[PASS]` with zero assertion failures.

---

### Step 15 — Document the CRC fallback policy in `nvs.h`

**Fixes:** Issue G — policy decision

**Description:** Depends on Steps 4 and 5. Issue G is marked **AMBIGUOUS** because the current behaviour (return
`NVS_ERR_CRC` on the newest copy, never fall back) matches the documented read
specification. However, the policy has a real cost: if the newest copy is corrupt but an
older intact copy exists, the caller cannot read the value at all. The policy must be
explicitly chosen and recorded.

**File:** `nvs/nvs.h` — above the `nvs_read()` declaration

**Action:** Choose one option and add the corresponding doc-comment:

**Option A — Fail-safe (current behaviour, no code change):**
```c
/**
 * CRC policy: if the newest copy of a key fails CRC verification,
 * NVS_ERR_CRC is returned.  No fallback to older copies is attempted.
 * Rationale: returning stale data silently is considered more dangerous
 * than surfacing the corruption to the caller.
 */
```

**Option B — Best-effort fallback:**
Walk copies in descending `seq_num` order. Return the first copy that passes CRC.
Only return `NVS_ERR_CRC` when no copy in any sector passes. In `nvs_read()`, instead
of returning `NVS_ERR_CRC` immediately, record the failure, continue scanning
lower-seq sectors, and only return the error if no intact copy is found.

**Test:** No automated test. Decision recorded in source.

---

### Step 16 — Update `test_issue_G_no_crc_fallback()` for chosen policy

**Description:** The test currently calls `REPORT_AMB`. It must be updated to call
`REPORT_PASS` for whichever policy was chosen in Step 18, so the test suite has a clean
all-pass result.

**File:** `tests/test_nvs_issues.c` — `test_issue_G_no_crc_fallback()`

**Action:**
- If **Option A**: change the `REPORT_AMB` on `NVS_ERR_CRC` to `REPORT_PASS`.
- If **Option B**: implement the CRC fallback walk in `nvs_read()` and update the test
  to call `REPORT_PASS` when `rc == NVS_OK && rb == 0x11223344` (the intact older copy).

**Test:** `test_issue_G_no_crc_fallback` reports `[PASS]`.

---

## Summary Checklist

| Step | Fixes | File | Test |
|------|-------|------|------|
| 3  | Issue F: `sector_count > 16` crash; add `NVS_MAX_SECTORS` | `nvs.h` + `nvs.c` | `test_issue_F.c` exits 0 |
| 4  | Header CRC written on format | `nvs.c` | CRC round-trip assertion passes |
| 5  | Header CRC verified on read | `nvs.c` | Corrupt-header-ignored test passes |
| 6  | Issue E: seq_counter poisoning | — (test only) | `test_issue_E_seq_poisoning` → `[PASS]` |
| 7  | Issues B1, B2: all-FULL data loss | `nvs.c` | `test_issue_B1` and `test_issue_B2` → `[PASS]` |
| 8  | Issue C: torn slot corrupts next write | `nvs.c` | `test_issue_C_torn_residue` → `[PASS]` |
| 9  | Pre-condition: `nvs_gc_resume()` helper extracted | `nvs.c` | All existing tests still pass |
| 10 | Add `NVS_SECTOR_FREEING` and commit before GC copy | `nvs.h` + `nvs.c` | Manual interrupted-GC test passes |
| 11 | Pre-condition: `activate_empty_sector_only()` helper | `nvs.c` | All existing tests still pass |
| 12 | Issue D: GC sector-rotation instead of abort | `nvs.c` | `test_issue_D_gc_cannot_relocate` → `[PASS]` |
| 13 | Mount resumes interrupted GC (`FREEING` detection) | `nvs.c` | See Step 14 |
| 14 | Interrupted-GC regression test | `tests/test_nvs_issues.c` | New test → `[PASS]` |
| 15 | Issue G: CRC fallback policy chosen and documented | `nvs.h` | Comment in source |
| 16 | Issue G: test updated for chosen policy | `tests/test_nvs_issues.c` | `test_issue_G_no_crc_fallback` → `[PASS]` |
