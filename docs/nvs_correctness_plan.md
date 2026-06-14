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
| 10 | Add `NVS_SECTOR_FREEING` and commit before GC copy | `nvs.h` + `nvs.c` | Manual interrupted-GC test passes |
| 11 | Pre-condition: `activate_empty_sector_only()` helper | `nvs.c` | All existing tests still pass |
| 12 | Issue D: GC sector-rotation instead of abort | `nvs.c` | `test_issue_D_gc_cannot_relocate` → `[PASS]` |
| 13 | Mount resumes interrupted GC (`FREEING` detection) | `nvs.c` | See Step 14 |
| 14 | Interrupted-GC regression test | `tests/test_nvs_issues.c` | New test → `[PASS]` |
| 15 | Issue G: CRC fallback policy chosen and documented | `nvs.h` | Comment in source |
| 16 | Issue G: test updated for chosen policy | `tests/test_nvs_issues.c` | `test_issue_G_no_crc_fallback` → `[PASS]` |
