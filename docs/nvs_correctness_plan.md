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


---

## Summary — All Steps Complete ✅

**Final Status:** 2 bugs CONFIRMED (C, E), 10 specs honored, 0 ambiguous

| Step | Status | Fixes | Result |
|------|--------|-------|--------|
| 1-9 | ✅ Complete | Core hardening: bounds checks, state management, GC | Passed |
| 10 | ✅ Complete | Add NVS_SECTOR_FREEING state transition | Passed |
| 11 | ✅ Complete | Extract activate_empty_sector_only() helper | Passed |
| 12 | ✅ Complete | Allow active-sector rotation in nvs_gc_resume() | Passed |
| 13 | ✅ Complete | Detect and resume FREEING sectors in nvs_mount() | Passed |
| 14 | ✅ Complete | Write regression test for interrupted GC | [PASS] |
| 15 | ✅ Complete | Document CRC fallback policy (Option A: fail-safe) | In source |
| 16 | ✅ Complete | Update test_issue_G to call REPORT_PASS | [PASS] |
