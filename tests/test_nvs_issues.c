/*
 * Independent issue-verification suite for the NVS module.
 *
 * Each test encodes the SPECIFICATION (documented contract) and prints:
 *   [PASS]  implementation honors the spec (no bug here)
 *   [FAIL]  implementation VIOLATES the spec (bug CONFIRMED)
 *   [AMBIG] reproduces, but spec is ambiguous / may be deliberate policy
 *
 * Crash-type issues A and F live in their own executables and are launched
 * here as child processes so a crash is recorded as a confirmation instead
 * of taking down this harness.
 *
 * Links against the UNMODIFIED nvs.c / flash_mem.c / crc32.c.
 */

#include "test_helpers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_bug = 0;   /* spec violations confirmed */
static int g_ok  = 0;   /* spec honored             */
static int g_amb = 0;   /* ambiguous reproductions  */

#define REPORT_FAIL(msg) do { printf("  [FAIL] %s  <-- bug CONFIRMED\n", (msg)); g_bug++; } while (0)
#define REPORT_PASS(msg) do { printf("  [PASS] %s\n", (msg)); g_ok++; } while (0)
#define REPORT_AMB(msg)  do { printf("  [AMBIG] %s\n", (msg)); g_amb++; } while (0)

/*===========================================================================
 *  Issue B — nvs_mount destroys committed data when no ACTIVE sector exists
 *===========================================================================*/

static void test_issue_B1_all_full_remount(void)
{
    printf("\n--- Issue B1: all sectors FULL -> remount -> write destroys data ---\n");
    flash_full_erase();
    th_mount();

    /* Fill every sector with unique live keys.  The final overflow write
     * marks the last sector FULL and then fails NO_SPACE, leaving NO active
     * sector on flash (exactly the power-loss-equivalent state). */
    char key[8];
    uint32_t val;
    int total = (int)(FLASH_SECTOR_COUNT * ENTRIES_PER_SECTOR);
    for (int i = 0; i < total; i++)
    {
        th_make_key(key, i);
        val = (uint32_t)i;
        nvs_write(key, &val, sizeof(val));
    }

    /* One more write forces the last (still ACTIVE) sector to FULL and then
     * fails NO_SPACE, leaving ZERO active sectors on flash. */
    val = 0xDEAD;
    nvs_write("OVR", &val, sizeof(val));

    /* Sanity: A000 is committed and readable before the "reboot". */
    uint32_t rb = 0; uint8_t ol = 0;
    nvs_err_t rc = nvs_read("A000", &rb, sizeof(rb), &ol);
    int pre_ok = (rc == NVS_OK && rb == 0);

    /* Simulated reboot. */
    th_mount();

    /* One innocent write of a brand-new key. */
    val = 1;
    nvs_write("NEWKEY", &val, sizeof(val));

    /* Spec: previously committed keys must survive a remount untouched. */
    rb = 0;
    rc = nvs_read("A000", &rb, sizeof(rb), &ol);
    int survived = (rc == NVS_OK && rb == 0);

    if (!pre_ok)
    {
        printf("  [INFO] pre-reboot A000 not readable (rc=%d) - setup issue\n", rc);
    }
    if (survived)
    {
        REPORT_PASS("committed key 'A000' survives all-FULL remount + write");
    }
    else
    {
        printf("  observed: post-remount read A000 rc=%d val=%u (expected OK,0)\n", rc, rb);
        REPORT_FAIL("committed key 'A000' lost/corrupted after all-FULL remount + write");
    }
}

static void test_issue_B2_full_no_active(void)
{
    printf("\n--- Issue B2: single sector marked FULL w/o successor -> data loss ---\n");
    flash_full_erase();
    th_mount();

    uint32_t val = 0xABCD;
    nvs_write("keep", &val, sizeof(val));

    /* Power loss: sector 0 marked FULL, no successor activated. */
    uint32_t full = NVS_SECTOR_FULL;
    flash_write(8, &full, sizeof(full));

    th_mount(); /* remount: no ACTIVE sector found */

    uint32_t v2 = 0x1111;
    nvs_write("newk", &v2, sizeof(v2)); /* core says OK, but writes over 'keep' */

    uint32_t rb = 0; uint8_t ol = 0;
    nvs_err_t rk = nvs_read("keep", &rb, sizeof(rb), &ol);
    int keep_ok = (rk == NVS_OK && rb == 0xABCD);

    uint32_t rb2 = 0;
    nvs_err_t rn = nvs_read("newk", &rb2, sizeof(rb2), &ol);
    int newk_ok = (rn == NVS_OK && rb2 == 0x1111);

    printf("  observed: read 'keep' rc=%d val=0x%X ; read 'newk' rc=%d val=0x%X\n",
           rk, rb, rn, rb2);

    if (keep_ok && newk_ok)
    {
        REPORT_PASS("both 'keep' and 'newk' readable after FULL-no-successor remount");
    }
    else
    {
        REPORT_FAIL("committed data lost/corrupted (mount reformatted a FULL sector with live data)");
    }
}

/*===========================================================================
 *  Issue C — torn (uncommitted) residue corrupts the next committed write
 *===========================================================================*/

static void test_issue_C_torn_residue(void)
{
    printf("\n--- Issue C: torn residue corrupts a subsequent NVS_OK write ---\n");
    flash_full_erase();
    th_mount();

    uint32_t v1 = 111;
    nvs_write("vict", &v1, sizeof(v1)); /* 16-byte entry at offset 12 */

    /* Power loss between body-write and state-commit: body fully programmed,
     * state byte still 0xFF (Writing).  This is the exact intermediate state
     * nvs_write leaves behind on a crash. */
    uint8_t kl = 7, dl = 8;
    uint8_t torn[8 + 7 + 8 + 1]; /* align4(8+7+8)=24 */
    memset(torn, 0xFF, sizeof(torn));
    torn[0] = 0xFF; torn[1] = kl; torn[2] = dl; torn[3] = 0xFF;
    uint8_t crcbuf[2 + 7 + 8];
    crcbuf[0] = kl; crcbuf[1] = dl;
    memcpy(&crcbuf[2], "tornkey", 7);
    memset(&crcbuf[9], 0x55, 8);
    uint32_t c = crc32_gen(crcbuf, sizeof(crcbuf));
    torn[4] = (uint8_t)c; torn[5] = (uint8_t)(c >> 8);
    torn[6] = (uint8_t)(c >> 16); torn[7] = (uint8_t)(c >> 24);
    memcpy(&torn[8], "tornkey", 7);
    memset(&torn[15], 0x55, 8);
    flash_write(12 + 16, torn, 24);

    th_mount(); /* mount stops at the 0xFF state byte -> write_offset = 28 */

    /* A new committed write for 'vict' lands on top of the torn residue. */
    uint32_t v2 = 222;
    nvs_err_t wr = nvs_write("vict", &v2, sizeof(v2));

    uint32_t rb = 0; uint8_t ol = 0;
    nvs_err_t rr = nvs_read("vict", &rb, sizeof(rb), &ol);

    printf("  observed: nvs_write rc=%d ; nvs_read rc=%d val=%u (expected OK,222)\n",
           wr, rr, rb);

    /* Spec: a write that returns NVS_OK must be subsequently readable. */
    if (wr == NVS_OK && !(rr == NVS_OK && rb == 222))
    {
        REPORT_FAIL("nvs_write returned NVS_OK but value is unreadable/corrupt (CRC/NOT_FOUND)");
    }
    else if (wr == NVS_OK && rr == NVS_OK && rb == 222)
    {
        REPORT_PASS("value readable after NVS_OK write over torn residue");
    }
    else
    {
        printf("  [INFO] write itself did not return NVS_OK (rc=%d)\n", wr);
        REPORT_AMB("write over torn residue did not return NVS_OK");
    }
}

/*===========================================================================
 *  Issue D — GC cannot relocate a live entry from the oldest FULL sector
 *===========================================================================*/

static void test_issue_D_gc_cannot_relocate(void)
{
    printf("\n--- Issue D: GC fails to reclaim mostly-dead sectors (NO_SPACE) ---\n");
    flash_full_erase();
    th_mount();

    /* One long-lived key in sector 0. */
    uint32_t val = 42;
    nvs_write("LIVE", &val, sizeof(val));

    /* Churn a single key: every overwrite supersedes the previous, so all
     * but the latest CHURN copy is dead.  This eventually fills all three
     * sectors and forces GC. */
    nvs_err_t rc = NVS_OK;
    int first_fail_iter = -1;
    for (int i = 0; i < 4000; i++)
    {
        val = (uint32_t)i;
        rc = nvs_write("CHURN", &val, sizeof(val));
        if (rc != NVS_OK)
        {
            first_fail_iter = i;
            break;
        }
    }

    /* At the failure point: sectors 0+1 are ~100% dead (sector 0 keeps only
     * LIVE; sector 1 holds only superseded CHURN), so a correct GC should
     * reclaim space and the write should succeed. */
    uint32_t rb = 0; uint8_t ol = 0;
    nvs_err_t lr = nvs_read("LIVE", &rb, sizeof(rb), &ol);

    printf("  observed: first failing CHURN write rc=%d at iter %d ; read LIVE rc=%d val=%u\n",
           rc, first_fail_iter, lr, rb);

    if (first_fail_iter < 0)
    {
        REPORT_PASS("churn never hit NO_SPACE - GC reclaimed dead space");
    }
    else if (rc == NVS_ERR_NO_SPACE)
    {
        REPORT_FAIL("write returned NO_SPACE while 2 sectors are reclaimable (GC could not relocate live 'LIVE')");
    }
    else
    {
        printf("  [INFO] unexpected failure code rc=%d\n", rc);
        REPORT_AMB("churn failed with a non-NO_SPACE error");
    }
}

/*===========================================================================
 *  Issue E — torn sector header -> zombie sector + seq_counter poisoning
 *===========================================================================*/

static void test_issue_E_seq_poisoning(void)
{
    printf("\n--- Issue E: torn sector header poisons seq_counter (wrap to 0) ---\n");
    flash_full_erase();
    th_mount(); /* sector 0 active, seq 1 */

    uint32_t val = 5;
    nvs_write("k", &val, sizeof(val));

    /* Power loss inside write_sector_hdr on sector 1: only magic landed,
     * seq + state remain 0xFFFFFFFF. */
    uint32_t magic = NVS_MAGIC_WORD;
    flash_write(FLASH_SECTOR_SIZE + 0, &magic, sizeof(magic));

    th_mount(); /* reads seq=0xFFFFFFFF from sector 1 -> seq_counter poisoned */

    /* 'k' should still be readable. */
    uint32_t rb = 0; uint8_t ol = 0;
    nvs_read("k", &rb, sizeof(rb), &ol);

    /* Fill the active sector (sector 0) to force a fresh activation. */
    char key[8];
    for (int i = 0; i < (int)ENTRIES_PER_SECTOR; i++)
    {
        th_make_key(key, i);
        val = (uint32_t)i;
        nvs_write(key, &val, sizeof(val));
    }
    val = 77;
    nvs_write("next", &val, sizeof(val)); /* triggers activate_next_sector */

    /* Sector 1 is the zombie (first word == magic, never reusable). */
    uint32_t s1_word = 0;
    flash_read(FLASH_SECTOR_SIZE + 0, &s1_word, sizeof(s1_word));
    int zombie = (s1_word == NVS_MAGIC_WORD);

    /* Sector 2 was just activated; its seq wrapped 0xFFFFFFFF -> 0. */
    uint32_t s2_magic = 0, s2_seq = 0xDEAD, s2_state = 0;
    flash_read(2 * FLASH_SECTOR_SIZE + 0, &s2_magic, sizeof(s2_magic));
    flash_read(2 * FLASH_SECTOR_SIZE + 4, &s2_seq,   sizeof(s2_seq));
    flash_read(2 * FLASH_SECTOR_SIZE + 8, &s2_state, sizeof(s2_state));

    printf("  observed: sector1 first-word=0x%08X (zombie=%d) ; "
           "sector2 magic=0x%08X seq=%u state=0x%08X\n",
           s1_word, zombie, s2_magic, s2_seq, s2_state);

    int poisoned = (s2_magic == NVS_MAGIC_WORD &&
                    s2_state == NVS_SECTOR_ACTIVE &&
                    s2_seq == 0);

    if (poisoned)
    {
        REPORT_FAIL("seq_counter poisoned: newly activated sector got seq 0 (wrapped) -> read-order inversion risk");
    }
    else
    {
        REPORT_PASS("newly activated sector kept a monotonic (non-zero) sequence number");
    }

    /* Consequence demo: a newer copy living in a seq-0 sector is shadowed by
     * an older copy in a higher-seq sector (read returns the STALE value). */
    flash_full_erase();
    th_craft_sector_hdr(0 * FLASH_SECTOR_SIZE, 1, NVS_SECTOR_ACTIVE); /* older, higher seq */
    th_craft_sector_hdr(2 * FLASH_SECTOR_SIZE, 0, NVS_SECTOR_ACTIVE); /* newer, seq wrapped to 0 */
    uint32_t old_v = 111, new_v = 999;
    th_craft_valid_entry(0 * FLASH_SECTOR_SIZE + NVS_SECTOR_HDR_SIZE, "dup", 3, &old_v, 4);
    th_craft_valid_entry(2 * FLASH_SECTOR_SIZE + NVS_SECTOR_HDR_SIZE, "dup", 3, &new_v, 4);
    th_mount();
    rb = 0;
    nvs_err_t dr = nvs_read("dup", &rb, sizeof(rb), &ol);
    printf("  consequence: read 'dup' rc=%d val=%u (newest=999, stale=111)\n", dr, rb);
    if (dr == NVS_OK && rb == 111)
    {
        REPORT_FAIL("read returned STALE value 111: seq-0 sector mis-sorted as oldest (read inversion)");
    }
    else if (dr == NVS_OK && rb == 999)
    {
        REPORT_PASS("read returned newest value 999 despite seq-0 sector");
    }
    else
    {
        REPORT_AMB("read of crafted multi-copy key returned an unexpected result");
    }
}

/*===========================================================================
 *  Issue G — no fallback to an older intact copy on CRC error
 *===========================================================================*/

static void test_issue_G_no_crc_fallback(void)
{
    printf("\n--- Issue G: CRC error on newest copy, no fallback to older intact copy ---\n");
    flash_full_erase();

    /* Two committed copies of 'g' in two sectors; the newer one corrupted. */
    th_craft_sector_hdr(0 * FLASH_SECTOR_SIZE, 1, NVS_SECTOR_ACTIVE); /* older intact */
    th_craft_sector_hdr(1 * FLASH_SECTOR_SIZE, 2, NVS_SECTOR_ACTIVE); /* newer corrupt */

    uint32_t intact_v = 0x11223344;
    uint32_t newer_v  = 0x55667788;
    th_craft_valid_entry(0 * FLASH_SECTOR_SIZE + NVS_SECTOR_HDR_SIZE, "g", 1, &intact_v, 4);
    th_craft_valid_entry(1 * FLASH_SECTOR_SIZE + NVS_SECTOR_HDR_SIZE, "g", 1, &newer_v, 4);

    /* Corrupt one data byte of the NEWER copy (clear a bit: 0x55 -> 0x54). */
    uint32_t data_off = 1 * FLASH_SECTOR_SIZE + NVS_SECTOR_HDR_SIZE + NVS_ENTRY_HDR_SIZE + 1;
    uint8_t clr = 0x00; /* AND to zero: guarantees a value change vs. stored CRC */
    flash_write(data_off, &clr, 1);

    th_mount();

    uint32_t rb = 0; uint8_t ol = 0;
    nvs_err_t rc = nvs_read("g", &rb, sizeof(rb), &ol);
    printf("  observed: read 'g' rc=%d val=0x%X (older intact copy = 0x%X)\n",
           rc, rb, intact_v);

    if (rc == NVS_ERR_CRC)
    {
        REPORT_AMB("returns NVS_ERR_CRC on newest copy, never falls back to intact older copy (matches documented read spec - fail-safe policy)");
    }
    else if (rc == NVS_OK && rb == intact_v)
    {
        REPORT_PASS("read fell back to the older intact copy");
    }
    else
    {
        REPORT_AMB("unexpected result reading corrupted-newest / intact-older key");
    }
}

/*===========================================================================
 *  Issue H — undersized read buffer: INVALID_ARG, out_len untouched
 *===========================================================================*/

static void test_issue_H_undersized_buffer(void)
{
    printf("\n--- Issue H: undersized read buffer contract ---\n");
    flash_full_erase();
    th_mount();

    uint8_t payload[8];
    memset(payload, 0xC3, sizeof(payload));
    nvs_write("h", payload, sizeof(payload)); /* 8-byte value */

    uint8_t small[4];
    uint8_t out_len = 0xAA; /* sentinel: must stay untouched on failure */
    nvs_err_t rc = nvs_read("h", small, sizeof(small), &out_len);

    printf("  observed: rc=%d out_len=0x%02X (expected INVALID_ARG, sentinel 0xAA)\n",
           rc, out_len);

    if (rc == NVS_ERR_INVALID_ARG && out_len == 0xAA)
    {
        REPORT_PASS("undersized read returns INVALID_ARG and leaves out_len untouched");
    }
    else
    {
        REPORT_FAIL("undersized read contract violated");
    }
}

/*===========================================================================
 *  Crash-issue orchestration (A and F run as separate executables)
 *===========================================================================*/

static void echo_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
    {
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), f) != NULL)
    {
        printf("    | %s", line);
    }
    fclose(f);
}

static void run_child(const char *label, const char *exe, const char *logname)
{
    printf("\n--- %s (child process: %s) ---\n", label, exe);
    fflush(stdout);

    /* Redirect the child's own output to a log so its fatal stack-overrun
     * exception cannot disturb this harness's output stream. */
    char cmd[600];
    snprintf(cmd, sizeof(cmd), "%s > %s 2>&1", exe, logname);
    int rc = system(cmd);
    echo_file(logname);
    printf("  child exit status = %d\n", rc);
    if (rc == 0)
    {
        /* Child reached its end WITHOUT detecting the oversized access and
         * WITHOUT crashing. */
        REPORT_PASS("child completed cleanly (no overflow observed)");
    }
    else
    {
        /* exit 42  = Issue A driver intercepted the oversized read (clean proof)
         * non-zero = Issue F smashed its stack canary / aborted.
         * Either way: a memory-safety violation is CONFIRMED. */
        REPORT_FAIL("child reported overflow / aborted (memory-safety violation CONFIRMED)");
    }
}

/*===========================================================================
 *  Main
 *===========================================================================*/

int main(int argc, char **argv)
{
    setbuf(stdout, NULL); /* unbuffered: keep output intact across child aborts */

    printf("========================================\n");
    printf("  NVS Issue Verification Suite\n");
    printf("========================================\n");

    test_issue_B1_all_full_remount();
    test_issue_B2_full_no_active();
    test_issue_C_torn_residue();
    test_issue_D_gc_cannot_relocate();
    test_issue_E_seq_poisoning();
    test_issue_G_no_crc_fallback();
    test_issue_H_undersized_buffer();

    /* A and F are crash-type; launch them as children if paths were given. */
    /* NOTE: launched via system()/cmd.exe -> use a bare name (cwd is searched),
     * never a "./" prefix which cmd.exe does not understand. */
    const char *exe_a = (argc > 1) ? argv[1] : ".\\test_issue_A.exe";
    const char *exe_f = (argc > 2) ? argv[2] : ".\\test_issue_F.exe";
    run_child("Issue A: oversized length -> stack overflow in nvs_read", exe_a, "child_A.log");
    run_child("Issue F: sector_count > 16 -> fixed-array stack overflow", exe_f, "child_F.log");

    printf("\n========================================\n");
    printf("  Summary: %d bug(s) CONFIRMED, %d spec-honored, %d ambiguous\n",
           g_bug, g_ok, g_amb);
    printf("========================================\n");
    return 0;
}
