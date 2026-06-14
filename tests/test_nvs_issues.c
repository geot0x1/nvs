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
    nvs_write("vict", &v1, sizeof(v1)); /* 16-byte entry at offset NVS_SECTOR_HDR_SIZE */

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
    /* Torn entry placed immediately after the committed "vict" entry.
     * "vict" occupies NVS_SECTOR_HDR_SIZE .. NVS_SECTOR_HDR_SIZE+15 (16 bytes). */
    flash_write(NVS_SECTOR_HDR_SIZE + 16, torn, 24);

    th_mount(); /* mount detects 0xFF state byte, marks DELETED, advances write_offset past it */

    /* Debug: print flash state after mount */
    {
        uint8_t dbg[80];
        flash_read(NVS_SECTOR_HDR_SIZE, dbg, sizeof(dbg));
        printf("  [DBG] flash[%u..%u] after 2nd mount:\n", NVS_SECTOR_HDR_SIZE, NVS_SECTOR_HDR_SIZE+79);
        for (int _i = 0; _i < 80; _i += 8)
        {
            printf("  [DBG]  +%02d: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   _i, dbg[_i],dbg[_i+1],dbg[_i+2],dbg[_i+3],dbg[_i+4],dbg[_i+5],dbg[_i+6],dbg[_i+7]);
        }
    }

    /* A new committed write for 'vict' lands on top of the torn residue. */
    uint32_t v2 = 222;
    nvs_err_t wr = nvs_write("vict", &v2, sizeof(v2));

    /* Debug: print flash state after write */
    {
        uint8_t dbg[80];
        flash_read(NVS_SECTOR_HDR_SIZE, dbg, sizeof(dbg));
        printf("  [DBG] flash[%u..%u] after nvs_write(vict,222):\n", NVS_SECTOR_HDR_SIZE, NVS_SECTOR_HDR_SIZE+79);
        for (int _i = 0; _i < 80; _i += 8)
        {
            printf("  [DBG]  +%02d: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   _i, dbg[_i],dbg[_i+1],dbg[_i+2],dbg[_i+3],dbg[_i+4],dbg[_i+5],dbg[_i+6],dbg[_i+7]);
        }
    }

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
 *  Regression test: Interrupted GC resume on remount
 *===========================================================================*/

static void test_interrupted_gc_resume(void)
{
    printf("\n--- Regression test: interrupted GC completes safely on remount ---\n");
    flash_full_erase();
    th_mount();

    /* Scenario: Fill sector 0 completely, then write to sector 1.
     * Simulate power loss mid-GC by setting sector 0 to FREEING and manually
     * copying only one entry to sector 1. */

    uint32_t val_a = 0xAAAA, val_b = 0xBBBB, val_c = 0xCCCC, val_d = 0xDDDD;
    nvs_write("A", &val_a, sizeof(val_a));
    nvs_write("B", &val_b, sizeof(val_b));
    nvs_write("C", &val_c, sizeof(val_c));

    /* Mark sector 0 as FULL to trigger new sector activation and GC. */
    uint32_t full_state = NVS_SECTOR_FULL;
    flash_write(8, &full_state, sizeof(full_state));

    /* Activate sector 1 by writing a new key. */
    nvs_write("D", &val_d, sizeof(val_d));

    /* Now manually simulate interrupted GC:
     * 1. Set sector 0 state to FREEING (as if GC started).
     * 2. Manually copy only key "A" to sector 1 (partial copy).
     * 3. Do NOT erase sector 0 yet.
     * 4. Remount and let nvs_mount detect and resume the FREEING sector. */

    /* Set sector 0 to FREEING. */
    uint32_t freeing_state = NVS_SECTOR_FREEING;
    flash_write(8, &freeing_state, sizeof(freeing_state));

    /* Manually craft entry "A" in sector 1 (after the "D" entry).
     * First, find where in sector 1 the "D" entry ends. */
    uint32_t sector_1_base = 4096; /* Assuming 4KB sectors, sector 1 starts at 4096 */
    uint32_t write_off = 16 + 8; /* header + 8-byte "D" entry aligned */

    uint8_t key_a = 1; /* "A" is 1 character */
    uint32_t entry_size = 8 + 1 + 4; /* header(8) + key(1) + data(4) */
    entry_size = (entry_size + 3) & ~3U; /* align4 = 16 bytes */

    th_craft_valid_entry(sector_1_base + write_off, "A", 1, &val_a, sizeof(val_a));

    /* Remount: nvs_mount should detect FREEING sector 0 and resume GC. */
    th_mount();

    /* Verify all four keys are readable with correct values. */
    uint32_t rb = 0;
    uint8_t ol = 0;

    nvs_err_t rc_a = nvs_read("A", &rb, sizeof(rb), &ol);
    int a_ok = (rc_a == NVS_OK && rb == 0xAAAA);

    rb = 0;
    nvs_err_t rc_b = nvs_read("B", &rb, sizeof(rb), &ol);
    int b_ok = (rc_b == NVS_OK && rb == 0xBBBB);

    rb = 0;
    nvs_err_t rc_c = nvs_read("C", &rb, sizeof(rb), &ol);
    int c_ok = (rc_c == NVS_OK && rb == 0xCCCC);

    rb = 0;
    nvs_err_t rc_d = nvs_read("D", &rb, sizeof(rb), &ol);
    int d_ok = (rc_d == NVS_OK && rb == 0xDDDD);

    /* Verify sector 0 is fully erased (GC completed). */
    uint32_t first_word = 0;
    flash_read(0, &first_word, sizeof(first_word));
    int sector_0_erased = (first_word == 0xFFFFFFFF);

    printf("  observed: A=%s B=%s C=%s D=%s sector0_erased=%d\n",
           a_ok ? "OK" : "FAIL", b_ok ? "OK" : "FAIL", c_ok ? "OK" : "FAIL",
           d_ok ? "OK" : "FAIL", sector_0_erased);

    if (a_ok && b_ok && c_ok && d_ok && sector_0_erased)
    {
        REPORT_PASS("all keys readable after interrupted-GC resume, sector erased");
    }
    else
    {
        REPORT_FAIL("interrupted GC resume lost data or did not complete sector erase");
    }
}

