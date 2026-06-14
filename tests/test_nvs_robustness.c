/*
 * test_nvs_robustness.c — NVS robustness and boundary-condition test suite.
 *
 * Covers scenarios not present in the functional, issue, edge-case, or stress
 * suites: payload patterns, cross-sector read ordering, GC edge cases, mount
 * idempotency, and key comparison boundaries.
 *
 * Scenarios:
 *   1.  Single-character key round-trip
 *   2.  All-zeros payload (same pattern as cleared memory)
 *   3.  All-0xFF payload (same bit pattern as erased NOR flash)
 *   4.  Alternating 0xAA/0x55 payload (classic stuck-bit pattern)
 *   5.  Same key written across three sectors — read returns newest
 *   6.  GC with exactly one live entry — forces copy before erase
 *   7.  Write -> GC -> remount — pre-GC data survives cold boot
 *   8.  Tombstone propagation — delete suppresses copies in older sectors after GC
 *   9.  Write-offset recovery after partial sector fill + remount
 *  10.  Repeated mount/unmount without writes — seq_counter must not drift
 *  11.  Key with all printable ASCII characters (15-char boundary)
 *  12.  Overwrite changes data length — shorter then longer payload
 *  13.  Read into exact-size buffer (no margin) returns NVS_OK
 *  14.  Two keys differing only in the last character are independent
 *  15.  GC preserves write ordering: latest copy always wins after reclaim
 */

#include "test_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_pass = 0;
static int g_fail = 0;

#define P_PASS(msg) do { printf("  [PASS] %s\n", (msg)); g_pass++; } while (0)
#define P_FAIL(msg) do { printf("  [FAIL] %s  (line %d)\n", (msg), __LINE__); g_fail++; } while (0)
#define P_ASSERT(cond, msg) do { if (cond) { P_PASS(msg); } else { P_FAIL(msg); } } while (0)

/*===========================================================================
 *  1. Single-character key round-trip
 *
 *  Key comparison must not confuse a 1-char key with a prefix of a longer key.
 *===========================================================================*/

static void test_single_char_key(void)
{
    printf("\n--- Robustness 1: single-character key round-trip ---\n");

    flash_full_erase();
    th_mount();

    uint32_t val = 0xDEADC0DEU;
    nvs_err_t rc = nvs_write("x", &val, sizeof(val));
    P_ASSERT(rc == NVS_OK, "write 1-char key 'x' returns NVS_OK");

    /* A different 1-char key must not collide. */
    uint32_t val2 = 0x12345678U;
    rc = nvs_write("y", &val2, sizeof(val2));
    P_ASSERT(rc == NVS_OK, "write 1-char key 'y' returns NVS_OK");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read("x", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,           "read 'x' returns NVS_OK");
    P_ASSERT(rb == 0xDEADC0DEU,      "read 'x' returns correct value");

    rb = 0;
    rc = nvs_read("y", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,           "read 'y' returns NVS_OK");
    P_ASSERT(rb == 0x12345678U,      "'y' not confused with 'x'");
}

/*===========================================================================
 *  2. All-zeros payload
 *
 *  A payload of all 0x00 bytes is legal.  The CRC over a zero buffer is a
 *  known non-zero value; the implementation must not short-circuit on zero
 *  data.
 *===========================================================================*/

static void test_all_zeros_payload(void)
{
    printf("\n--- Robustness 2: all-zeros payload ---\n");

    flash_full_erase();
    th_mount();

    uint8_t zeroes[16];
    memset(zeroes, 0x00, sizeof(zeroes));

    nvs_err_t rc = nvs_write("zeros", zeroes, sizeof(zeroes));
    P_ASSERT(rc == NVS_OK, "write all-zeros payload returns NVS_OK");

    uint8_t rb[16];
    memset(rb, 0xFF, sizeof(rb)); /* poison with 0xFF so a false pass is visible */
    uint8_t ol = 0;
    rc = nvs_read("zeros", rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,               "read all-zeros payload returns NVS_OK");
    P_ASSERT(ol == sizeof(zeroes),        "read reports correct length");
    P_ASSERT(memcmp(rb, zeroes, ol) == 0, "all-zeros payload is byte-exact");
}

/*===========================================================================
 *  3. All-0xFF payload
 *
 *  0xFF is the erased NOR flash state.  A payload of all 0xFF bytes must
 *  be distinguishable from unwritten flash.  The CRC covers the payload so
 *  the stored CRC will differ from 0xFFFFFFFF, and the entry state byte
 *  (0xFE = VALID) distinguishes it from empty flash (0xFF).
 *===========================================================================*/

static void test_all_ff_payload(void)
{
    printf("\n--- Robustness 3: all-0xFF payload (erased flash pattern) ---\n");

    flash_full_erase();
    th_mount();

    uint8_t ffs[8];
    memset(ffs, 0xFF, sizeof(ffs));

    nvs_err_t rc = nvs_write("ffs", ffs, sizeof(ffs));
    P_ASSERT(rc == NVS_OK, "write all-0xFF payload returns NVS_OK");

    uint8_t rb[8];
    memset(rb, 0x00, sizeof(rb));
    uint8_t ol = 0;
    rc = nvs_read("ffs", rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,            "read all-0xFF payload returns NVS_OK");
    P_ASSERT(ol == sizeof(ffs),        "read reports correct length");
    P_ASSERT(memcmp(rb, ffs, ol) == 0, "all-0xFF payload is byte-exact");

    /* CRC of the 0xFF blob must have been correctly stored — verify by
     * corrupting one byte and confirming CRC detection fires. */
    uint8_t bad = 0x00;
    /* Entry starts at NVS_SECTOR_HDR_SIZE; data starts at +NVS_ENTRY_HDR_SIZE+3 (key "ffs"). */
    uint32_t data_byte_addr = NVS_SECTOR_HDR_SIZE + NVS_ENTRY_HDR_SIZE + 3U;
    flash_write(data_byte_addr, &bad, 1);

    rb[0] = 0xAB; /* poison */
    ol = 0;
    rc = nvs_read("ffs", rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_ERR_CRC, "corrupted 0xFF payload detected by CRC");
}

/*===========================================================================
 *  4. Alternating 0xAA/0x55 payload (stuck-bit pattern)
 *
 *  Classic pattern used in memory tests to catch stuck-at-0 and stuck-at-1
 *  bit faults.
 *===========================================================================*/

static void test_alternating_pattern_payload(void)
{
    printf("\n--- Robustness 4: alternating 0xAA/0x55 payload ---\n");

    flash_full_erase();
    th_mount();

    uint8_t pattern[32];
    for (int i = 0; i < 32; i++)
    {
        pattern[i] = (i % 2 == 0) ? 0xAAU : 0x55U;
    }

    nvs_err_t rc = nvs_write("alt", pattern, sizeof(pattern));
    P_ASSERT(rc == NVS_OK, "write alternating 0xAA/0x55 payload returns NVS_OK");

    uint8_t rb[32];
    memset(rb, 0, sizeof(rb));
    uint8_t ol = 0;
    rc = nvs_read("alt", rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,                  "read alternating payload returns NVS_OK");
    P_ASSERT(ol == sizeof(pattern),          "read reports correct length (32)");
    P_ASSERT(memcmp(rb, pattern, ol) == 0,   "alternating payload is byte-exact");
}

/*===========================================================================
 *  5. Same key written across three sectors — read returns newest
 *
 *  Writes "multi" once per sector-fill cycle so it ends up with one live
 *  copy in each of the three sectors.  nvs_read must return the copy from
 *  the highest-sequence sector, not the first one found.
 *===========================================================================*/

static void test_same_key_across_three_sectors(void)
{
    printf("\n--- Robustness 5: same key written across three sectors ---\n");

    flash_full_erase();
    th_mount();

    char key[5];
    uint32_t fill_val;

    /* Write "multi" = 111 into sector 0, then fill sector 0 to force it FULL. */
    uint32_t v1 = 111U;
    nvs_write("multi", &v1, sizeof(v1));

    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR - 1U; i++)
    {
        key[0] = 'P'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        fill_val = i;
        nvs_write(key, &fill_val, sizeof(fill_val));
    }

    /* Write "multi" = 222 into sector 1, then fill sector 1. */
    uint32_t v2 = 222U;
    nvs_write("multi", &v2, sizeof(v2));

    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR - 1U; i++)
    {
        key[0] = 'Q'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        fill_val = i;
        nvs_write(key, &fill_val, sizeof(fill_val));
    }

    /* Write "multi" = 333 into sector 2 (now the active sector). */
    uint32_t v3 = 333U;
    nvs_err_t rc = nvs_write("multi", &v3, sizeof(v3));
    P_ASSERT(rc == NVS_OK, "third cross-sector write of 'multi' returns NVS_OK");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read("multi", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,   "read 'multi' returns NVS_OK");
    P_ASSERT(rb == 333U,     "read 'multi' returns newest value (333), not stale (111 or 222)");
}

/*===========================================================================
 *  6. GC with exactly one live entry — forced copy before erase
 *
 *  All entries in the oldest FULL sector are DELETED except one.  GC must
 *  copy that single live entry to the active sector before erasing the source.
 *===========================================================================*/

static void test_gc_single_live_entry(void)
{
    printf("\n--- Robustness 6: GC with exactly one live entry in target sector ---\n");

    flash_full_erase();
    th_mount();

    /* Write the lone survivor early so it lands in sector 0. */
    uint32_t survivor_val = 0xCAFEF00DU;
    nvs_write("lone", &survivor_val, sizeof(survivor_val));

    /* Fill the rest of sector 0 with a key we'll delete later. */
    uint32_t fill_val;
    char key[5];
    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR - 1U; i++)
    {
        key[0] = 'D'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        fill_val = i;
        nvs_write(key, &fill_val, sizeof(fill_val));
    }

    /* Delete every filler key — sector 0 now has exactly one live entry: "lone". */
    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR - 1U; i++)
    {
        key[0] = 'D'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        nvs_delete(key);
    }

    /* Fill sector 1 entirely with unique keys to force GC when we overflow. */
    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR; i++)
    {
        key[0] = 'U'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        fill_val = i + 1000U;
        nvs_write(key, &fill_val, sizeof(fill_val));
    }

    /* This write overflows sector 2 and triggers GC on sector 0. */
    uint32_t post_gc_val = 0xBEEFBEEFU;
    nvs_err_t rc = nvs_write("POST", &post_gc_val, sizeof(post_gc_val));
    P_ASSERT(rc == NVS_OK, "write triggering GC of single-live-entry sector returns NVS_OK");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read("lone", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,           "lone survivor is readable after GC");
    P_ASSERT(rb == 0xCAFEF00DU,      "lone survivor value is correct after GC");

    rc = nvs_read("POST", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,           "post-GC entry is readable");
    P_ASSERT(rb == 0xBEEFBEEFU,      "post-GC entry value is correct");
}

/*===========================================================================
 *  7. Write -> GC -> remount — pre-GC data survives cold boot
 *
 *  Writes a set of anchor keys, triggers GC, then simulates a power cycle.
 *  All pre-GC anchor keys must survive.
 *===========================================================================*/

static void test_write_gc_remount_survival(void)
{
    printf("\n--- Robustness 7: write -> GC -> remount survival ---\n");

    flash_full_erase();
    th_mount();

    /* Write 5 anchor keys that must survive everything. */
    uint32_t anchors[5] = {0xA1A1A1A1U, 0xB2B2B2B2U, 0xC3C3C3C3U,
                           0xD4D4D4D4U, 0xE5E5E5E5U};
    const char *anchor_keys[5] = {"anc0", "anc1", "anc2", "anc3", "anc4"};
    for (int i = 0; i < 5; i++)
    {
        nvs_write(anchor_keys[i], &anchors[i], sizeof(anchors[i]));
    }

    /* Fill sector 0 with churn to make it mostly dead, then trigger GC. */
    uint32_t val;
    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR - 5U; i++)
    {
        val = i;
        nvs_write("churn", &val, sizeof(val));
    }

    /* Fill sector 1. */
    char key[5];
    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR; i++)
    {
        key[0] = 'F'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        val = i;
        nvs_write(key, &val, sizeof(val));
    }

    /* This write triggers GC. */
    val = 0x7E7E7E7EU;
    nvs_err_t rc = nvs_write("trig", &val, sizeof(val));
    P_ASSERT(rc == NVS_OK, "GC-triggering write returns NVS_OK");

    /* Simulate power cycle. */
    th_mount();

    uint32_t rb = 0;
    uint8_t  ol = 0;
    int all_ok = 1;
    for (int i = 0; i < 5; i++)
    {
        rb = 0;
        rc = nvs_read(anchor_keys[i], &rb, sizeof(rb), &ol);
        if (rc != NVS_OK || rb != anchors[i])
        {
            printf("  [INFO] anchor '%s': expected 0x%08X got 0x%08X rc=%d\n",
                   anchor_keys[i], anchors[i], rb, rc);
            all_ok = 0;
        }
    }
    P_ASSERT(all_ok, "all 5 anchor keys survive write -> GC -> remount");

    rb = 0;
    rc = nvs_read("trig", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK && rb == 0x7E7E7E7EU,
             "GC-triggering entry survives remount");
}

/*===========================================================================
 *  8. Tombstone propagation — delete suppresses copies in older sectors
 *
 *  Write key "tomb" once in sector 0, once in sector 1 (overwrite), then
 *  delete it.  After a GC cycle and remount, nvs_read must return NOT_FOUND.
 *===========================================================================*/

static void test_tombstone_propagation(void)
{
    printf("\n--- Robustness 8: tombstone propagation after GC ---\n");

    flash_full_erase();
    th_mount();

    uint32_t v1 = 0x11112222U;
    nvs_write("tomb", &v1, sizeof(v1));

    char key[5];
    uint32_t fill_val;
    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR - 1U; i++)
    {
        key[0] = 'T'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        fill_val = i;
        nvs_write(key, &fill_val, sizeof(fill_val));
    }

    uint32_t v2 = 0x33334444U;
    nvs_write("tomb", &v2, sizeof(v2));

    nvs_err_t rc = nvs_delete("tomb");
    P_ASSERT(rc == NVS_OK, "delete 'tomb' returns NVS_OK");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read("tomb", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_ERR_NOT_FOUND, "'tomb' is NOT_FOUND immediately after delete");

    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR; i++)
    {
        key[0] = 'G'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        fill_val = i + 2000U;
        nvs_write(key, &fill_val, sizeof(fill_val));
    }

    th_mount();

    rc = nvs_read("tomb", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_ERR_NOT_FOUND,
             "'tomb' remains NOT_FOUND after GC + remount (tombstone propagated correctly)");
}

/*===========================================================================
 *  9. Write-offset recovery after partial sector fill + remount
 *
 *  Write N entries (not a full sector), remount, then write one more entry.
 *  The new entry must be appended after the existing ones, not written on top
 *  of them.  Catches the class of bug where mount resets write_offset to
 *  NVS_SECTOR_HDR_SIZE instead of scanning to find the true end of data.
 *===========================================================================*/

static void test_write_offset_recovery_after_partial_fill(void)
{
    printf("\n--- Robustness 9: write-offset recovery after partial fill + remount ---\n");

    flash_full_erase();
    th_mount();

    const uint32_t half = ENTRIES_PER_SECTOR / 2U;
    char key[5];
    uint32_t val;

    for (uint32_t i = 0; i < half; i++)
    {
        key[0] = 'H'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        val = i * 2U;
        nvs_write(key, &val, sizeof(val));
    }

    th_mount();

    uint32_t post_val = 0xABCDABCDU;
    nvs_err_t rc = nvs_write("post", &post_val, sizeof(post_val));
    P_ASSERT(rc == NVS_OK, "write after partial-fill remount returns NVS_OK");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read("post", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK && rb == 0xABCDABCDU,
             "post-remount entry reads back correctly");

    int pre_ok = 1;
    for (uint32_t i = 0; i < half; i += (half / 4U + 1U))
    {
        key[0] = 'H'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        rb = 0;
        rc = nvs_read(key, &rb, sizeof(rb), &ol);
        if (rc != NVS_OK || rb != i * 2U)
        {
            printf("  [INFO] pre-remount key '%s' expected %u got %u rc=%d\n",
                   key, i * 2U, rb, rc);
            pre_ok = 0;
        }
    }
    P_ASSERT(pre_ok,
             "pre-remount entries are undamaged after post-remount write (offset recovered correctly)");
}

/*===========================================================================
 *  10. Repeated mount/unmount without writes — seq_counter must not drift
 *
 *  Mount 100 times in succession without writing anything.  The seq_counter
 *  must not advance on read-only mounts.
 *===========================================================================*/

static void test_repeated_mount_no_writes(void)
{
    printf("\n--- Robustness 10: repeated mount/unmount without writes ---\n");

    flash_full_erase();
    th_mount();

    uint32_t sentinel = 0xFACEFACEU;
    nvs_write("sent", &sentinel, sizeof(sentinel));

    uint32_t seq_before = 0;
    flash_read(4U, &seq_before, sizeof(seq_before)); /* sector 0 seq field at offset 4 */

    for (int i = 0; i < 100; i++)
    {
        th_mount();
    }

    uint32_t seq_after = 0;
    flash_read(4U, &seq_after, sizeof(seq_after));

    P_ASSERT(seq_before == seq_after,
             "seq_counter does not advance across 100 read-only mounts");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    nvs_err_t rc = nvs_read("sent", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK && rb == 0xFACEFACEU,
             "sentinel value intact after 100 remounts");
}

/*===========================================================================
 *  11. Key with all printable ASCII chars at the 15-char boundary
 *===========================================================================*/

static void test_max_key_all_printable(void)
{
    printf("\n--- Robustness 11: 15-char key with mixed printable ASCII ---\n");

    flash_full_erase();
    th_mount();

    char k15[16];
    memcpy(k15, "aB3xY9mK2nP7qRz", 15);
    k15[15] = '\0';

    uint32_t val = 0x55AA55AAU;
    nvs_err_t rc = nvs_write(k15, &val, sizeof(val));
    P_ASSERT(rc == NVS_OK, "write 15-char mixed-ASCII key returns NVS_OK");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read(k15, &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK,       "read 15-char mixed-ASCII key returns NVS_OK");
    P_ASSERT(rb == 0x55AA55AAU,  "value correct for 15-char key");
}

/*===========================================================================
 *  12. Overwrite changes data length — shorter then longer payload
 *
 *  Write 8 bytes, overwrite with 4 bytes, then overwrite again with 16 bytes.
 *  Each read must return the current payload length and bytes exactly.
 *===========================================================================*/

static void test_overwrite_changes_data_length(void)
{
    printf("\n--- Robustness 12: overwrite changes data length (8->4->16) ---\n");

    flash_full_erase();
    th_mount();

    uint8_t payload8[8]  = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};
    uint8_t payload4[4]  = {0xAA,0xBB,0xCC,0xDD};
    uint8_t payload16[16];
    for (int i = 0; i < 16; i++)
    {
        payload16[i] = (uint8_t)(0x10 + i);
    }

    nvs_err_t rc = nvs_write("vary", payload8, sizeof(payload8));
    P_ASSERT(rc == NVS_OK, "initial 8-byte write returns NVS_OK");

    uint8_t rb[16];
    uint8_t ol = 0;
    rc = nvs_read("vary", rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK && ol == 8,          "read after 8-byte write reports length 8");
    P_ASSERT(memcmp(rb, payload8, 8) == 0,     "8-byte payload is byte-exact");

    rc = nvs_write("vary", payload4, sizeof(payload4));
    P_ASSERT(rc == NVS_OK, "overwrite with 4-byte (shorter) payload returns NVS_OK");

    memset(rb, 0xFF, sizeof(rb));
    ol = 0;
    rc = nvs_read("vary", rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK && ol == 4,          "read after 4-byte overwrite reports length 4");
    P_ASSERT(memcmp(rb, payload4, 4) == 0,     "4-byte payload is byte-exact");

    rc = nvs_write("vary", payload16, sizeof(payload16));
    P_ASSERT(rc == NVS_OK, "overwrite with 16-byte (longer) payload returns NVS_OK");

    memset(rb, 0x00, sizeof(rb));
    ol = 0;
    rc = nvs_read("vary", rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK && ol == 16,         "read after 16-byte overwrite reports length 16");
    P_ASSERT(memcmp(rb, payload16, 16) == 0,   "16-byte payload is byte-exact");
}

/*===========================================================================
 *  13. Read into exact-size buffer (no margin) returns NVS_OK
 *
 *  buf_size == stored data length is the tight boundary; catches off-by-one
 *  bugs in the buffer-size comparison (> vs >=).
 *===========================================================================*/

static void test_read_exact_buffer_size(void)
{
    printf("\n--- Robustness 13: read into exact-size buffer (no margin) ---\n");

    flash_full_erase();
    th_mount();

    uint8_t payload[7] = {0x10,0x20,0x30,0x40,0x50,0x60,0x70};
    nvs_write("exact", payload, sizeof(payload));

    uint8_t rb[7];
    memset(rb, 0, sizeof(rb));
    uint8_t ol = 0;

    nvs_err_t rc = nvs_read("exact", rb, 7, &ol);
    P_ASSERT(rc == NVS_OK,                     "read with buf_size == data_len returns NVS_OK");
    P_ASSERT(ol == 7,                           "out_len is 7");
    P_ASSERT(memcmp(rb, payload, 7) == 0,       "payload byte-exact with exact-size buffer");

    rc = nvs_read("exact", rb, 6, &ol);
    P_ASSERT(rc == NVS_ERR_INVALID_ARG,         "read with buf_size == data_len-1 returns INVALID_ARG");
}

/*===========================================================================
 *  14. Two keys differing only in last character are independent
 *
 *  Key comparison must be exact — a shared prefix must not cause aliasing.
 *===========================================================================*/

static void test_keys_differ_only_in_last_char(void)
{
    printf("\n--- Robustness 14: keys differing only in last character are independent ---\n");

    flash_full_erase();
    th_mount();

    uint32_t va = 0xAAAAAAAAU;
    uint32_t vb = 0xBBBBBBBBU;
    uint32_t vc = 0xCCCCCCCCU;

    nvs_write("tempa", &va, sizeof(va));
    nvs_write("tempb", &vb, sizeof(vb));
    nvs_write("tempc", &vc, sizeof(vc));

    uint32_t rb = 0;
    uint8_t  ol = 0;

    nvs_read("tempa", &rb, sizeof(rb), &ol);
    P_ASSERT(rb == 0xAAAAAAAAU, "'tempa' reads 0xAAAAAAAA");

    nvs_read("tempb", &rb, sizeof(rb), &ol);
    P_ASSERT(rb == 0xBBBBBBBBU, "'tempb' reads 0xBBBBBBBB");

    nvs_read("tempc", &rb, sizeof(rb), &ol);
    P_ASSERT(rb == 0xCCCCCCCCU, "'tempc' reads 0xCCCCCCCC");

    uint32_t vb2 = 0xDDDDDDDDU;
    nvs_write("tempb", &vb2, sizeof(vb2));

    nvs_read("tempa", &rb, sizeof(rb), &ol);
    P_ASSERT(rb == 0xAAAAAAAAU, "'tempa' unchanged after overwriting 'tempb'");

    nvs_read("tempb", &rb, sizeof(rb), &ol);
    P_ASSERT(rb == 0xDDDDDDDDU, "'tempb' updated to 0xDDDDDDDD");

    nvs_read("tempc", &rb, sizeof(rb), &ol);
    P_ASSERT(rb == 0xCCCCCCCCU, "'tempc' unchanged after overwriting 'tempb'");
}

/*===========================================================================
 *  15. GC preserves write ordering: latest copy always wins after reclaim
 *
 *  A key is written 3 times across sector boundaries.  After GC and a remount,
 *  nvs_read must return the absolute latest value.
 *===========================================================================*/

static void test_gc_preserves_write_ordering(void)
{
    printf("\n--- Robustness 15: GC preserves write ordering across reclaim ---\n");

    flash_full_erase();
    th_mount();

    uint32_t v1 = 1111U;
    nvs_write("order", &v1, sizeof(v1));

    char key[5];
    uint32_t fill_val;

    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR - 2U; i++)
    {
        key[0] = 'R'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        fill_val = i;
        nvs_write(key, &fill_val, sizeof(fill_val));
    }

    uint32_t v2 = 2222U;
    nvs_write("order", &v2, sizeof(v2));

    fill_val = 0xFFFF;
    nvs_write("pad0", &fill_val, sizeof(fill_val));

    uint32_t v3 = 3333U;
    nvs_write("order", &v3, sizeof(v3));

    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR - 2U; i++)
    {
        key[0] = 'S'; key[1] = (char)('0' + i / 100 % 10);
        key[2] = (char)('0' + i / 10 % 10); key[3] = (char)('0' + i % 10); key[4] = '\0';
        fill_val = i + 500U;
        nvs_write(key, &fill_val, sizeof(fill_val));
    }

    nvs_write("pad1", &fill_val, sizeof(fill_val));

    th_mount();

    uint32_t rb = 0;
    uint8_t  ol = 0;
    nvs_err_t rc = nvs_read("order", &rb, sizeof(rb), &ol);
    P_ASSERT(rc == NVS_OK, "read 'order' after GC + remount returns NVS_OK");
    P_ASSERT(rb == 3333U,  "read 'order' returns latest value (3333), not stale v1 or v2");
}

/*===========================================================================
 *  Entry point (called from main.c)
 *===========================================================================*/

void run_robustness_tests(int *pass, int *fail)
{
    printf("\n========================================\n");
    printf("  NVS Robustness Test Suite\n");
    printf("========================================\n");

    test_single_char_key();
    test_all_zeros_payload();
    test_all_ff_payload();
    test_alternating_pattern_payload();
    test_same_key_across_three_sectors();
    test_gc_single_live_entry();
    test_write_gc_remount_survival();
    test_tombstone_propagation();
    test_write_offset_recovery_after_partial_fill();
    test_repeated_mount_no_writes();
    test_max_key_all_printable();
    test_overwrite_changes_data_length();
    test_read_exact_buffer_size();
    test_keys_differ_only_in_last_char();
    test_gc_preserves_write_ordering();

    *pass += g_pass;
    *fail += g_fail;

    printf("\n========================================\n");
    printf("  Robustness suite: %d passed, %d failed\n", g_pass, g_fail);
    printf("========================================\n");
}
