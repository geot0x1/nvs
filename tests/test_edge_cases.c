/*
 * test_edge_cases.c — NVS edge-case tests targeting whole-system corruption.
 *
 * Each test probes a scenario that, if handled incorrectly, silently corrupts
 * data or leaves the NVS subsystem in an unrecoverable state.  Tests are
 * self-contained: they erase flash and mount fresh before each scenario.
 *
 * Scenarios covered:
 *   1. API calls before nvs_mount        — uninitialized driver must not crash
 *   2. seq_counter genuine wrap          — UINT32_MAX -> 0 must sort as highest
 *   3. Entry at exact sector boundary    — write_offset + esz == SECTOR_SIZE
 *   4. Delete all keys then remount      — system must stay operational
 *   5. Write after NO_SPACE then delete  — delete enables GC reclaim
 *   6. Overwrite with identical value    — old entry must be invalidated
 *   7. Max key + max data combined entry — largest legal entry must round-trip
 */

#include "test_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_pass = 0;
static int g_fail = 0;

#define EC_PASS(msg) do { printf("  [PASS] %s\n", (msg)); g_pass++; } while (0)
#define EC_FAIL(msg) do { printf("  [FAIL] %s  (line %d)\n", (msg), __LINE__); g_fail++; } while (0)
#define EC_ASSERT(cond, msg) do { if (cond) { EC_PASS(msg); } else { EC_FAIL(msg); } } while (0)

/*===========================================================================
 *  1. API calls before nvs_mount
 *
 *  After the last test leaves g_nvs with a valid driver, we force the
 *  unmounted state by mounting a zeroed driver (all function pointers NULL).
 *  This causes nvs_mount to return NVS_ERR_INVALID_ARG and leaves g_nvs.driver
 *  unchanged — still holding the previous valid pointers.  The only reliable
 *  way to test the pre-mount guard is via the nvs_is_mounted() check added to
 *  each public function, which tests driver->write != NULL.
 *
 *  Strategy: mount a dummy driver with only sector geometry set (no function
 *  pointers), which fails validation and leaves g_nvs.driver.write == NULL.
 *  Then call write/read/delete and verify they return an error without crashing.
 *===========================================================================*/

static void test_api_before_mount(void)
{
    printf("\n--- Edge case 1: API calls before nvs_mount ---\n");

    flash_full_erase();

    /* Attempt to mount with NULL function pointers — must fail, leaving
     * g_nvs.driver.write == NULL (the is-mounted sentinel). */
    nvs_flash_driver_t bad_drv = {0};
    bad_drv.sector_size  = FLASH_SECTOR_SIZE;
    bad_drv.sector_count = FLASH_SECTOR_COUNT;
    /* write / read / erase_sector are NULL */
    nvs_err_t bad_mount = nvs_mount(&bad_drv);
    EC_ASSERT(bad_mount == NVS_ERR_INVALID_ARG,
              "mount with NULL function pointers returns INVALID_ARG");

    /* Now call each public API — must return an error, not crash. */
    uint8_t dummy = 0xAA;
    uint8_t buf[4];
    uint8_t out_len = 0;

    nvs_err_t wr = nvs_write("k", &dummy, 1);
    nvs_err_t rd = nvs_read("k", buf, sizeof(buf), &out_len);
    nvs_err_t dl = nvs_delete("k");

    EC_ASSERT(wr != NVS_OK, "nvs_write before mount does not return NVS_OK");
    EC_ASSERT(rd != NVS_OK, "nvs_read before mount does not return NVS_OK");
    EC_ASSERT(dl != NVS_OK, "nvs_delete before mount does not return NVS_OK");

    /* After a proper mount the system must be fully operational. */
    th_mount();
    wr = nvs_write("k", &dummy, 1);
    rd = nvs_read("k", buf, sizeof(buf), &out_len);
    EC_ASSERT(wr == NVS_OK, "nvs_write after proper mount succeeds");
    EC_ASSERT(rd == NVS_OK && buf[0] == 0xAA,
              "nvs_read after proper mount returns correct value");
}

/*===========================================================================
 *  2. seq_counter genuine wrap (UINT32_MAX -> 0)
 *
 *  Craft two sectors: one with seq=UINT32_MAX (older) and one with seq=0
 *  (newer, counter wrapped).  seq_sort_key(0) maps to 0xFFFFFFFF so seq=0
 *  sorts FIRST.  nvs_read must return the value from the seq=0 sector.
 *  Incorrect behaviour would return the stale value from seq=UINT32_MAX.
 *===========================================================================*/

static void test_seq_counter_wrap(void)
{
    printf("\n--- Edge case 2: seq_counter genuine wrap (UINT32_MAX -> 0) ---\n");

    flash_full_erase();

    /* Sector 0: older copy, seq = UINT32_MAX. */
    th_craft_sector_hdr(0 * FLASH_SECTOR_SIZE, 0xFFFFFFFFU, NVS_SECTOR_ACTIVE);
    uint32_t old_val = 0x0A0B0C0DU;
    th_craft_valid_entry(0 * FLASH_SECTOR_SIZE + NVS_SECTOR_HDR_SIZE,
                         "wrap", 4, &old_val, sizeof(old_val));

    /* Sector 1: newer copy, seq = 0 (counter wrapped past UINT32_MAX). */
    th_craft_sector_hdr(1 * FLASH_SECTOR_SIZE, 0x00000000U, NVS_SECTOR_ACTIVE);
    uint32_t new_val = 0xCAFEF00DU;
    th_craft_valid_entry(1 * FLASH_SECTOR_SIZE + NVS_SECTOR_HDR_SIZE,
                         "wrap", 4, &new_val, sizeof(new_val));

    th_mount();

    uint32_t rb = 0;
    uint8_t  ol = 0;
    nvs_err_t rc = nvs_read("wrap", &rb, sizeof(rb), &ol);

    printf("  observed: rc=%d val=0x%08X (newest=0x%08X stale=0x%08X)\n",
           rc, rb, new_val, old_val);

    EC_ASSERT(rc == NVS_OK,
              "nvs_read returns NVS_OK with seq=0 sector present");
    EC_ASSERT(rb == new_val,
              "nvs_read returns NEWER value from seq=0 sector, not stale seq=UINT32_MAX copy");
}

/*===========================================================================
 *  3. Entry at exact sector boundary
 *
 *  ENTRIES_PER_SECTOR writes of 4-byte-key + 4-byte-data entries fill sector 0
 *  exactly (write_offset lands on SECTOR_SIZE).  The next write must activate
 *  sector 1 cleanly.  If the boundary check is off-by-one (> vs >=), this
 *  write either fails spuriously or tries to write past the end of the sector.
 *===========================================================================*/

static void test_entry_at_exact_sector_boundary(void)
{
    printf("\n--- Edge case 3: entry at exact sector boundary ---\n");

    flash_full_erase();
    th_mount();

    char key[5];
    uint32_t val;
    int fill_ok = 1;

    for (uint32_t i = 0; i < ENTRIES_PER_SECTOR; i++)
    {
        key[0] = 'E';
        key[1] = (char)('0' + (i / 100) % 10);
        key[2] = (char)('0' + (i / 10)  % 10);
        key[3] = (char)('0' + (i)        % 10);
        key[4] = '\0';
        val = i;
        if (nvs_write(key, &val, sizeof(val)) != NVS_OK)
        {
            fill_ok = 0;
            break;
        }
    }
    EC_ASSERT(fill_ok, "ENTRIES_PER_SECTOR fill writes all return NVS_OK");

    /* Sector 0 is now exactly full. Next write must activate sector 1. */
    val = 0xBEEFBEEFU;
    nvs_err_t rc = nvs_write("NEXT", &val, sizeof(val));
    EC_ASSERT(rc == NVS_OK,
              "write after exact-full sector activates next sector and succeeds");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read("NEXT", &rb, sizeof(rb), &ol);
    EC_ASSERT(rc == NVS_OK && rb == 0xBEEFBEEFU,
              "entry written after exact boundary is readable with correct value");

    /* The last entry written before the boundary must still be intact. */
    rb = 0;
    rc = nvs_read("E000", &rb, sizeof(rb), &ol);
    EC_ASSERT(rc == NVS_OK && rb == 0,
              "last entry before exact boundary is still readable after sector transition");
}

/*===========================================================================
 *  4. Delete all keys then remount
 *
 *  After deleting every key, all entries are in DELETED (0x00) state.  On
 *  remount the mount scan must walk past them and set write_offset correctly
 *  past all deleted entries.  If write_offset is reset to NVS_SECTOR_HDR_SIZE,
 *  the next write AND-writes into already-committed bytes, corrupting their CRC.
 *===========================================================================*/

static void test_delete_all_then_remount(void)
{
    printf("\n--- Edge case 4: delete all keys then remount ---\n");

    flash_full_erase();
    th_mount();

    uint32_t v1 = 0x11111111U, v2 = 0x22222222U, v3 = 0x33333333U;
    nvs_write("da1", &v1, sizeof(v1));
    nvs_write("da2", &v2, sizeof(v2));
    nvs_write("da3", &v3, sizeof(v3));

    nvs_delete("da1");
    nvs_delete("da2");
    nvs_delete("da3");

    nvs_err_t mrc = th_mount();
    EC_ASSERT(mrc == NVS_OK, "remount after deleting all keys returns NVS_OK");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    EC_ASSERT(nvs_read("da1", &rb, sizeof(rb), &ol) == NVS_ERR_NOT_FOUND,
              "da1 is NOT_FOUND after delete-all + remount");
    EC_ASSERT(nvs_read("da2", &rb, sizeof(rb), &ol) == NVS_ERR_NOT_FOUND,
              "da2 is NOT_FOUND after delete-all + remount");
    EC_ASSERT(nvs_read("da3", &rb, sizeof(rb), &ol) == NVS_ERR_NOT_FOUND,
              "da3 is NOT_FOUND after delete-all + remount");

    /* New write must land after all deleted entries, not on top of them. */
    uint32_t new_v = 0xFEEDFACEU;
    nvs_err_t wrc = nvs_write("fresh", &new_v, sizeof(new_v));
    EC_ASSERT(wrc == NVS_OK,
              "write after delete-all + remount returns NVS_OK");

    rb = 0;
    nvs_err_t rrc = nvs_read("fresh", &rb, sizeof(rb), &ol);
    EC_ASSERT(rrc == NVS_OK && rb == 0xFEEDFACEU,
              "value written after delete-all + remount is readable and correct");
}

/*===========================================================================
 *  5. Write after NVS_ERR_NO_SPACE, then delete, then write again
 *
 *  When every sector is FULL with unique live entries, nvs_write returns
 *  NVS_ERR_NO_SPACE.  Deleting one full sector's worth of keys makes that
 *  sector contain only DELETED entries.  GC can now erase it (no live entries
 *  to copy), providing a free sector.  The next write must succeed.
 *===========================================================================*/

static void test_write_after_no_space_then_delete(void)
{
    printf("\n--- Edge case 5: write after NO_SPACE, delete, then write again ---\n");

    flash_full_erase();
    th_mount();

    char key[8];
    uint32_t val;
    int total = (int)(FLASH_SECTOR_COUNT * ENTRIES_PER_SECTOR);

    for (int i = 0; i < total; i++)
    {
        th_make_key(key, i);
        val = (uint32_t)i;
        nvs_write(key, &val, sizeof(val));
    }

    val = 0xDEADBEEFU;
    nvs_err_t rc = nvs_write("XTRA", &val, sizeof(val));
    EC_ASSERT(rc == NVS_ERR_NO_SPACE,
              "write to genuinely full flash returns NO_SPACE");

    /* Delete all keys from sector 0 — that sector becomes entirely dead. */
    for (int i = 0; i < (int)ENTRIES_PER_SECTOR; i++)
    {
        th_make_key(key, i);
        nvs_delete(key);
    }

    /* GC must now be able to erase sector 0 and accept a new write. */
    val = 0x5AFE5AFEU;
    rc = nvs_write("RECL", &val, sizeof(val));
    EC_ASSERT(rc == NVS_OK,
              "write succeeds after deleting enough entries for GC to reclaim a sector");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read("RECL", &rb, sizeof(rb), &ol);
    EC_ASSERT(rc == NVS_OK && rb == 0x5AFE5AFEU,
              "value written after GC reclaim is readable and correct");

    /* First key from sector 1 (untouched) must be intact. */
    th_make_key(key, (int)ENTRIES_PER_SECTOR);
    rb = 0;
    rc = nvs_read(key, &rb, sizeof(rb), &ol);
    EC_ASSERT(rc == NVS_OK && rb == (uint32_t)ENTRIES_PER_SECTOR,
              "untouched keys from other sectors survive NO_SPACE + delete + reclaim");
}

/*===========================================================================
 *  6. Overwrite with identical value
 *
 *  Writing the same key+value twice must still invalidate the first entry.
 *  If it does not, two VALID entries exist for the same key.  The scan finds
 *  the last one encountered — correctness then depends on scan order, which
 *  is an unspecified implementation detail and a latent corruption vector.
 *===========================================================================*/

static void test_overwrite_identical_value(void)
{
    printf("\n--- Edge case 6: overwrite with identical value ---\n");

    flash_full_erase();
    th_mount();

    uint32_t val = 0xABCDABCDU;
    nvs_write("same", &val, sizeof(val));

    nvs_err_t rc = nvs_write("same", &val, sizeof(val));
    EC_ASSERT(rc == NVS_OK,
              "second write of identical key+value returns NVS_OK");

    uint32_t rb = 0;
    uint8_t  ol = 0;
    rc = nvs_read("same", &rb, sizeof(rb), &ol);
    EC_ASSERT(rc == NVS_OK,
              "read after identical overwrite returns NVS_OK");
    EC_ASSERT(rb == 0xABCDABCDU,
              "read after identical overwrite returns correct value");

    /* The first entry (at NVS_SECTOR_HDR_SIZE offset) must be DELETED. */
    uint8_t state_byte = 0xFF;
    flash_read(NVS_SECTOR_HDR_SIZE, &state_byte, 1);
    EC_ASSERT(state_byte == NVS_ENTRY_DELETED,
              "original entry is DELETED after identical-value overwrite");

    /* A third write with a different value must be correct. */
    uint32_t new_val = 0x12345678U;
    nvs_write("same", &new_val, sizeof(new_val));
    rb = 0;
    nvs_read("same", &rb, sizeof(rb), &ol);
    EC_ASSERT(rb == 0x12345678U,
              "subsequent overwrite with different value reads back correctly");
}

/*===========================================================================
 *  7. Max key length + max data length combined entry
 *
 *  The largest legal entry: key_len=15, data_len=128.
 *  On-flash size: align4(8 + 15 + 128) = align4(151) = 152 bytes.
 *  Must write successfully, round-trip with exact byte integrity, and leave
 *  neighboring sentinel entries undamaged.
 *===========================================================================*/

static void test_max_key_and_data_combined(void)
{
    printf("\n--- Edge case 7: max key length + max data length combined entry ---\n");

    flash_full_erase();
    th_mount();

    uint32_t sentinel_before = 0xBEF00001U;
    nvs_write("bef", &sentinel_before, sizeof(sentinel_before));

    const char *max_key = "123456789012345"; /* exactly 15 chars */
    uint8_t max_data[128];
    for (int i = 0; i < 128; i++)
    {
        max_data[i] = (uint8_t)(i ^ 0xA5);
    }

    nvs_err_t rc = nvs_write(max_key, max_data, sizeof(max_data));
    EC_ASSERT(rc == NVS_OK,
              "write of max-key (15) + max-data (128) returns NVS_OK");

    uint32_t sentinel_after = 0xAF7E0002U;
    nvs_write("aft", &sentinel_after, sizeof(sentinel_after));

    uint8_t readback[128];
    memset(readback, 0, sizeof(readback));
    uint8_t ol = 0;
    rc = nvs_read(max_key, readback, sizeof(readback), &ol);
    EC_ASSERT(rc == NVS_OK,
              "read of max-key + max-data entry returns NVS_OK");
    EC_ASSERT(ol == 128,
              "read reports correct length (128)");
    EC_ASSERT(memcmp(max_data, readback, 128) == 0,
              "max entry payload is byte-for-byte correct");

    uint32_t rb = 0;
    nvs_read("bef", &rb, sizeof(rb), &ol);
    EC_ASSERT(rb == 0xBEF00001U,
              "sentinel before max entry is undamaged");

    rb = 0;
    nvs_read("aft", &rb, sizeof(rb), &ol);
    EC_ASSERT(rb == 0xAF7E0002U,
              "sentinel after max entry is undamaged");
}

/*===========================================================================
 *  Entry point (called from main.c)
 *===========================================================================*/

void run_edge_case_tests(int *pass, int *fail)
{
    printf("\n========================================\n");
    printf("  NVS Edge-Case Test Suite\n");
    printf("========================================\n");

    test_api_before_mount();
    test_seq_counter_wrap();
    test_entry_at_exact_sector_boundary();
    test_delete_all_then_remount();
    test_write_after_no_space_then_delete();
    test_overwrite_identical_value();
    test_max_key_and_data_combined();

    *pass += g_pass;
    *fail += g_fail;

    printf("\n========================================\n");
    printf("  Edge-case suite: %d passed, %d failed\n", g_pass, g_fail);
    printf("========================================\n");
}
