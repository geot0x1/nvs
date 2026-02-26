
#include "flash_mem.h"
#include "nvs.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*===========================================================================
 *  Test helpers
 *===========================================================================*/

static int g_pass = 0;
static int g_fail = 0;

#define TEST_ASSERT(cond, msg)                                 \
    do                                                         \
    {                                                          \
        if (cond)                                              \
        {                                                      \
            printf("  [PASS] %s\n", (msg));                    \
            g_pass++;                                          \
        }                                                      \
        else                                                   \
        {                                                      \
            printf("  [FAIL] %s  (line %d)\n", (msg), __LINE__); \
            g_fail++;                                          \
        }                                                      \
    } while (0)

/** Build the flash driver struct and call nvs_mount(). */
static nvs_err_t test_mount_nvs(void)
{
    nvs_flash_driver_t drv;
    drv.write        = flash_write;
    drv.read         = flash_read;
    drv.erase_sector = flash_erase_sector;
    drv.sector_size  = FLASH_SECTOR_SIZE;
    drv.sector_count = FLASH_SECTOR_COUNT;
    return nvs_mount(&drv);
}

/*===========================================================================
 *  Test cases
 *===========================================================================*/

static void test_mount_on_blank_flash(void)
{
    printf("\n--- Test: Mount on blank flash ---\n");
    flash_full_erase();
    nvs_err_t rc = test_mount_nvs();
    TEST_ASSERT(rc == NVS_OK, "nvs_mount on erased flash returns NVS_OK");
}

static void test_write_and_read(void)
{
    printf("\n--- Test: Write and read back ---\n");

    const char *key = "sensor1";
    uint32_t value = 42;

    nvs_err_t rc = nvs_write(key, &value, sizeof(value));
    TEST_ASSERT(rc == NVS_OK, "nvs_write returns NVS_OK");

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    rc = nvs_read(key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "nvs_read returns NVS_OK");
    TEST_ASSERT(out_len == sizeof(value), "Read length matches write length");
    TEST_ASSERT(readback == 42, "Read value matches written value (42)");
}

static void test_write_string(void)
{
    printf("\n--- Test: Write and read a string ---\n");

    const char *key = "greeting";
    const char *msg = "Hello, NVS!";
    uint8_t msg_len = (uint8_t)(strlen(msg) + 1); /* include null terminator */

    nvs_err_t rc = nvs_write(key, msg, msg_len);
    TEST_ASSERT(rc == NVS_OK, "nvs_write string returns NVS_OK");

    char buf[64] = {0};
    uint8_t out_len = 0;
    rc = nvs_read(key, buf, sizeof(buf), &out_len);
    TEST_ASSERT(rc == NVS_OK, "nvs_read string returns NVS_OK");
    TEST_ASSERT(strcmp(buf, msg) == 0, "Read string matches written string");
}

static void test_overwrite_key(void)
{
    printf("\n--- Test: Overwrite existing key ---\n");

    const char *key = "counter";
    uint32_t v1 = 100;
    uint32_t v2 = 200;

    nvs_write(key, &v1, sizeof(v1));
    nvs_write(key, &v2, sizeof(v2));

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    nvs_err_t rc = nvs_read(key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "nvs_read after overwrite returns NVS_OK");
    TEST_ASSERT(readback == 200, "Read returns latest value (200), not old (100)");
}

static void test_delete_key(void)
{
    printf("\n--- Test: Delete key ---\n");

    const char *key = "temp";
    uint16_t value = 1234;

    nvs_write(key, &value, sizeof(value));

    nvs_err_t rc = nvs_delete(key);
    TEST_ASSERT(rc == NVS_OK, "nvs_delete returns NVS_OK");

    uint16_t readback = 0;
    uint8_t  out_len  = 0;
    rc = nvs_read(key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_ERR_NOT_FOUND, "nvs_read after delete returns NOT_FOUND");
}

static void test_read_nonexistent(void)
{
    printf("\n--- Test: Read nonexistent key ---\n");

    uint8_t buf[16];
    uint8_t out_len = 0;
    nvs_err_t rc = nvs_read("nokey", buf, sizeof(buf), &out_len);
    TEST_ASSERT(rc == NVS_ERR_NOT_FOUND, "Reading non-existent key returns NOT_FOUND");
}

static void test_sector_skip_logic(void)
{
    printf("\n--- Test: Sector boundary skip logic ---\n");

    /* Start with a fresh flash. */
    flash_full_erase();
    test_mount_nvs();

    /*
     * Fill the first sector with many writes.
     * Each entry: 8 B header + 4 B key + 4 B data = 16 B (already aligned).
     * Sector usable space: 4096 - 12 (header) = 4084 bytes.
     * Number of 16-B entries that fit: 4084 / 16 = 255 (with 4 bytes left).
     *
     * After 255 writes, there are only 4 bytes left — not enough for
     * any new entry (min 12 B). The next write must skip to sector 1.
     */
    char key[5];
    uint32_t val;

    int writes_ok = 1;
    for (int i = 0; i < 255; i++)
    {
        /* Generate unique 4-char keys: "K000" .. "K254" */
        key[0] = 'K';
        key[1] = '0' + (char)(i / 100);
        key[2] = '0' + (char)((i / 10) % 10);
        key[3] = '0' + (char)(i % 10);
        key[4] = '\0';
        val = (uint32_t)i;

        nvs_err_t rc = nvs_write(key, &val, sizeof(val));
        if (rc != NVS_OK)
        {
            writes_ok = 0;
            break;
        }
    }
    TEST_ASSERT(writes_ok, "255 entries written to fill first sector");

    /* This write should trigger the skip to sector 1. */
    const char *overflow_key = "OVER";
    uint32_t overflow_val = 9999;
    nvs_err_t rc = nvs_write(overflow_key, &overflow_val, sizeof(overflow_val));
    TEST_ASSERT(rc == NVS_OK, "Write that triggers sector skip succeeds");

    /* Verify we can still read it back. */
    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    rc = nvs_read(overflow_key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read from new sector returns NVS_OK");
    TEST_ASSERT(readback == 9999, "Overflow entry value is correct (9999)");
}

static void test_garbage_collection(void)
{
    printf("\n--- Test: Garbage collection ---\n");

    /* Start fresh. */
    flash_full_erase();
    test_mount_nvs();

    /*
     * We have 3 sectors.  Strategy:
     *   1. Fill sector 0 with entries for key "A".
     *   2. Sector 0 becomes Full, sector 1 becomes Active.
     *   3. Fill sector 1 with entries for key "B".
     *   4. Sector 1 becomes Full, sector 2 becomes Active.
     *   5. Now sectors 0 and 1 are Full, sector 2 is Active.
     *   6. Write a new "A" in sector 2 (supersedes all old "A"s).
     *   7. Next write that would need a new sector should trigger GC,
     *      erasing sector 0 (oldest, all "A"s invalidated).
     *
     * Use a single repeating key per sector so deletions are simple.
     */

    /* Fill sector 0 (255 entries of key "A"). */
    uint32_t val;
    for (int i = 0; i < 255; i++)
    {
        val = (uint32_t)i;
        nvs_write("AAAA", &val, sizeof(val));
    }

    /* Fill sector 1 (255 entries of key "B"). */
    for (int i = 0; i < 255; i++)
    {
        val = (uint32_t)(i + 1000);
        nvs_write("BBBB", &val, sizeof(val));
    }

    /* Now in sector 2. Write new "A" to supersede old ones. */
    val = 7777;
    nvs_write("AAAA", &val, sizeof(val));

    /* Write another value — this should work fine in sector 2. */
    val = 8888;
    nvs_err_t rc = nvs_write("CCCC", &val, sizeof(val));
    TEST_ASSERT(rc == NVS_OK, "Write after GC-eligible state succeeds");

    /* Verify "A" reads its newest value. */
    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    rc = nvs_read("AAAA", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read 'AAAA' returns NVS_OK");
    TEST_ASSERT(readback == 7777, "Read 'AAAA' returns latest value (7777)");

    /* Verify "B" reads its newest value. */
    readback = 0;
    rc = nvs_read("BBBB", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read 'BBBB' returns NVS_OK");
    TEST_ASSERT(readback == 1254, "Read 'BBBB' returns latest value (1254)");

    /* Now fill sector 2 to trigger GC. */
    for (int i = 0; i < 250; i++)
    {
        val = (uint32_t)(i + 5000);
        nvs_write("DDDD", &val, sizeof(val));
    }

    /* This write will need a new sector — GC should reclaim the oldest Full sector. */
    val = 42424;
    rc = nvs_write("POST", &val, sizeof(val));
    TEST_ASSERT(rc == NVS_OK, "Write that triggers GC succeeds");

    /* Verify the post-GC value. */
    readback = 0;
    rc = nvs_read("POST", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read post-GC entry returns NVS_OK");
    TEST_ASSERT(readback == 42424, "Post-GC entry value is correct (42424)");
}

static void test_remount_persistence(void)
{
    printf("\n--- Test: Remount persistence ---\n");

    /* Start fresh. */
    flash_full_erase();
    test_mount_nvs();

    const char *key = "persist";
    uint32_t value = 55555;
    nvs_write(key, &value, sizeof(value));

    /* Simulate reboot by re-mounting (flash data stays in RAM sim). */
    test_mount_nvs();

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    nvs_err_t rc = nvs_read(key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read after remount returns NVS_OK");
    TEST_ASSERT(readback == 55555, "Data survives remount (55555)");
}

static void test_invalid_arguments(void)
{
    printf("\n--- Test: Invalid arguments ---\n");

    flash_full_erase();
    test_mount_nvs();

    uint8_t dummy = 0;
    uint8_t out_len = 0;

    /* NULL key */
    TEST_ASSERT(nvs_write(NULL, &dummy, 1) == NVS_ERR_INVALID_ARG,
                "Write with NULL key returns INVALID_ARG");

    /* NULL data */
    TEST_ASSERT(nvs_write("k", NULL, 1) == NVS_ERR_INVALID_ARG,
                "Write with NULL data returns INVALID_ARG");

    /* Empty key */
    TEST_ASSERT(nvs_write("", &dummy, 1) == NVS_ERR_INVALID_ARG,
                "Write with empty key returns INVALID_ARG");

    /* Key too long (16 chars) */
    TEST_ASSERT(nvs_write("1234567890123456", &dummy, 1) == NVS_ERR_INVALID_ARG,
                "Write with 16-char key returns INVALID_ARG");

    /* Data too large (129 bytes) */
    uint8_t big[129];
    memset(big, 0xAB, sizeof(big));
    TEST_ASSERT(nvs_write("k", big, 129) == NVS_ERR_INVALID_ARG,
                "Write with 129-byte data returns INVALID_ARG");

    /* NULL args for read */
    TEST_ASSERT(nvs_read(NULL, &dummy, 1, &out_len) == NVS_ERR_INVALID_ARG,
                "Read with NULL key returns INVALID_ARG");
    TEST_ASSERT(nvs_read("k", NULL, 1, &out_len) == NVS_ERR_INVALID_ARG,
                "Read with NULL buf returns INVALID_ARG");
    TEST_ASSERT(nvs_read("k", &dummy, 1, NULL) == NVS_ERR_INVALID_ARG,
                "Read with NULL out_len returns INVALID_ARG");

    /* NULL key for delete */
    TEST_ASSERT(nvs_delete(NULL) == NVS_ERR_INVALID_ARG,
                "Delete with NULL key returns INVALID_ARG");
}

static void test_zero_length_data(void)
{
    printf("\n--- Test: Zero-length data ---\n");

    flash_full_erase();
    test_mount_nvs();

    /* Writing a key with 0-byte payload (like a flag / boolean marker). */
    uint8_t dummy = 0;
    nvs_err_t rc = nvs_write("flag", &dummy, 0);
    TEST_ASSERT(rc == NVS_OK, "Write zero-length data returns NVS_OK");

    uint8_t buf[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t out_len = 99;
    rc = nvs_read("flag", buf, sizeof(buf), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read zero-length data returns NVS_OK");
    TEST_ASSERT(out_len == 0, "Read reports out_len == 0");
}

static void test_max_size_payload(void)
{
    printf("\n--- Test: Max-size payload (128 bytes) ---\n");

    flash_full_erase();
    test_mount_nvs();

    uint8_t payload[128];
    for (int i = 0; i < 128; i++)
    {
        payload[i] = (uint8_t)(i & 0xFF);
    }

    nvs_err_t rc = nvs_write("big", payload, 128);
    TEST_ASSERT(rc == NVS_OK, "Write 128-byte payload returns NVS_OK");

    uint8_t readback[128];
    memset(readback, 0, sizeof(readback));
    uint8_t out_len = 0;
    rc = nvs_read("big", readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read 128-byte payload returns NVS_OK");
    TEST_ASSERT(out_len == 128, "Read reports out_len == 128");
    TEST_ASSERT(memcmp(payload, readback, 128) == 0,
                "128-byte payload data matches exactly");
}

static void test_max_length_key(void)
{
    printf("\n--- Test: Max-length key (15 chars) ---\n");

    flash_full_erase();
    test_mount_nvs();

    const char *long_key = "123456789012345"; /* exactly 15 chars */
    uint32_t value = 0xDEADBEEF;

    nvs_err_t rc = nvs_write(long_key, &value, sizeof(value));
    TEST_ASSERT(rc == NVS_OK, "Write with 15-char key returns NVS_OK");

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    rc = nvs_read(long_key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read with 15-char key returns NVS_OK");
    TEST_ASSERT(readback == 0xDEADBEEF, "Value matches (0xDEADBEEF)");
}

static void test_multiple_coexisting_keys(void)
{
    printf("\n--- Test: Multiple coexisting keys ---\n");

    flash_full_erase();
    test_mount_nvs();

    uint32_t v1 = 111, v2 = 222, v3 = 333, v4 = 444, v5 = 555;
    nvs_write("alpha", &v1, sizeof(v1));
    nvs_write("bravo", &v2, sizeof(v2));
    nvs_write("charlie", &v3, sizeof(v3));
    nvs_write("delta", &v4, sizeof(v4));
    nvs_write("echo", &v5, sizeof(v5));

    uint32_t rb = 0;
    uint8_t  ol = 0;

    nvs_read("alpha", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rb == 111, "Key 'alpha' reads 111");

    nvs_read("bravo", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rb == 222, "Key 'bravo' reads 222");

    nvs_read("charlie", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rb == 333, "Key 'charlie' reads 333");

    nvs_read("delta", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rb == 444, "Key 'delta' reads 444");

    nvs_read("echo", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rb == 555, "Key 'echo' reads 555");
}

static void test_write_after_delete(void)
{
    printf("\n--- Test: Write after delete (re-create key) ---\n");

    flash_full_erase();
    test_mount_nvs();

    uint32_t v1 = 100;
    nvs_write("reborn", &v1, sizeof(v1));
    nvs_delete("reborn");

    /* Re-create with a new value. */
    uint32_t v2 = 999;
    nvs_err_t rc = nvs_write("reborn", &v2, sizeof(v2));
    TEST_ASSERT(rc == NVS_OK, "Write after delete returns NVS_OK");

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    rc = nvs_read("reborn", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read re-created key returns NVS_OK");
    TEST_ASSERT(readback == 999, "Re-created key has new value (999)");
}

static void test_multiple_overwrites(void)
{
    printf("\n--- Test: Many sequential overwrites ---\n");

    flash_full_erase();
    test_mount_nvs();

    const char *key = "seq";
    uint32_t value;

    /* Write the same key 50 times with increasing values. */
    for (int i = 0; i < 50; i++)
    {
        value = (uint32_t)(i * 10);
        nvs_write(key, &value, sizeof(value));
    }

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    nvs_err_t rc = nvs_read(key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read after 50 overwrites returns NVS_OK");
    TEST_ASSERT(readback == 490, "Final overwrite value is correct (490)");
}

static void test_struct_storage(void)
{
    printf("\n--- Test: Struct storage ---\n");

    flash_full_erase();
    test_mount_nvs();

    typedef struct
    {
        uint16_t id;
        int32_t  temperature;
        uint8_t  flags;
    } sensor_data_t;

    sensor_data_t original;
    original.id          = 42;
    original.temperature = -1500;
    original.flags       = 0xAB;

    nvs_err_t rc = nvs_write("sens", &original, sizeof(original));
    TEST_ASSERT(rc == NVS_OK, "Write struct returns NVS_OK");

    sensor_data_t readback;
    memset(&readback, 0, sizeof(readback));
    uint8_t out_len = 0;
    rc = nvs_read("sens", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read struct returns NVS_OK");
    TEST_ASSERT(out_len == sizeof(sensor_data_t), "Struct size matches");
    TEST_ASSERT(readback.id == 42, "Struct field 'id' matches (42)");
    TEST_ASSERT(readback.temperature == -1500, "Struct field 'temperature' matches (-1500)");
    TEST_ASSERT(readback.flags == 0xAB, "Struct field 'flags' matches (0xAB)");
}

static void test_delete_nonexistent(void)
{
    printf("\n--- Test: Delete nonexistent key ---\n");

    flash_full_erase();
    test_mount_nvs();

    nvs_err_t rc = nvs_delete("ghost");
    TEST_ASSERT(rc == NVS_ERR_NOT_FOUND, "Deleting nonexistent key returns NOT_FOUND");
}

static void test_remount_after_sector_skip(void)
{
    printf("\n--- Test: Remount after sector skip ---\n");

    flash_full_erase();
    test_mount_nvs();

    /* Fill sector 0 completely. */
    char key[5];
    uint32_t val;
    for (int i = 0; i < 255; i++)
    {
        key[0] = 'K';
        key[1] = '0' + (char)(i / 100);
        key[2] = '0' + (char)((i / 10) % 10);
        key[3] = '0' + (char)(i % 10);
        key[4] = '\0';
        val = (uint32_t)i;
        nvs_write(key, &val, sizeof(val));
    }

    /* This goes to sector 1. */
    val = 12345;
    nvs_write("POST", &val, sizeof(val));

    /* Simulate reboot. */
    test_mount_nvs();

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    nvs_err_t rc = nvs_read("POST", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read after remount+sector skip returns NVS_OK");
    TEST_ASSERT(readback == 12345, "Value survives remount across sectors (12345)");

    /* Also verify an entry from sector 0 is still readable. */
    readback = 0;
    rc = nvs_read("K000", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Old sector entry readable after remount");
    TEST_ASSERT(readback == 0, "Old sector entry value correct (0)");
}

static void test_crc_corruption_detection(void)
{
    printf("\n--- Test: CRC corruption detection ---\n");

    flash_full_erase();
    test_mount_nvs();

    const char *key = "crc1";
    uint32_t value = 0xCAFEBABE;
    nvs_write(key, &value, sizeof(value));

    /*
     * The entry is at sector 0, offset 12 (right after the 12-byte header).
     * Entry layout: [state(1) key_len(1) data_len(1) rsv(1) crc(4) key(4) data(4)]
     * Data bytes start at offset 12 + 8 + 4 = 24.
     * Corrupt one byte of the data region.
     */
    uint8_t corrupt = 0x00;
    flash_write(24, &corrupt, 1);

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    nvs_err_t rc = nvs_read(key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_ERR_CRC, "Read of corrupted entry returns NVS_ERR_CRC");
}

static void test_torn_write_recovery(void)
{
    printf("\n--- Test: Torn write (power-loss) recovery ---\n");

    flash_full_erase();
    test_mount_nvs();

    /* Write a valid entry first. */
    const char *key = "good";
    uint32_t v1 = 111;
    nvs_write(key, &v1, sizeof(v1));

    /*
     * Simulate a torn write: manually craft an incomplete entry
     * directly in flash with state = 0xFF (WRITING).
     * This is what would happen if power was lost mid-write.
     *
     * The "good" entry is 16 bytes (8 hdr + 4 key + 4 data).
     * So the next free offset is 12 + 16 = 28.
     */
    uint8_t torn_entry[16];
    memset(torn_entry, 0xFF, sizeof(torn_entry));
    torn_entry[0] = 0xFF;  /* state = WRITING (incomplete) */
    torn_entry[1] = 4;     /* key_len = 4 */
    torn_entry[2] = 4;     /* data_len = 4 */
    torn_entry[3] = 0xFF;  /* reserved */
    /* CRC and data are garbage — simulating partial write. */
    flash_write(28, torn_entry, sizeof(torn_entry));

    /* Simulate reboot — remount should skip the torn entry. */
    test_mount_nvs();

    /* The valid entry should still be readable. */
    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    nvs_err_t rc = nvs_read(key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Valid entry survives torn write + remount");
    TEST_ASSERT(readback == 111, "Valid entry value is correct (111)");

    /* The torn key should not be found (state was never committed to 0xFE). */
    rc = nvs_read("torn", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_ERR_NOT_FOUND, "Torn entry is not readable");

    /* We should be able to write new data after the torn entry position. */
    uint32_t v2 = 222;
    rc = nvs_write("new1", &v2, sizeof(v2));
    TEST_ASSERT(rc == NVS_OK, "Can write new data after torn entry recovery");
}

static void test_buffer_too_small(void)
{
    printf("\n--- Test: Buffer too small on read ---\n");

    flash_full_erase();
    test_mount_nvs();

    uint32_t value = 12345678;
    nvs_write("big4", &value, sizeof(value));  /* writes 4 bytes */

    /* Try to read into a 2-byte buffer — should fail. */
    uint8_t small_buf[2];
    uint8_t out_len = 0;
    nvs_err_t rc = nvs_read("big4", small_buf, sizeof(small_buf), &out_len);
    TEST_ASSERT(rc == NVS_ERR_INVALID_ARG,
                "Read with undersized buffer returns INVALID_ARG");
}

static void test_gc_no_reclaimable_space(void)
{
    printf("\n--- Test: GC with no reclaimable space ---\n");

    flash_full_erase();
    test_mount_nvs();

    /*
     * Fill all 3 sectors with unique keys so no entry is superseded.
     * Each entry: 8 B header + 4 B key + 4 B data = 16 B.
     * Per sector: (4096 - 12) / 16 = 255 entries.
     * Total unique keys: 255 * 3 = 765.
     *
     * After filling sectors 0 and 1, sector 2 becomes Active.
     * Fill sector 2 too. The *next* write should fail with NO_SPACE
     * because GC can't reclaim any sector (all entries are live & unique).
     */
    char key[5];
    uint32_t val;
    int fills_ok = 1;

    for (int i = 0; i < 765; i++)
    {
        /* Generate unique 4-char keys: "A000" .. "A764" */
        key[0] = (char)('A' + (i / 255));
        key[1] = '0' + (char)((i % 255) / 100);
        key[2] = '0' + (char)(((i % 255) / 10) % 10);
        key[3] = '0' + (char)((i % 255) % 10);
        key[4] = '\0';
        val = (uint32_t)i;

        nvs_err_t rc = nvs_write(key, &val, sizeof(val));
        if (rc != NVS_OK)
        {
            fills_ok = 0;
            break;
        }
    }
    TEST_ASSERT(fills_ok, "765 unique entries written across 3 sectors");

    /* One more write should fail — flash is truly full. */
    val = 9999;
    nvs_err_t rc = nvs_write("FULL", &val, sizeof(val));
    TEST_ASSERT(rc == NVS_ERR_NO_SPACE,
                "Write when flash is truly full returns NVS_ERR_NO_SPACE");

    /* Verify existing data is still intact. */
    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    rc = nvs_read("A000", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Existing data survives failed write");
    TEST_ASSERT(readback == 0, "Existing data value is correct (0)");
}

static void test_key_prefix_collision(void)
{
    printf("\n--- Test: Key prefix collision ---\n");

    flash_full_erase();
    test_mount_nvs();

    /* Write two keys where one is a prefix of the other. */
    uint32_t v1 = 100;
    uint32_t v2 = 200;
    nvs_write("foo", &v1, sizeof(v1));
    nvs_write("foobar", &v2, sizeof(v2));

    uint32_t rb = 0;
    uint8_t  ol = 0;

    nvs_err_t rc = nvs_read("foo", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rc == NVS_OK, "Read 'foo' returns NVS_OK");
    TEST_ASSERT(rb == 100, "'foo' reads 100, not confused with 'foobar'");

    rb = 0;
    rc = nvs_read("foobar", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rc == NVS_OK, "Read 'foobar' returns NVS_OK");
    TEST_ASSERT(rb == 200, "'foobar' reads 200, not confused with 'foo'");

    /* Overwrite the shorter key — the longer one must not be affected. */
    v1 = 999;
    nvs_write("foo", &v1, sizeof(v1));

    rb = 0;
    rc = nvs_read("foobar", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rc == NVS_OK, "'foobar' still readable after overwriting 'foo'");
    TEST_ASSERT(rb == 200, "'foobar' still 200 after overwriting 'foo'");

    rb = 0;
    rc = nvs_read("foo", &rb, sizeof(rb), &ol);
    TEST_ASSERT(rb == 999, "'foo' updated to 999");
}

static void test_remount_after_gc(void)
{
    printf("\n--- Test: Remount after GC ---\n");

    flash_full_erase();
    test_mount_nvs();

    /*
     * Fill sector 0 with the same key so all but one entry are superseded.
     * Then fill sector 1 similarly. At that point sector 0 is Full with
     * mostly deleted entries, and sector 1 is Full.  Writing into sector 2
     * forces GC on sector 0.  Then we remount.
     */
    uint32_t val;
    for (int i = 0; i < 255; i++)
    {
        val = (uint32_t)i;
        nvs_write("AAAA", &val, sizeof(val));
    }

    for (int i = 0; i < 255; i++)
    {
        val = (uint32_t)(i + 1000);
        nvs_write("BBBB", &val, sizeof(val));
    }

    /* Now in sector 2. Write a sentinel value. */
    val = 3333;
    nvs_write("CCCC", &val, sizeof(val));

    /* Fill sector 2 to trigger GC on sector 0. */
    for (int i = 0; i < 252; i++)
    {
        val = (uint32_t)(i + 5000);
        nvs_write("DDDD", &val, sizeof(val));
    }

    /* This should trigger sector skip + GC. */
    val = 6666;
    nvs_err_t rc = nvs_write("POST", &val, sizeof(val));
    TEST_ASSERT(rc == NVS_OK, "Write that triggers GC succeeds");

    /* Remount. */
    test_mount_nvs();

    uint32_t readback = 0;
    uint8_t  out_len  = 0;

    rc = nvs_read("POST", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "POST readable after GC + remount");
    TEST_ASSERT(readback == 6666, "POST value correct (6666)");

    rc = nvs_read("BBBB", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "BBBB readable after GC + remount");
    TEST_ASSERT(readback == 1254, "BBBB value correct (1254)");
}

static void test_delete_followed_by_gc(void)
{
    printf("\n--- Test: Delete followed by GC ---\n");

    flash_full_erase();
    test_mount_nvs();

    /*
     * Fill sector 0 with one key ("DEL1"), then delete it.
     * All entries in sector 0 are now Deleted.
     * Fill sector 1. Fill sector 2 to trigger GC on sector 0.
     * After GC, "DEL1" must NOT be resurrected — it should
     * remain NOT_FOUND.
     */
    uint32_t val;
    for (int i = 0; i < 255; i++)
    {
        val = (uint32_t)i;
        nvs_write("DEL1", &val, sizeof(val));
    }

    /* Delete it. All 255 entries in sector 0 become Deleted. */
    nvs_delete("DEL1");

    /* Fill sector 1 with a different key. */
    for (int i = 0; i < 255; i++)
    {
        val = (uint32_t)(i + 2000);
        nvs_write("KEEP", &val, sizeof(val));
    }

    /* Fill sector 2 to trigger GC on sector 0. */
    for (int i = 0; i < 253; i++)
    {
        val = (uint32_t)(i + 4000);
        nvs_write("FILL", &val, sizeof(val));
    }

    /* Trigger GC. */
    val = 8888;
    nvs_err_t rc = nvs_write("TRIG", &val, sizeof(val));
    TEST_ASSERT(rc == NVS_OK, "Write triggering GC after delete succeeds");

    /* DEL1 must still be gone — GC must NOT resurrect deleted entries. */
    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    rc = nvs_read("DEL1", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_ERR_NOT_FOUND,
                "Deleted key remains NOT_FOUND after GC");

    /* KEEP should survive. */
    rc = nvs_read("KEEP", &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Non-deleted key survives GC");
    TEST_ASSERT(readback == 2254, "Non-deleted key value correct (2254)");
}

static void test_repeated_gc_cycles(void)
{
    printf("\n--- Test: Repeated GC cycles (stress) ---\n");

    flash_full_erase();
    test_mount_nvs();

    /*
     * Stress test: write a small set of keys many times,
     * cycling through multiple GC rounds.  Each key is
     * overwritten ~800 times across ~3200 total writes.
     * With 3 sectors × 255 entries each, this forces
     * several GC cycles.
     */
    const char *keys[] = {"K1", "K2", "K3", "K4"};
    const int num_keys = 4;
    const int total_writes = 3200;
    int writes_ok = 1;
    uint32_t val;

    for (int i = 0; i < total_writes; i++)
    {
        val = (uint32_t)i;
        nvs_err_t rc = nvs_write(keys[i % num_keys], &val, sizeof(val));
        if (rc != NVS_OK)
        {
            printf("  [INFO] Write failed at iteration %d (rc=%d)\n", i, rc);
            writes_ok = 0;
            break;
        }
    }
    TEST_ASSERT(writes_ok, "3200 writes across multiple GC cycles succeed");

    /* Verify each key holds its most recent value. */
    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    int reads_ok = 1;

    for (int k = 0; k < num_keys; k++)
    {
        /* The most recent write to keys[k] was at iteration
           (total_writes - 1) rounded down to the last i where i%num_keys==k.
           Last write for K1(0): i=3196, K2(1): i=3197, K3(2): i=3198, K4(3): i=3199 */
        int last_i = total_writes - num_keys + k;

        nvs_err_t rc = nvs_read(keys[k], &readback, sizeof(readback), &out_len);
        if (rc != NVS_OK || readback != (uint32_t)last_i)
        {
            printf("  [INFO] Key '%s' expected %d got %u (rc=%d)\n",
                   keys[k], last_i, readback, rc);
            reads_ok = 0;
        }
    }
    TEST_ASSERT(reads_ok, "All keys hold correct final values after stress test");
}

/*===========================================================================
 *  Main
 *===========================================================================*/

int main(void)
{
    printf("========================================\n");
    printf("  NVS Module — Test Suite\n");
    printf("========================================\n");

    test_mount_on_blank_flash();
    test_write_and_read();
    test_write_string();
    test_overwrite_key();
    test_delete_key();
    test_read_nonexistent();
    test_sector_skip_logic();
    test_garbage_collection();
    test_remount_persistence();
    test_invalid_arguments();
    test_zero_length_data();
    test_max_size_payload();
    test_max_length_key();
    test_multiple_coexisting_keys();
    test_write_after_delete();
    test_multiple_overwrites();
    test_struct_storage();
    test_delete_nonexistent();
    test_remount_after_sector_skip();
    test_crc_corruption_detection();
    test_torn_write_recovery();
    test_buffer_too_small();
    test_gc_no_reclaimable_space();
    test_key_prefix_collision();
    test_remount_after_gc();
    test_delete_followed_by_gc();
    test_repeated_gc_cycles();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("========================================\n");

    return g_fail > 0 ? 1 : 0;
}
