
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

/*===========================================================================
 *  Test cases
 *===========================================================================*/

static void test_mount_on_blank_flash(void)
{
    printf("\n--- Test: Mount on blank flash ---\n");
    flash_full_erase();
    nvs_err_t rc = nvs_mount();
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
    nvs_mount();

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
    nvs_mount();

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
    nvs_mount();

    const char *key = "persist";
    uint32_t value = 55555;
    nvs_write(key, &value, sizeof(value));

    /* Simulate reboot by re-mounting (flash data stays in RAM sim). */
    nvs_mount();

    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    nvs_err_t rc = nvs_read(key, &readback, sizeof(readback), &out_len);
    TEST_ASSERT(rc == NVS_OK, "Read after remount returns NVS_OK");
    TEST_ASSERT(readback == 55555, "Data survives remount (55555)");
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

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed\n", g_pass, g_fail);
    printf("========================================\n");

    return g_fail > 0 ? 1 : 0;
}
