/**
 * @file main.c
 * @brief NVS smoke-test: exercises init, integer set/get, string set/get,
 *        blob set/get, key update (logical overwrite), erase_key, GC trigger,
 *        and cross-namespace isolation.
 *
 * Flash adapter: the test connects the in-process flash_mem simulator to the
 * nvs_config_t function pointers, so no real hardware is needed.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "flash_mem/flash_mem.h"
#include "nvs_lite/nvs_lite.h"

/* -----------------------------------------------------------------------
 * Flash adapter — bridges nvs_config_t to flash_mem.h
 *
 * flash_mem functions are void (they print to stderr on error), so the
 * adapters always return 0.  On real hardware these would propagate the
 * hardware error code.
 * --------------------------------------------------------------------- */

static int adapter_read(uint32_t addr, void *buf, uint32_t len)
{
    flash_read(addr, buf, (uint16_t)len);
    return 0;
}

static int adapter_write(uint32_t addr, const void *buf, uint32_t len)
{
    flash_write(addr, buf, (uint16_t)len);
    return 0;
}

static int adapter_erase(uint32_t addr)
{
    flash_erase_sector(addr);
    return 0;
}

/* -----------------------------------------------------------------------
 * Test helpers
 * --------------------------------------------------------------------- */

#define TEST(name)  do { printf("\n[TEST] %s\n", (name)); } while (0)
#define PASS()      do { printf("  PASS\n"); } while (0)
#define FAIL(msg)   do { printf("  FAIL: %s\n", (msg)); return 1; } while (0)

/**
 * CHECK(expr) — evaluates expr, expects it to be NVS_OK (0).
 * Any non-zero return is treated as a failure.
 */
#define CHECK(expr)                                                     \
    do {                                                                \
        int _rc = (expr);                                               \
        if (_rc != NVS_OK)                                              \
        {                                                               \
            printf("  FAIL: %s  (rc=%d)\n", #expr, _rc);               \
            return 1;                                                   \
        }                                                               \
    } while (0)

/**
 * CHECK_EQ(expr, expected) — evaluates expr, expects it to equal expected.
 */
#define CHECK_EQ(expr, expected)                                        \
    do {                                                                \
        int _rc = (int)(expr);                                          \
        if (_rc != (int)(expected))                                     \
        {                                                               \
            printf("  FAIL: %s  (got %d, expected %d)\n",              \
                   #expr, _rc, (int)(expected));                        \
            return 1;                                                   \
        }                                                               \
    } while (0)

/* -----------------------------------------------------------------------
 * Tests
 * --------------------------------------------------------------------- */

static int test_init(nvs_config_t *cfg)
{
    TEST("nvs_init on blank flash");

    flash_full_erase();
    int rc = nvs_init(cfg);
    if (rc != NVS_OK)
    {
        printf("  nvs_init returned %d\n", rc);
        return 1;
    }
    PASS();
    return 0;
}

static int test_integer_set_get(void)
{
    TEST("Integer set / get — all types");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h));

    /* u8 */
    CHECK(nvs_set_u8(h, "boot_cnt", 42u));
    uint8_t u8v = 0;
    CHECK(nvs_get_u8(h, "boot_cnt", &u8v));
    CHECK_EQ(u8v, 42u);

    /* i8 */
    CHECK(nvs_set_i8(h, "temp_off", -5));
    int8_t i8v = 0;
    CHECK(nvs_get_i8(h, "temp_off", &i8v));
    CHECK_EQ(i8v, -5);

    /* u16 */
    CHECK(nvs_set_u16(h, "interval", 5000u));
    uint16_t u16v = 0;
    CHECK(nvs_get_u16(h, "interval", &u16v));
    CHECK_EQ(u16v, 5000u);

    /* i16 */
    CHECK(nvs_set_i16(h, "altitude", -300));
    int16_t i16v = 0;
    CHECK(nvs_get_i16(h, "altitude", &i16v));
    CHECK_EQ(i16v, -300);

    /* u32 */
    CHECK(nvs_set_u32(h, "uid", 0xDEADBEEFu));
    uint32_t u32v = 0;
    CHECK(nvs_get_u32(h, "uid", &u32v));
    CHECK_EQ((int)u32v, (int)0xDEADBEEFu);

    /* i32 */
    CHECK(nvs_set_i32(h, "latitude", -33750000));
    int32_t i32v = 0;
    CHECK(nvs_get_i32(h, "latitude", &i32v));
    CHECK_EQ(i32v, -33750000);

    /* u64 */
    CHECK(nvs_set_u64(h, "epoch", 0x000000600F00D000ULL));
    uint64_t u64v = 0;
    CHECK(nvs_get_u64(h, "epoch", &u64v));
    if (u64v != 0x000000600F00D000ULL)
    {
        printf("  FAIL: u64 mismatch (got 0x%016llX)\n",
               (unsigned long long)u64v);
        return 1;
    }

    /* i64 */
    CHECK(nvs_set_i64(h, "offset_ns", -123456789012LL));
    int64_t i64v = 0;
    CHECK(nvs_get_i64(h, "offset_ns", &i64v));
    if (i64v != -123456789012LL)
    {
        printf("  FAIL: i64 mismatch (got %lld)\n", (long long)i64v);
        return 1;
    }

    CHECK(nvs_commit(h));
    nvs_close(h);
    PASS();
    return 0;
}

static int test_string_set_get(void)
{
    TEST("String set / get (single and multi-entry)");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h));

    /* Short string — fits in 1 continuation slot */
    const char *short_str = "Hello, NVS!";
    CHECK(nvs_set_str(h, "greeting", short_str));

    char   buf[256];
    size_t len = sizeof(buf);
    CHECK(nvs_get_str(h, "greeting", buf, &len));
    if (strcmp(buf, short_str) != 0)
    {
        printf("  FAIL: greeting mismatch: \"%s\"\n", buf);
        return 1;
    }
    printf("  greeting = \"%s\"\n", buf);

    /* Long string — spans multiple entries */
    const char *long_str =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs. "
        "How vainly men themselves amaze...";

    CHECK(nvs_set_str(h, "quote", long_str));

    memset(buf, 0, sizeof(buf));
    len = sizeof(buf);
    CHECK(nvs_get_str(h, "quote", buf, &len));
    if (strcmp(buf, long_str) != 0)
    {
        printf("  FAIL: quote mismatch\n");
        return 1;
    }
    printf("  quote length = %zu\n", len);

    /* Query mode: buf=NULL returns required size */
    size_t req_len = 0;
    CHECK(nvs_get_str(h, "quote", NULL, &req_len));
    if (req_len != strlen(long_str) + 1u)
    {
        printf("  FAIL: query length %zu != %zu\n",
               req_len, strlen(long_str) + 1u);
        return 1;
    }

    CHECK(nvs_commit(h));
    nvs_close(h);
    PASS();
    return 0;
}

static int test_blob_set_get(void)
{
    TEST("Blob set / get");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h));

    const uint8_t src[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
    };

    CHECK(nvs_set_blob(h, "cal_data", src, sizeof(src)));

    /* Query size */
    size_t sz = 0;
    CHECK(nvs_get_blob(h, "cal_data", NULL, &sz));
    if (sz != sizeof(src))
    {
        printf("  FAIL: blob size query %zu != %zu\n", sz, sizeof(src));
        return 1;
    }

    /* Read back */
    uint8_t dst[64];
    memset(dst, 0, sizeof(dst));
    sz = sizeof(dst);
    CHECK(nvs_get_blob(h, "cal_data", dst, &sz));
    if (memcmp(src, dst, sizeof(src)) != 0)
    {
        printf("  FAIL: blob data mismatch\n");
        return 1;
    }
    printf("  blob round-trip OK (%zu bytes)\n", sz);

    nvs_close(h);
    PASS();
    return 0;
}

static int test_key_update(void)
{
    TEST("Key update — old entry logically erased, new value readable");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h));

    CHECK(nvs_set_i32(h, "counter", 1));
    CHECK(nvs_set_i32(h, "counter", 2));
    CHECK(nvs_set_i32(h, "counter", 3));
    CHECK(nvs_set_i32(h, "counter", 42));

    int32_t val = 0;
    CHECK(nvs_get_i32(h, "counter", &val));
    CHECK_EQ(val, 42);
    printf("  counter = %d  (expected 42)\n", val);

    nvs_close(h);
    PASS();
    return 0;
}

static int test_erase_key(void)
{
    TEST("nvs_erase_key — key disappears after erase");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h));

    CHECK(nvs_set_u32(h, "token", 0xCAFEBABEu));
    CHECK(nvs_erase_key(h, "token"));

    uint32_t v  = 0;
    int      rc = nvs_get_u32(h, "token", &v);
    CHECK_EQ(rc, NVS_ERR_NOT_FOUND);

    nvs_close(h);
    PASS();
    return 0;
}

static int test_cross_namespace_isolation(void)
{
    TEST("Cross-namespace isolation — same key, different namespaces");

    nvs_handle_t h1, h2;
    CHECK(nvs_open("ns_alpha", NVS_READWRITE, &h1));
    CHECK(nvs_open("ns_beta",  NVS_READWRITE, &h2));

    CHECK(nvs_set_u32(h1, "shared_key", 0xAAAAAAAAu));
    CHECK(nvs_set_u32(h2, "shared_key", 0xBBBBBBBBu));

    uint32_t v1 = 0, v2 = 0;
    CHECK(nvs_get_u32(h1, "shared_key", &v1));
    CHECK(nvs_get_u32(h2, "shared_key", &v2));
    CHECK_EQ((int)v1, (int)0xAAAAAAAAu);
    CHECK_EQ((int)v2, (int)0xBBBBBBBBu);
    printf("  ns_alpha:shared_key = 0x%08X\n", v1);
    printf("  ns_beta:shared_key  = 0x%08X\n", v2);

    nvs_close(h1);
    nvs_close(h2);
    PASS();
    return 0;
}

static int test_gc_trigger(nvs_config_t *cfg)
{
    TEST("Garbage Collection — fill partition, verify data survives");

    /*
     * Re-init on a fresh flash image to have a known clean state.
     * sector_size=4096 and num_sectors=4 gives a small partition that
     * fills quickly, forcing GC to run.
     */
    nvs_config_t small_cfg  = *cfg;
    small_cfg.sector_size   = 4096u;
    small_cfg.num_sectors   = 4u;
    small_cfg.base_address  = 0u;

    flash_full_erase();
    CHECK(nvs_init(&small_cfg));

    nvs_handle_t h;
    CHECK(nvs_open("gc_ns", NVS_READWRITE, &h));

    /* Write a key we want to survive GC */
    CHECK(nvs_set_u32(h, "survivor", 0x12345678u));

    /*
     * Fill the partition by repeatedly updating a key.  Each update
     * writes a new entry and marks the old one as Erased, consuming
     * slots until GC is forced.
     */
    const int ITERATIONS = 800;
    for (int i = 0; i < ITERATIONS; i++)
    {
        int rc = nvs_set_u32(h, "filler", (uint32_t)i);
        if (rc != NVS_OK)
        {
            printf("  nvs_set_u32 at iter %d returned %d\n", i, rc);
            nvs_close(h);
            return 1;
        }
    }

    /* Verify the survivor key is still readable after GC */
    uint32_t sv = 0;
    CHECK(nvs_get_u32(h, "survivor", &sv));
    if (sv != 0x12345678u)
    {
        printf("  FAIL: survivor = 0x%08X (expected 0x12345678)\n", sv);
        nvs_close(h);
        return 1;
    }
    printf("  survivor = 0x%08X  (GC preserved it)\n", sv);

    /* Verify the most recent filler value */
    uint32_t fv = 0;
    CHECK(nvs_get_u32(h, "filler", &fv));
    if (fv != (uint32_t)(ITERATIONS - 1))
    {
        printf("  FAIL: filler = %u (expected %d)\n", fv, ITERATIONS - 1);
        nvs_close(h);
        return 1;
    }
    printf("  filler   = %u  (expected %d)\n", fv, ITERATIONS - 1);

    nvs_close(h);

    /* Restore config for subsequent tests */
    flash_full_erase();
    CHECK(nvs_init(cfg));

    PASS();
    return 0;
}

static int test_reinit_persistence(const nvs_config_t *cfg)
{
    TEST("Persistence — data survives re-init (simulated reboot)");

    /* Use the same 4 KB geometry as test_gc_trigger */
    static nvs_config_t small_cfg;
    small_cfg.base_address = 0u;
    small_cfg.sector_size  = 4096u;
    small_cfg.num_sectors  = 4u;
    small_cfg.read         = cfg->read;
    small_cfg.write        = cfg->write;
    small_cfg.erase        = cfg->erase;

    nvs_handle_t h;
    CHECK(nvs_open("persist", NVS_READWRITE, &h));
    CHECK(nvs_set_u32(h, "magic", 0xDEADBEEFu));
    CHECK(nvs_set_str(h, "name", "PersistenceRecord"));
    nvs_close(h);

    /* Simulated reboot: re-init with the same config (flash unchanged) */
    CHECK(nvs_init(&small_cfg));

    CHECK(nvs_open("persist", NVS_READONLY, &h));

    uint32_t magic = 0;
    CHECK(nvs_get_u32(h, "magic", &magic));
    if (magic != 0xDEADBEEFu)
    {
        FAIL("magic mismatch after reboot");
    }

    char   name[32];
    size_t len = sizeof(name);
    CHECK(nvs_get_str(h, "name", name, &len));
    if (strcmp(name, "PersistenceRecord") != 0)
    {
        FAIL("name mismatch after reboot");
    }

    nvs_close(h);
    PASS();
    return 0;
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */

int main(void)
{
    printf("========================================\n");
    printf("  NVS-Lite Smoke Test\n");
    printf("========================================\n");

    nvs_config_t cfg =
    {
        .sector_size  = FLASH_SECTOR_SIZE,
        .num_sectors  = 8u,
        .base_address = 0u,
        .read         = adapter_read,
        .write        = adapter_write,
        .erase        = adapter_erase,
    };

    int failures = 0;

    failures += test_init(&cfg);
    failures += test_integer_set_get();
    failures += test_string_set_get();
    failures += test_blob_set_get();
    failures += test_key_update();
    failures += test_erase_key();
    failures += test_cross_namespace_isolation();
    failures += test_gc_trigger(&cfg);
    failures += test_reinit_persistence(&cfg);

    printf("\n========================================\n");
    if (failures == 0)
    {
        printf("  ALL TESTS PASSED\n");
    }
    else
    {
        printf("  %d TEST(S) FAILED\n", failures);
    }
    printf("========================================\n");

    return (failures == 0) ? 0 : 1;
}
