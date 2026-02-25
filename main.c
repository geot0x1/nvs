/**
 * @file main.c
 * @brief NVS smoke-test: exercises init, integer set/get, string set/get,
 *        key update (logical overwrite), erase_key, GC trigger, and
 *        cross-namespace isolation.
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

#define TEST(name)  do { printf("\n[TEST] %s\n", name); } while(0)
#define PASS()      do { printf("  PASS\n"); } while(0)
#define FAIL(msg)   do { printf("  FAIL: %s\n", msg); return 1; } while(0)
#define CHECK(expr) do { int _rc = (expr); if (_rc != 0 && _rc != 1) { printf("  FAIL: %s (rc=%d)\n", #expr, _rc); return 1; } else if (!_rc) { FAIL(#expr); } } while(0)

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
    TEST("Integer set / get all types");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h) == NVS_OK);

    /* u8 */
    CHECK(nvs_set_u8(h, "boot_cnt", 42u) == NVS_OK);
    uint8_t u8v = 0;
    CHECK(nvs_get_u8(h, "boot_cnt", &u8v) == NVS_OK);
    CHECK(u8v == 42u);

    /* i8 */
    CHECK(nvs_set_i8(h, "temp_off", -5) == NVS_OK);
    int8_t i8v = 0;
    CHECK(nvs_get_i8(h, "temp_off", &i8v) == NVS_OK);
    CHECK(i8v == -5);

    /* u16 */
    CHECK(nvs_set_u16(h, "interval", 5000u) == NVS_OK);
    uint16_t u16v = 0;
    CHECK(nvs_get_u16(h, "interval", &u16v) == NVS_OK);
    CHECK(u16v == 5000u);

    /* i16 */
    CHECK(nvs_set_i16(h, "altitude", -300) == NVS_OK);
    int16_t i16v = 0;
    CHECK(nvs_get_i16(h, "altitude", &i16v) == NVS_OK);
    CHECK(i16v == -300);

    /* u32 */
    CHECK(nvs_set_u32(h, "uid", 0xDEADBEEFu) == NVS_OK);
    uint32_t u32v = 0;
    CHECK(nvs_get_u32(h, "uid", &u32v) == NVS_OK);
    CHECK(u32v == 0xDEADBEEFu);

    /* i32 */
    CHECK(nvs_set_i32(h, "latitude", -33750000) == NVS_OK);
    int32_t i32v = 0;
    CHECK(nvs_get_i32(h, "latitude", &i32v) == NVS_OK);
    CHECK(i32v == -33750000);

    /* u64 */
    CHECK(nvs_set_u64(h, "epoch", 0x000000600F00D000ULL) == NVS_OK);
    uint64_t u64v = 0;
    CHECK(nvs_get_u64(h, "epoch", &u64v) == NVS_OK);
    CHECK(u64v == 0x000000600F00D000ULL);

    /* i64 */
    CHECK(nvs_set_i64(h, "offset_ns", -123456789012LL) == NVS_OK);
    int64_t i64v = 0;
    CHECK(nvs_get_i64(h, "offset_ns", &i64v) == NVS_OK);
    CHECK(i64v == -123456789012LL);

    CHECK(nvs_commit(h) == NVS_OK);
    nvs_close(h);
    PASS();
    return 0;
}

static int test_string_set_get(void)
{
    TEST("String set / get (single and multi-entry)");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h) == NVS_OK);

    /* Short string — fits in 1 continuation slot */
    const char *short_str = "Hello, NVS!";
    CHECK(nvs_set_str(h, "greeting", short_str) == NVS_OK);

    char buf[256];
    size_t len = sizeof(buf);
    CHECK(nvs_get_str(h, "greeting", buf, &len) == NVS_OK);
    CHECK(strcmp(buf, short_str) == 0);
    printf("  greeting = \"%s\"\n", buf);

    /* Long string — spans multiple entries */
    const char *long_str =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs. "
        "How vainly men themselves amaze...";

    CHECK(nvs_set_str(h, "quote", long_str) == NVS_OK);

    memset(buf, 0, sizeof(buf));
    len = sizeof(buf);
    CHECK(nvs_get_str(h, "quote", buf, &len) == NVS_OK);
    CHECK(strcmp(buf, long_str) == 0);
    printf("  quote length = %zu\n", len);

    /* Query mode: buf=NULL */
    size_t req_len = 0;
    CHECK(nvs_get_str(h, "quote", NULL, &req_len) == NVS_OK);
    CHECK(req_len == strlen(long_str) + 1u);

    CHECK(nvs_commit(h) == NVS_OK);
    nvs_close(h);
    PASS();
    return 0;
}

static int test_key_update(void)
{
    TEST("Key update — old entry logically erased, new value readable");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h) == NVS_OK);

    /* Write initial value */
    CHECK(nvs_set_i32(h, "counter", 1) == NVS_OK);

    /* Update three times */
    CHECK(nvs_set_i32(h, "counter", 2) == NVS_OK);
    CHECK(nvs_set_i32(h, "counter", 3) == NVS_OK);
    CHECK(nvs_set_i32(h, "counter", 42) == NVS_OK);

    int32_t val = 0;
    CHECK(nvs_get_i32(h, "counter", &val) == NVS_OK);
    CHECK(val == 42);
    printf("  counter = %d  (expected 42)\n", val);

    nvs_close(h);
    PASS();
    return 0;
}

static int test_erase_key(void)
{
    TEST("nvs_erase_key — key disappears after erase");

    nvs_handle_t h;
    CHECK(nvs_open("app_cfg", NVS_READWRITE, &h) == NVS_OK);

    CHECK(nvs_set_u32(h, "token", 0xCAFEBABEu) == NVS_OK);
    CHECK(nvs_erase_key(h, "token") == NVS_OK);

    uint32_t v = 0;
    int rc = nvs_get_u32(h, "token", &v);
    CHECK(rc == NVS_ERR_NOT_FOUND);

    nvs_close(h);
    PASS();
    return 0;
}

static int test_cross_namespace_isolation(void)
{
    TEST("Cross-namespace isolation — same key, different namespaces");

    nvs_handle_t h1, h2;
    CHECK(nvs_open("ns_alpha", NVS_READWRITE, &h1) == NVS_OK);
    CHECK(nvs_open("ns_beta",  NVS_READWRITE, &h2) == NVS_OK);

    CHECK(nvs_set_u32(h1, "shared_key", 0xAAAAAAAAu) == NVS_OK);
    CHECK(nvs_set_u32(h2, "shared_key", 0xBBBBBBBBu) == NVS_OK);

    uint32_t v1 = 0, v2 = 0;
    CHECK(nvs_get_u32(h1, "shared_key", &v1) == NVS_OK);
    CHECK(nvs_get_u32(h2, "shared_key", &v2) == NVS_OK);
    CHECK(v1 == 0xAAAAAAAAu);
    CHECK(v2 == 0xBBBBBBBBu);
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
     * We keep sector_size=4096 and num_sectors=4 so the partition is small
     * enough to fill quickly, forcing GC to run.
     */
    nvs_config_t small_cfg = *cfg;
    small_cfg.sector_size = 4096u;
    small_cfg.num_sectors = 3u;
    small_cfg.base_address = 0u;

    flash_full_erase();
    CHECK(nvs_init(&small_cfg) == NVS_OK);

    nvs_handle_t h;
    CHECK(nvs_open("gc_ns", NVS_READWRITE, &h) == NVS_OK);

    /* Write a key we want to survive GC */
    CHECK(nvs_set_u32(h, "survivor", 0x12345678u) == NVS_OK);

    /*
     * Fill up the partition by repeatedly updating a key (each update
     * writes a new entry + marks old as Erased, consuming slots).
     * We do this enough times to force GC to run at least once.
     */
    const int ITERATIONS = 80000;
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
    CHECK(nvs_get_u32(h, "survivor", &sv) == NVS_OK);
    CHECK(sv == 0x12345678u);
    printf("  survivor = 0x%08X  (GC preserved it)\n", sv);

    /* And the most recent filler value */
    uint32_t fv = 0;
    CHECK(nvs_get_u32(h, "filler", &fv) == NVS_OK);
    CHECK(fv == (uint32_t)(ITERATIONS - 1));
    printf("  filler   = %u  (expected %d)\n", fv, ITERATIONS - 1);

    nvs_close(h);

    /* Restore config for subsequent tests by re-initialising */
    flash_full_erase();
    CHECK(nvs_init(cfg) == NVS_OK);

    PASS();
    return 0;
}

static int test_reinit_persistence(const nvs_config_t *cfg)
{
    /* Use the same 4KB config as test_gc_trigger to avoid geometry mismatch */
    static nvs_config_t small_cfg;
    small_cfg.base_address = 0;
    small_cfg.sector_size  = 4096;
    small_cfg.num_sectors  = 4;
    small_cfg.read         = cfg->read;
    small_cfg.write        = cfg->write;
    small_cfg.erase        = cfg->erase;

    TEST("Persistence — data survives re-init (simulated reboot)");

    nvs_handle_t h;
    CHECK(nvs_open("persist", NVS_READWRITE, &h) == NVS_OK);
    CHECK(nvs_set_u32(h, "magic", 0xDEADBEEFu) == NVS_OK);
    CHECK(nvs_set_str(h, "name", "PersistenceRecord") == NVS_OK);
    nvs_close(h);

    /* Simulated reboot: re-init with same config */
    CHECK(nvs_init(&small_cfg) == NVS_OK);

    CHECK(nvs_open("persist", NVS_READONLY, &h) == NVS_OK);
    
    uint32_t magic = 0;
    CHECK(nvs_get_u32(h, "magic", &magic) == NVS_OK);
    if (magic != 0xDEADBEEFu)
    {
        FAIL("magic mismatch");
    }

    char name[32];
    size_t len = sizeof(name);
    CHECK(nvs_get_str(h, "name", name, &len) == NVS_OK);
    if (strcmp(name, "PersistenceRecord") != 0)
    {
        FAIL("name mismatch");
    }
    
    nvs_close(h);
    PASS();
    return 0;
}

static int test_erase_all(void)
{
    TEST("nvs_erase_all — remove all keys in a namespace");

    nvs_handle_t h1, h2;
    CHECK(nvs_open("ns_erase", NVS_READWRITE, &h1) == NVS_OK);
    CHECK(nvs_open("ns_keep",  NVS_READWRITE, &h2) == NVS_OK);

    /* Fill ns_erase */
    CHECK(nvs_set_u32(h1, "key1", 1) == NVS_OK);
    CHECK(nvs_set_u32(h1, "key2", 2) == NVS_OK);
    /* Fill ns_keep */
    CHECK(nvs_set_u32(h2, "key3", 3) == NVS_OK);

    /* Erase all in ns_erase */
    CHECK(nvs_erase_all(h1) == NVS_OK);

    /* Verify keys in ns_erase are gone */
    uint32_t v = 0;
    CHECK(nvs_get_u32(h1, "key1", &v) == NVS_ERR_NOT_FOUND);
    CHECK(nvs_get_u32(h1, "key2", &v) == NVS_ERR_NOT_FOUND);

    /* Verify key in ns_keep survives */
    CHECK(nvs_get_u32(h2, "key3", &v) == NVS_OK);
    CHECK(v == 3);

    nvs_close(h1);
    nvs_close(h2);
    PASS();
    return 0;
}

static int test_handle_limits(void)
{
    TEST("Handle limits — NVS_MAX_HANDLES enforcement");

    nvs_handle_t handles[NVS_MAX_HANDLES];
    int rc;

    /* Open max allowed handles */
    for (int i = 0; i < (int)NVS_MAX_HANDLES; i++)
    {
        char ns[16];
        sprintf(ns, "ns_lim_%d", i);
        CHECK(nvs_open(ns, NVS_READWRITE, &handles[i]) == NVS_OK);
    }

    /* Try to open one more — should fail */
    nvs_handle_t h_fail;
    rc = nvs_open("one_too_many", NVS_READWRITE, &h_fail);
    if (rc != NVS_ERR_HANDLE)
    {
        FAIL("Allowed opening more than NVS_MAX_HANDLES");
    }

    /* Close all */
    for (int i = 0; i < (int)NVS_MAX_HANDLES; i++)
    {
        nvs_close(handles[i]);
    }

    PASS();
    return 0;
}

static int test_read_only_mode(void)
{
    TEST("Read-only mode — prevent writes on RO handles");

    nvs_handle_t h;
    /* First ensure namespace exists by opening RW and writing something */
    CHECK(nvs_open("ro_test", NVS_READWRITE, &h) == NVS_OK);
    CHECK(nvs_set_u32(h, "data", 100) == NVS_OK);
    nvs_close(h);

    /* Open in RO mode */
    CHECK(nvs_open("ro_test", NVS_READONLY, &h) == NVS_OK);

    /* Try to write — should fail */
    int rc = nvs_set_u32(h, "data", 200);
    if (rc != NVS_ERR_READ_ONLY)
    {
        FAIL("Allowed write on read-only handle");
    }

    /* Try to erase — should fail */
    rc = nvs_erase_key(h, "data");
    /* nvs_erase_key returns NVS_ERR_HANDLE if not READWRITE */
    if (rc != NVS_ERR_HANDLE)
    {
        FAIL("Allowed erase on read-only handle (expected ERR_HANDLE)");
    }

    nvs_close(h);
    PASS();
    return 0;
}

static int test_error_conditions(void)
{
    TEST("Generic error conditions (invalid args, small buffers)");

    nvs_handle_t h;
    CHECK(nvs_open("err_ns", NVS_READWRITE, &h) == NVS_OK);

    /* 1. NULL pointer error */
    if (nvs_set_u32(h, NULL, 42) != NVS_ERR_INVALID_ARG)
    {
        FAIL("Allowed NULL key in nvs_set_u32");
    }

    /* 2. Key too long */
    if (nvs_set_u32(h, "this_key_is_definitely_more_than_15_chars", 123) != NVS_ERR_KEY_TOO_LONG)
    {
        FAIL("Allowed key longer than NVS_KEY_MAX_LEN");
    }

    /* 3. Get non-existent key */
    uint32_t val;
    if (nvs_get_u32(h, "no_such_key", &val) != NVS_ERR_NOT_FOUND)
    {
        FAIL("nvs_get_u32 returned success for non-existent key");
    }

    /* 4. String buffer too small */
    const char *str = "Testing small buffers";
    size_t str_len = strlen(str) + 1;
    CHECK(nvs_set_str(h, "msg", str) == NVS_OK);

    char small_buf[5];
    size_t req_len = sizeof(small_buf);
    int rc = nvs_get_str(h, "msg", small_buf, &req_len);
    if (rc != NVS_ERR_BUF_TOO_SMALL)
    {
        FAIL("nvs_get_str did not return NVS_ERR_BUF_TOO_SMALL");
    }
    if (req_len != str_len)
    {
        FAIL("nvs_get_str did not return required length when buf too small");
    }

    /* 5. Invalid handle */
    if (nvs_set_u32(0, "key", 1) != NVS_ERR_HANDLE)
    {
        FAIL("Allowed operations on handle 0");
    }
    if (nvs_set_u32(99, "key", 1) != NVS_ERR_HANDLE)
    {
        FAIL("Allowed operations on out-of-range handle");
    }

    nvs_close(h);
    PASS();
    return 0;
}

static int test_not_init_check(nvs_config_t *cfg)
{
    TEST("Invalid config during init");

    nvs_config_t bad_cfg = *cfg;
    bad_cfg.sector_size = 0;
    if (nvs_init(&bad_cfg) != NVS_ERR_INVALID_ARG)
    {
        FAIL("nvs_init allowed zero sector_size");
    }

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
        .num_sectors  = 3u,            /* use first 8 sectors of the simulator */
        .base_address = 0u,
        .read         = adapter_read,
        .write        = adapter_write,
        .erase        = adapter_erase,
    };

    int failures = 0;

    failures += test_init(&cfg);
    failures += test_integer_set_get();
    failures += test_string_set_get();
    failures += test_key_update();
    failures += test_erase_key();
    failures += test_cross_namespace_isolation();
    failures += test_gc_trigger(&cfg);
    failures += test_reinit_persistence(&cfg);
    failures += test_erase_all();
    failures += test_handle_limits();
    failures += test_read_only_mode();
    failures += test_error_conditions();
    failures += test_not_init_check(&cfg);

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
