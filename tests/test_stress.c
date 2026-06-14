/*
 * test_stress.c — NVS stress test suite
 *
 * Exercises the NVS subsystem under heavy write/read pressure while printing
 * flash layout snapshots at key milestones so the on-flash data structure can
 * be inspected visually.
 *
 * Three test scenarios:
 *
 *   1. test_stress_single_key_churn
 *      Hammers a single key with 10 000 sequential overwrites.  After every
 *      GC-sized batch the flash header region of each sector is printed so the
 *      sector-state progression (EMPTY → ACTIVE → FULL → FREEING → EMPTY) can
 *      be observed.
 *
 *   2. test_stress_multi_key_interleaved
 *      Writes 8 distinct keys in a rotating pattern (10 000 total writes).
 *      Interleaves random-order reads after every 500 writes and asserts that
 *      each key always holds the most-recently-written value.
 *
 *   3. test_stress_remount_integrity
 *      Writes 20 keys, remounts 50 times, each time performing another batch
 *      of writes and re-reading every key.  Verifies data survives across
 *      repeated cold-boot cycles.
 */

#include "flash_mem.h"
#include "nvs.h"
#include "test_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*===========================================================================
 *  Shared assert machinery
 *===========================================================================*/

#define STRESS_ASSERT(pass_p, fail_p, cond, msg)                          \
    do                                                                    \
    {                                                                     \
        if (cond)                                                         \
        {                                                                 \
            printf("  [PASS] %s\n", (msg));                               \
            (*(pass_p))++;                                                \
        }                                                                 \
        else                                                              \
        {                                                                 \
            printf("  [FAIL] %s  (line %d)\n", (msg), __LINE__);         \
            (*(fail_p))++;                                                \
        }                                                                 \
    } while (0)

/*===========================================================================
 *  Internal helpers
 *===========================================================================*/

/*
 * Print the first 48 bytes of every sector (covers the 16-byte sector header
 * plus the first two entry headers).  This gives a compact view of sector
 * state without flooding the console with the full 4096-byte dump.
 */
static void print_all_sector_headers(const char *label)
{
    printf("\n  [FLASH] %s\n", label);
    for (int s = 0; s < FLASH_SECTOR_COUNT; s++)
    {
        uint32_t base = (uint32_t)s * FLASH_SECTOR_SIZE;
        flash_print_sector(base, 48);
    }
}

/* Build a stress key of the form "SK_XX" where XX is zero-padded. */
static void make_stress_key(char *out, int idx)
{
    out[0] = 'S';
    out[1] = 'K';
    out[2] = '_';
    out[3] = (char)('0' + (idx / 10) % 10);
    out[4] = (char)('0' + (idx % 10));
    out[5] = '\0';
}

/*===========================================================================
 *  Test 1 — Single-key churn
 *===========================================================================*/

/*
 * Every time a full sector's worth of writes is completed the flash headers are
 * printed so the ACTIVE → FULL → FREEING → EMPTY cycle can be tracked.
 */
static void test_stress_single_key_churn(int *pass, int *fail)
{
    printf("\n=== Stress Test 1: Single-key churn (10 000 writes) ===\n");

    flash_full_erase();
    th_mount();

    const int total_writes = 10000;
    /* Print a flash snapshot every time this many writes complete. */
    const int snapshot_interval = (int)ENTRIES_PER_SECTOR;

    int all_writes_ok = 1;
    int snapshot_count = 0;

    for (int i = 0; i < total_writes; i++)
    {
        uint32_t val = (uint32_t)i;
        nvs_err_t rc = nvs_write("CHURN", &val, sizeof(val));
        if (rc != NVS_OK)
        {
            printf("  [FAIL] Write %d returned rc=%d\n", i, rc);
            all_writes_ok = 0;
            break;
        }

        /* Snapshot at every sector-boundary interval. */
        if ((i + 1) % snapshot_interval == 0)
        {
            snapshot_count++;
            char label[64];
            snprintf(label, sizeof(label),
                     "after write %d (snapshot #%d)", i + 1, snapshot_count);
            print_all_sector_headers(label);
        }
    }

    STRESS_ASSERT(pass, fail, all_writes_ok, "10 000 single-key writes all return NVS_OK");

    /* Read back and verify the final value. */
    uint32_t readback = 0;
    uint8_t  out_len  = 0;
    nvs_err_t rc = nvs_read("CHURN", &readback, sizeof(readback), &out_len);

    STRESS_ASSERT(pass, fail, rc == NVS_OK,               "Read after churn returns NVS_OK");
    STRESS_ASSERT(pass, fail, out_len == sizeof(uint32_t), "Read length is correct");
    STRESS_ASSERT(pass, fail, readback == (uint32_t)(total_writes - 1),
                  "Final value matches last written value");

    printf("  [INFO] Expected %u, got %u\n", (unsigned)(total_writes - 1), readback);
    printf("  [INFO] Total flash snapshots taken: %d\n", snapshot_count);
}

/*===========================================================================
 *  Test 2 — Multi-key interleaved writes + reads
 *===========================================================================*/

/*
 * 8 keys are written in a rotating pattern.  After every READ_INTERVAL writes
 * all 8 keys are read back and the values verified.  A flash snapshot is
 * taken every SNAPSHOT_INTERVAL writes to observe sector layout under sustained
 * multi-key pressure.
 */
static void test_stress_multi_key_interleaved(int *pass, int *fail)
{
    printf("\n=== Stress Test 2: Multi-key interleaved writes + reads (10 000 writes) ===\n");

    flash_full_erase();
    th_mount();

    const int   num_keys        = 8;
    const int   total_writes    = 10000;
    const int   read_interval   = 500;
    const int   snapshot_interval = (int)ENTRIES_PER_SECTOR * 2;

    /* Track the expected value for each key (the iteration index of its last write). */
    int expected[8];
    for (int k = 0; k < num_keys; k++)
    {
        expected[k] = -1; /* not yet written */
    }

    char key[8];
    int all_writes_ok = 1;
    int all_reads_ok  = 1;
    int snapshot_count = 0;

    for (int i = 0; i < total_writes; i++)
    {
        int key_idx = i % num_keys;
        make_stress_key(key, key_idx);

        uint32_t val = (uint32_t)i;
        nvs_err_t rc = nvs_write(key, &val, sizeof(val));
        if (rc != NVS_OK)
        {
            printf("  [FAIL] Write %d key='%s' returned rc=%d\n", i, key, rc);
            all_writes_ok = 0;
            break;
        }
        expected[key_idx] = i;

        /* Periodic read-back of all written keys. */
        if ((i + 1) % read_interval == 0)
        {
            for (int k = 0; k < num_keys; k++)
            {
                if (expected[k] < 0)
                {
                    continue; /* not yet written */
                }

                make_stress_key(key, k);
                uint32_t rb   = 0;
                uint8_t  olen = 0;
                nvs_err_t rrc = nvs_read(key, &rb, sizeof(rb), &olen);

                if (rrc != NVS_OK || rb != (uint32_t)expected[k])
                {
                    printf("  [FAIL] After write %d: key='%s' expected %d got %u (rc=%d)\n",
                           i + 1, key, expected[k], rb, rrc);
                    all_reads_ok = 0;
                }
            }
        }

        /* Flash snapshot to observe sector layout progression. */
        if ((i + 1) % snapshot_interval == 0)
        {
            snapshot_count++;
            char label[64];
            snprintf(label, sizeof(label),
                     "after write %d (snapshot #%d)", i + 1, snapshot_count);
            print_all_sector_headers(label);
        }
    }

    STRESS_ASSERT(pass, fail, all_writes_ok, "10 000 multi-key writes all return NVS_OK");
    STRESS_ASSERT(pass, fail, all_reads_ok,  "All periodic read-backs return correct values");

    /* Final read-back of all 8 keys. */
    int final_ok = 1;
    for (int k = 0; k < num_keys; k++)
    {
        if (expected[k] < 0)
        {
            continue;
        }

        make_stress_key(key, k);
        uint32_t rb   = 0;
        uint8_t  olen = 0;
        nvs_err_t rc = nvs_read(key, &rb, sizeof(rb), &olen);
        if (rc != NVS_OK || rb != (uint32_t)expected[k])
        {
            printf("  [FAIL] Final check: key='%s' expected %d got %u (rc=%d)\n",
                   key, expected[k], rb, rc);
            final_ok = 0;
        }
    }

    STRESS_ASSERT(pass, fail, final_ok, "All 8 keys hold correct final values after 10 000 writes");
    printf("  [INFO] Total flash snapshots taken: %d\n", snapshot_count);
}

/*===========================================================================
 *  Test 3 — Remount integrity under write pressure
 *===========================================================================*/

/*
 * 20 keys are maintained across 50 remount cycles.  Each cycle:
 *   1. Remounts (simulates a cold boot).
 *   2. Writes one new value to every key.
 *   3. Reads back every key and asserts the value matches.
 * A flash snapshot is printed at cycle 1, 10, 25, and 50.
 */
static void test_stress_remount_integrity(int *pass, int *fail)
{
    printf("\n=== Stress Test 3: Remount integrity under write pressure (50 cycles × 20 keys) ===\n");

    flash_full_erase();
    th_mount();

    const int num_keys     = 20;
    const int remount_cycles = 50;

    /* Snapshot milestones (1-based cycle numbers). */
    const int snapshot_cycles[] = {1, 10, 25, 50};
    const int num_snapshots = (int)(sizeof(snapshot_cycles) / sizeof(snapshot_cycles[0]));

    char key[8];
    int all_ok = 1;

    /* Seed: write every key once before the remount loop so they all exist. */
    for (int k = 0; k < num_keys; k++)
    {
        make_stress_key(key, k);
        uint32_t val = 0;
        nvs_err_t rc = nvs_write(key, &val, sizeof(val));
        if (rc != NVS_OK)
        {
            printf("  [FAIL] Seed write k=%d returned rc=%d\n", k, rc);
            all_ok = 0;
        }
    }

    for (int cycle = 1; cycle <= remount_cycles && all_ok; cycle++)
    {
        /* Simulate power-on by remounting. */
        nvs_err_t mrc = th_mount();
        if (mrc != NVS_OK)
        {
            printf("  [FAIL] Remount at cycle %d returned rc=%d\n", cycle, mrc);
            all_ok = 0;
            break;
        }

        /* Write a new value to every key — value encodes (cycle << 8 | key_idx). */
        for (int k = 0; k < num_keys; k++)
        {
            make_stress_key(key, k);
            uint32_t val = (uint32_t)((cycle << 8) | k);
            nvs_err_t rc = nvs_write(key, &val, sizeof(val));
            if (rc != NVS_OK)
            {
                printf("  [FAIL] Cycle %d write k=%d returned rc=%d\n", cycle, k, rc);
                all_ok = 0;
                break;
            }
        }

        if (!all_ok)
        {
            break;
        }

        /* Verify every key holds the expected value. */
        for (int k = 0; k < num_keys; k++)
        {
            make_stress_key(key, k);
            uint32_t expected = (uint32_t)((cycle << 8) | k);
            uint32_t rb       = 0;
            uint8_t  olen     = 0;
            nvs_err_t rc = nvs_read(key, &rb, sizeof(rb), &olen);
            if (rc != NVS_OK || rb != expected)
            {
                printf("  [FAIL] Cycle %d read k=%d: expected 0x%08X got 0x%08X (rc=%d)\n",
                       cycle, k, expected, rb, rc);
                all_ok = 0;
                break;
            }
        }

        /* Print a flash snapshot at the configured cycle milestones. */
        for (int m = 0; m < num_snapshots; m++)
        {
            if (cycle == snapshot_cycles[m])
            {
                char label[64];
                snprintf(label, sizeof(label), "after remount cycle %d", cycle);
                print_all_sector_headers(label);
                break;
            }
        }
    }

    STRESS_ASSERT(pass, fail, all_ok, "All 20 keys survive 50 remount/write/read cycles with correct values");
}

/*===========================================================================
 *  Entry point (called from main.c)
 *===========================================================================*/

void run_stress_tests(int *pass, int *fail)
{
    printf("\n========================================\n");
    printf("  NVS Stress Test Suite\n");
    printf("========================================\n");

    test_stress_single_key_churn(pass, fail);
    test_stress_multi_key_interleaved(pass, fail);
    test_stress_remount_integrity(pass, fail);

    printf("\n========================================\n");
    printf("  Stress suite complete\n");
    printf("========================================\n");
}
