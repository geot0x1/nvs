/*
 * test_vuln_toctou.c
 *
 * Vulnerability: TOCTOU unvalidated re-read of dl2 in nvs_read()
 * ----------------------------------------------------------------
 * nvs_read() performs two independent reads of the same entry header:
 *
 *   Pass 1 — walk_sector_entries() reads (kl, dl) and enforces:
 *               kl > NVS_MAX_KEY_LEN || dl > NVS_MAX_DATA_LEN -> break
 *             Only entries that pass this guard reach find_last_visitor().
 *
 *   Pass 2 — after find_last_visitor() records match_off, nvs_read() calls
 *               read_entry_hdr(base + match_off, &kl2, &dl2, ...)
 *             and then immediately:
 *               DRV_READ(... data_buf, dl2)   // data_buf is uint8_t[NVS_MAX_DATA_LEN]
 *             There is NO bounds check on dl2 before this read.
 *
 * A flash bit-flip that corrupts the dl field between Pass 1 and Pass 2
 * can produce dl2 > NVS_MAX_DATA_LEN, causing a stack buffer overflow.
 *
 * Test methodology
 * ----------------
 * Install an instrumented driver that counts reads of the entry header at
 * a known address.  On the SECOND read of that address (the unguarded re-read
 * in nvs_read()), the driver injects dl=200 (> NVS_MAX_DATA_LEN=128) to
 * simulate the bit-flip.  If nvs_read() issues a DRV_READ with len=200 into
 * data_buf[128], we intercept it and record the overflow before it occurs.
 *
 * Expected (secure) behaviour  : nvs_read validates kl2/dl2 against
 *                                 NVS_MAX_KEY_LEN / NVS_MAX_DATA_LEN before
 *                                 the DRV_READ and returns NVS_ERR_CRC (or
 *                                 NVS_ERR_INVALID_ARG) — overflow_detected stays 0.
 *
 * Observed (vulnerable) behaviour: nvs_read issues a DRV_READ with len=200 —
 *                                   overflow_detected is set to 1 (confirmed bug).
 */

#include "flash_mem.h"
#include "nvs.h"
#include "nvs_internal.h"
#include "crc32.h"
#include "test_helpers.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*---------------------------------------------------------------------------
 * Globals shared by the instrumented driver
 *---------------------------------------------------------------------------*/

static uint32_t g_watch_addr  = 0;     /* address to intercept (entry header) */
static int      g_read_count  = 0;     /* how many times that address was read */
static int      g_inject_on   = 2;     /* inject poison on this read number    */
static int      g_overflow_detected = 0;

/*---------------------------------------------------------------------------
 * Instrumented driver callbacks
 *---------------------------------------------------------------------------*/

static void instr_write(uint32_t addr, const void *data, uint16_t len)
{
    flash_write(addr, data, len);
}

static void instr_read(uint32_t addr, void *data, uint16_t len)
{
    /* Track reads of the watched entry-header address. */
    if (addr == g_watch_addr && len == NVS_ENTRY_HDR_SIZE)
    {
        g_read_count++;

        if (g_read_count == g_inject_on)
        {
            /* This is the unguarded re-read in nvs_read()'s second loop.
             * Inject dl = 200 (> NVS_MAX_DATA_LEN) to simulate a bit-flip. */
            flash_read(addr, data, len);
            uint8_t *hdr = (uint8_t *)data;
            hdr[2] = 200;   /* overwrite data_len field only */
            return;
        }
    }

    /* Intercept an oversized data read: this is the overflow that would
     * clobber data_buf[NVS_MAX_DATA_LEN] on the stack. */
    if (len > NVS_MAX_DATA_LEN && addr != g_watch_addr)
    {
        g_overflow_detected = 1;
        /* Clamp the read so the process survives for reporting. */
        flash_read(addr, data, NVS_MAX_DATA_LEN);
        return;
    }

    flash_read(addr, data, len);
}

static void instr_erase(uint32_t addr)
{
    flash_erase_sector(addr);
}

/*---------------------------------------------------------------------------
 * Helper: mount with the instrumented driver
 *---------------------------------------------------------------------------*/

static nvs_err_t instr_mount(void)
{
    nvs_flash_driver_t drv = {0};
    drv.write        = instr_write;
    drv.read         = instr_read;
    drv.erase_sector = instr_erase;
    drv.sector_size  = FLASH_SECTOR_SIZE;
    drv.sector_count = FLASH_SECTOR_COUNT;
    return nvs_mount(&drv);
}

/*---------------------------------------------------------------------------
 * Test
 *---------------------------------------------------------------------------*/

static int g_pass = 0;
static int g_fail = 0;

#define VULN_PASS(msg) do { printf("  [PASS] %s\n", (msg)); g_pass++; } while (0)
#define VULN_FAIL(msg) do { printf("  [FAIL] %s  <-- VULNERABILITY CONFIRMED\n", (msg)); g_fail++; } while (0)

void run_vuln_toctou_tests(int *out_pass, int *out_fail)
{
    printf("\n========================================\n");
    printf("  TOCTOU Re-read Vulnerability Test\n");
    printf("========================================\n");

    /*
     * Scenario
     * --------
     * 1. Write key "vuln" with a 4-byte payload.
     * 2. The entry lands at SECTOR_HDR_SIZE (offset 16) in sector 0.
     * 3. Mount the instrumented driver and note the entry address.
     * 4. Call nvs_read() with a correctly-sized 4-byte buffer.
     *    - Pass 1 (walk): reads header at entry_addr -> kl=4, dl=4 -> passes guard
     *    - find_last_visitor records match_off
     *    - Pass 2 (re-read): reads header at entry_addr again; we inject dl=200
     *    - nvs_read then calls DRV_READ(..., data_buf, 200) -> overflow
     * 5. SECURE fix: nvs_read must validate kl2/dl2 <= NVS_MAX_KEY_LEN/DATA_LEN
     *    before the DRV_READ, returning NVS_ERR_CRC or NVS_ERR_INVALID_ARG.
     */

    printf("\n--- TOCTOU: unguarded dl2 re-read overflows data_buf[%u] ---\n",
           NVS_MAX_DATA_LEN);

    flash_full_erase();
    instr_mount();

    /* Write the victim entry. */
    uint32_t val = 0xDEADBEEF;
    nvs_err_t wrc = nvs_write("vuln", &val, sizeof(val));
    if (wrc != NVS_OK)
    {
        printf("  [SKIP] nvs_write failed (rc=%d) — setup issue\n", wrc);
        goto done;
    }

    /*
     * The entry occupies the first slot after the sector header.
     * Entry layout: 8-byte hdr | 4-byte key | 4-byte data = 16 bytes (align4).
     * Address: sector 0 base (0) + NVS_SECTOR_HDR_SIZE (16) = 16.
     */
    /*
     * Header read order within a single nvs_read() call:
     *   1. find_key_data_len() -> walk_sector_entries() reads entry header
     *   2. find_key_data_len() -> read_entry_hdr() re-reads (has bounds check)
     *   3. nvs_read() second loop -> walk_sector_entries() reads entry header
     *   4. nvs_read() second loop -> read_entry_hdr() re-reads (NO bounds check)
     *
     * Injecting on read #4 simulates a bit-flip that occurs after
     * find_key_data_len() has already validated the entry (safe), but before
     * nvs_read()'s second loop re-reads the header (unguarded).
     */
    g_watch_addr = (uint32_t)NVS_SECTOR_HDR_SIZE;
    g_read_count = 0;
    g_inject_on  = 4;   /* 4th read: unguarded re-read in nvs_read() second loop */
    g_overflow_detected = 0;

    uint8_t buf[4];
    uint8_t out_len = 0;
    nvs_err_t rrc = nvs_read("vuln", buf, sizeof(buf), &out_len);

    printf("  nvs_read rc=%d, out_len=%u, entry-hdr reads=%d, overflow_detected=%d\n",
           rrc, out_len, g_read_count, g_overflow_detected);

    if (g_overflow_detected)
    {
        VULN_FAIL("nvs_read issued DRV_READ(len=200) into data_buf[128]: stack buffer overflow");
    }
    else if (rrc == NVS_ERR_CRC || rrc == NVS_ERR_INVALID_ARG)
    {
        VULN_PASS("nvs_read detected injected dl=200 and returned an error (safe)");
    }
    else if (rrc == NVS_OK)
    {
        /* Clamped read returned OK with corrupted-but-short data. */
        VULN_FAIL("nvs_read returned NVS_OK with unvalidated dl2=200 (silent data corruption)");
    }
    else
    {
        printf("  unexpected rc=%d\n", rrc);
        VULN_FAIL("nvs_read returned unexpected code while processing injected dl=200");
    }

done:
    *out_pass += g_pass;
    *out_fail += g_fail;
}
