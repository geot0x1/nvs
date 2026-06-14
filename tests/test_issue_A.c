/*
 * Issue A (CRITICAL) — committed entry with data_len > NVS_MAX_DATA_LEN.
 *
 * A committed (Valid, 0xFE) entry whose data_len exceeds NVS_MAX_DATA_LEN
 * (128) is read by nvs_read into fixed stack buffers BEFORE any validation:
 *
 *     uint8_t data_buf[NVS_MAX_DATA_LEN];          // 128 bytes
 *     DRV_READ(... data_buf, dl2);                 // dl2 = 200  -> overflow
 *     compute_entry_crc(kl2, dl2, ...);            // buf[145]   -> overflow
 *
 * This program installs an instrumented flash driver that forwards to the
 * real simulator but INTERCEPTS the unvalidated oversized data read at the
 * driver boundary.  The moment nvs_read asks to read more than
 * NVS_MAX_DATA_LEN bytes of payload into its fixed 128-byte buffer, we have
 * deterministic proof of the out-of-bounds access, and we _exit(1) BEFORE
 * the overflowing copy happens (so the harness is not corrupted).
 *
 * Built with -fstack-protector-all; if the interception were removed the
 * process would instead abort on a smashed stack canary.  Either outcome is
 * a confirmation.
 *
 * Links against the UNMODIFIED nvs.c / flash_mem.c / crc32.c.
 */

#include "flash_mem.h"
#include "nvs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int g_tripped = 0;

static void inst_write(uint32_t addr, const void *data, uint16_t len)
{
    flash_write(addr, data, len);
}

static void inst_read(uint32_t addr, void *data, uint16_t len)
{
    /* The only read that legitimately exceeds NVS_MAX_DATA_LEN bytes would
     * be a payload read for a data_len > 128 — which nvs_read copies into a
     * fixed uint8_t[128] stack buffer.  Catch it here, before the copy. */
    if (len > NVS_MAX_DATA_LEN)
    {
        g_tripped = 1;
        printf("  [DETECTED] nvs_read issued a %u-byte read into its fixed "
               "%u-byte stack data buffer\n", (unsigned)len, NVS_MAX_DATA_LEN);
        printf("  -> unvalidated data_len causes stack buffer overflow "
               "(stopped before the overwrite)\n");
        fflush(stdout);
        _exit(42); /* distinctive deterministic confirmation code, no corruption */
    }
    flash_read(addr, data, len);
}

static void inst_erase(uint32_t addr)
{
    flash_erase_sector(addr);
}

int main(void)
{
    printf("=== Issue A: oversized data_len -> stack overflow in nvs_read ===\n");
    fflush(stdout);

    flash_full_erase();

    nvs_flash_driver_t drv = {0};
    drv.write        = inst_write;
    drv.read         = inst_read;
    drv.erase_sector = inst_erase;
    drv.sector_size  = FLASH_SECTOR_SIZE;
    drv.sector_count = FLASH_SECTOR_COUNT;
    nvs_mount(&drv); /* formats sector 0 Active, seq 1 */

    /* Craft a committed entry: key "evil" (4), data_len = 200 (> 128). */
    uint8_t kl = 4, dl = 200;
    uint8_t evil[NVS_ENTRY_HDR_SIZE + 4 + 200];
    memset(evil, 0xA5, sizeof(evil));
    evil[0] = (uint8_t)NVS_ENTRY_VALID;
    evil[1] = kl;
    evil[2] = dl;
    evil[3] = 0xFF;
    /* CRC bytes irrelevant: the overflow happens before any CRC check. */
    memcpy(&evil[NVS_ENTRY_HDR_SIZE], "evil", 4);
    flash_write(NVS_SECTOR_HDR_SIZE, evil, (uint16_t)(NVS_ENTRY_HDR_SIZE + 4 + 200));

    uint8_t buf[255];
    uint8_t out_len = 0;
    printf("  calling nvs_read(\"evil\") ...\n");
    fflush(stdout);

    nvs_err_t rc = nvs_read("evil", buf, sizeof(buf), &out_len);

    /* Only reached if the oversized read never happened. */
    printf("  survived without oversized read: rc=%d out_len=%u (tripped=%d)\n",
           rc, out_len, g_tripped);
    return 0;
}
