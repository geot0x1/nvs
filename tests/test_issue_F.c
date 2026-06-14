/*
 * Issue F (HIGH) — nvs_mount accepts sector_count > 16, but the internal
 * scratch arrays in get_sectors_by_seq_desc() (seqs[16], valid[16]) and in
 * nvs_read() (indices[16]) are fixed at 16 entries.
 *
 * With more than 16 valid sectors, the scan loop writes seqs[16..N-1] and
 * valid[16..N-1] past the end of those 16-element arrays -> stack buffer
 * overflow.  This program supplies its OWN tiny flash simulator (a separate
 * RAM buffer + AND-write semantics) sized for 255 sectors, so flash_mem.c is
 * left completely untouched.
 *
 * Built with -fstack-protector-all: the ~956-byte overflow obliterates the
 * stack canary and return address, so the process aborts ("stack smashing
 * detected") or segfaults.  Any abnormal termination = confirmation.
 *
 * Links against the UNMODIFIED nvs.c / crc32.c (flash_mem.c not needed here).
 */

#include "nvs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#endif

#define FF_SECTOR_SIZE   64U
#define FF_SECTOR_COUNT  255U
#define FF_SIZE          (FF_SECTOR_SIZE * FF_SECTOR_COUNT)

static uint8_t ff_mem[FF_SIZE];

static void ff_write(uint32_t addr, const void *data, uint16_t len)
{
    if ((uint32_t)addr + len > FF_SIZE)
    {
        return;
    }
    const uint8_t *src = (const uint8_t *)data;
    for (uint16_t i = 0; i < len; i++)
    {
        ff_mem[addr + i] &= src[i]; /* NOR AND semantics */
    }
}

static void ff_read(uint32_t addr, void *data, uint16_t size)
{
    if ((uint32_t)addr + size > FF_SIZE)
    {
        return;
    }
    memcpy(data, &ff_mem[addr], size);
}

static void ff_erase(uint32_t addr)
{
    uint32_t base = addr - (addr % FF_SECTOR_SIZE);
    if (base + FF_SECTOR_SIZE > FF_SIZE)
    {
        return;
    }
    memset(&ff_mem[base], 0xFF, FF_SECTOR_SIZE);
}

int main(void)
{
#ifdef _WIN32
    /* Suppress Windows Error Reporting popups so the inevitable stack-overrun
     * fail-fast terminates the process immediately and cleanly. */
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
#endif

    printf("=== Issue F: sector_count=%u > 16 -> fixed-array stack overflow ===\n",
           FF_SECTOR_COUNT);
    fflush(stdout);

    memset(ff_mem, 0xFF, sizeof(ff_mem));

    /* Craft a valid header (magic + distinct seq + ACTIVE) in EVERY sector,
     * so get_sectors_by_seq_desc() counts all 255 as valid. */
    for (uint32_t s = 0; s < FF_SECTOR_COUNT; s++)
    {
        uint32_t base  = s * FF_SECTOR_SIZE;
        uint32_t magic = NVS_MAGIC_WORD;
        uint32_t seq   = s + 1;
        uint32_t state = NVS_SECTOR_ACTIVE;
        ff_write(base + 0, &magic, sizeof(magic));
        ff_write(base + 4, &seq,   sizeof(seq));
        ff_write(base + 8, &state, sizeof(state));
    }

    nvs_flash_driver_t drv = {0};
    drv.write        = ff_write;
    drv.read         = ff_read;
    drv.erase_sector = ff_erase;
    drv.sector_size  = FF_SECTOR_SIZE;
    drv.sector_count = (uint8_t)FF_SECTOR_COUNT;

    nvs_err_t mrc = nvs_mount(&drv);
    printf("  nvs_mount(sector_count=255) rc=%d\n", mrc);
    fflush(stdout);

    uint8_t buf[16];
    uint8_t out_len = 0;
    printf("  calling nvs_read() -> get_sectors_by_seq_desc fills 255 entries "
           "into 16-slot arrays ...\n");
    fflush(stdout);

    nvs_err_t rc = nvs_read("anykey", buf, sizeof(buf), &out_len);

    /* Only reached if no overflow/canary trip occurred. */
    printf("  survived: nvs_read rc=%d (no detectable overflow on this layout)\n", rc);
    return 0;
}
