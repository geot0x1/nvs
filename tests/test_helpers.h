#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

/*
 * Shared helpers for the NVS issue-verification suite.
 *
 * These helpers ONLY use the public NVS API plus the (allowed) direct
 * flash_* simulator calls and crc32_gen.  They never modify nvs.c,
 * flash_mem.c or crc32.c.
 */

#include "flash_mem.h"
#include "nvs.h"
#include "crc32.h"

#include <stdint.h>
#include <string.h>

/* Number of 16-byte entries (8 hdr + 4 key + 4 data) that fit in a sector. */
#define ENTRIES_PER_SECTOR ((FLASH_SECTOR_SIZE - NVS_SECTOR_HDR_SIZE) / 16U)

/** Mount the NVS core against the standard 3-sector RAM simulator. */
static inline nvs_err_t th_mount(void)
{
    nvs_flash_driver_t drv;
    drv.write        = flash_write;
    drv.read         = flash_read;
    drv.erase_sector = flash_erase_sector;
    drv.sector_size  = FLASH_SECTOR_SIZE;
    drv.sector_count = FLASH_SECTOR_COUNT;
    return nvs_mount(&drv);
}

/** Generate up to 765 unique 4-char keys: "A000".."C254". */
static inline void th_make_key(char *key, int i)
{
    key[0] = (char)('A' + (i / (int)ENTRIES_PER_SECTOR));
    key[1] = (char)('0' + ((i % (int)ENTRIES_PER_SECTOR) / 100));
    key[2] = (char)('0' + (((i % (int)ENTRIES_PER_SECTOR) / 10) % 10));
    key[3] = (char)('0' + ((i % (int)ENTRIES_PER_SECTOR) % 10));
    key[4] = '\0';
}

/**
 * Directly craft a COMMITTED (Valid, 0xFE) entry on flash, exactly as the
 * NVS core would lay it out, using the real CRC algorithm.  Flash must be
 * erased (0xFF) at `addr` for the AND-write to land the exact bytes.
 */
static inline void th_craft_valid_entry(uint32_t addr,
                                        const char *key, uint8_t key_len,
                                        const void *data, uint8_t data_len)
{
    uint8_t entry[NVS_ENTRY_HDR_SIZE + 255 + 255];
    uint32_t total = (uint32_t)NVS_ENTRY_HDR_SIZE + key_len + data_len;
    total = (total + 3U) & ~3U; /* align4 */
    memset(entry, 0xFF, sizeof(entry));

    entry[0] = (uint8_t)NVS_ENTRY_VALID;
    entry[1] = key_len;
    entry[2] = data_len;
    entry[3] = 0xFF;

    /* CRC over key_len + data_len + key + data. */
    uint8_t crcbuf[2 + 255 + 255];
    uint32_t n = 0;
    crcbuf[n++] = key_len;
    crcbuf[n++] = data_len;
    memcpy(&crcbuf[n], key, key_len); n += key_len;
    memcpy(&crcbuf[n], data, data_len); n += data_len;
    uint32_t c = crc32_gen(crcbuf, n);

    entry[4] = (uint8_t)(c);
    entry[5] = (uint8_t)(c >> 8);
    entry[6] = (uint8_t)(c >> 16);
    entry[7] = (uint8_t)(c >> 24);

    memcpy(&entry[NVS_ENTRY_HDR_SIZE], key, key_len);
    memcpy(&entry[NVS_ENTRY_HDR_SIZE + key_len], data, data_len);

    flash_write(addr, entry, (uint16_t)total);
}

/** Craft a sector header (magic + seq + state) on erased flash. */
static inline void th_craft_sector_hdr(uint32_t base, uint32_t seq, uint32_t state)
{
    uint32_t magic = NVS_MAGIC_WORD;
    flash_write(base + 0, &magic, sizeof(magic));
    flash_write(base + 4, &seq,   sizeof(seq));
    flash_write(base + 8, &state, sizeof(state));
}

#endif /* TEST_HELPERS_H */
