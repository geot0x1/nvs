/**
 * @file flash_mem.c
 * @brief In-process NOR-flash simulator.
 *
 * Enforces real NOR-flash write semantics: a write can only clear bits
 * (1 → 0), never set them (0 → 1).  Attempting to set a bit that is
 * already 0 is a programming error; the simulator asserts in debug builds
 * and silently ignores the offending bit in release builds, matching the
 * behaviour of real hardware.
 *
 * Erase operations reset an entire sector to 0xFF (all bits 1), which is
 * the only way to restore bits to 1.
 */

#include "flash_mem.h"
#include <string.h>
#include <stdio.h>
#include <assert.h>

static uint8_t s_flash[FLASH_SIZE];

/* -----------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------- */

static int bounds_check(uint32_t addr, uint32_t len)
{
    if (addr >= FLASH_SIZE || len > FLASH_SIZE || addr + len > FLASH_SIZE)
    {
        fprintf(stderr, "flash_mem: out-of-bounds access addr=0x%08X len=%u\n",
                addr, len);
        return 0;
    }
    return 1;
}

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

void flash_write(uint32_t addr, const void *data, uint16_t len)
{
    if (!bounds_check(addr, (uint32_t)len))
    {
        return;
    }

    const uint8_t *src = (const uint8_t *)data;
    for (uint16_t i = 0u; i < len; i++)
    {
        uint8_t existing = s_flash[addr + i];
        uint8_t incoming = src[i];

        /*
         * NOR-flash constraint: a write can only clear bits (AND semantics).
         * Attempting to set a bit that is already 0 is a programming error.
         */
        if ((incoming & ~existing) != 0u)
        {
            fprintf(stderr,
                    "flash_mem: NOR violation at 0x%08X byte %u: "
                    "existing=0x%02X incoming=0x%02X (would set bits)\n",
                    addr, i, existing, incoming);
            assert(0 && "flash_mem: attempted to set bits in NOR flash without erase");
        }

        s_flash[addr + i] = existing & incoming;
    }
}

void flash_read(uint32_t addr, void *data, uint16_t size)
{
    if (!bounds_check(addr, (uint32_t)size))
    {
        return;
    }
    memcpy(data, &s_flash[addr], size);
}

void flash_erase_sector(uint32_t addr)
{
    /* Align down to sector boundary */
    uint32_t base = addr - (addr % FLASH_SECTOR_SIZE);

    if (!bounds_check(base, FLASH_SECTOR_SIZE))
    {
        return;
    }

    memset(&s_flash[base], 0xFF, FLASH_SECTOR_SIZE);
}

void flash_full_erase(void)
{
    memset(s_flash, 0xFF, FLASH_SIZE);
}

void flash_print_sector(uint32_t addr, uint32_t num_bytes)
{
    uint32_t base = addr - (addr % FLASH_SECTOR_SIZE);

    printf("--- Sector at 0x%08X (printing %u bytes) ---\n", base, num_bytes);
    for (uint32_t i = 0u; i < num_bytes; i += 16u)
    {
        printf("%08X: ", base + i);
        for (uint32_t j = 0u; j < 16u; j++)
        {
            if (i + j < num_bytes)
            {
                printf("%02X ", s_flash[base + i + j]);
            }
            else
            {
                printf("   ");
            }
        }
        printf("\n");
    }
    printf("---------------------------\n");
}
