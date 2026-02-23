#include "flash_mem.h"
#include <string.h>
#include <stdio.h>

static uint8_t fcb_flash[FLASH_SIZE];

void flash_write(uint32_t addr, const void* data, uint16_t len)
{
    if (addr + len > FLASH_SIZE)
    {
        return; // Simple bounds check
    }
    memcpy(&fcb_flash[addr], data, len);
}

void flash_read(uint32_t addr, void* data, uint16_t size)
{
    if (addr + size > FLASH_SIZE)
    {
        return; // Simple bounds check
    }
    memcpy(data, &fcb_flash[addr], size);
}

void flash_erase_sector(uint32_t addr)
{
    // Find the base address of the sector (align to FLASH_SECTOR_SIZE)
    uint32_t base_addr = addr - (addr % FLASH_SECTOR_SIZE);

    if (base_addr + FLASH_SECTOR_SIZE > FLASH_SIZE)
    {
        return; // Simple bounds check
    }
    // Set 64KB (65536 bytes) to 0xFF
    memset(&fcb_flash[base_addr], 0xFF, FLASH_SECTOR_SIZE);
}

void flash_full_erase(void)
{
    memset(fcb_flash, 0xFF, FLASH_SIZE);
}

void flash_print_sector(uint32_t addr, uint32_t num_bytes)
{
    uint32_t base_addr = addr - (addr % FLASH_SECTOR_SIZE);
    
    printf("--- Sector at 0x%08X (printing %u bytes) ---\n", base_addr, num_bytes);
    for (uint32_t i = 0; i < num_bytes; i += 16)
    {
        printf("%08X: ", base_addr + i);
        for (uint32_t j = 0; j < 16; j++)
        {
            if (i + j < num_bytes)
            {
                printf("%02X ", fcb_flash[base_addr + i + j]);
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
