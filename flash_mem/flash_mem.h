#ifndef FLASH_MEM_H
#define FLASH_MEM_H

#include <stdint.h>
#include <stddef.h>

#define FLASH_SECTOR_SIZE (64 * 1024)
#define FLASH_SECTOR_COUNT 64
#define FLASH_SIZE (FLASH_SECTOR_SIZE * FLASH_SECTOR_COUNT)

/**
 * @brief Write data to flash.
 * 
 * @param addr Destination address in flash.
 * @param data Source data buffer.
 * @param len Number of bytes to write.
 */
void flash_write(uint32_t addr, const void* data, uint16_t len);

/**
 * @brief Read data from flash.
 * 
 * @param addr Source address in flash.
 * @param data Destination buffer.
 * @param size Number of bytes to read.
 */
void flash_read(uint32_t addr, void* data, uint16_t size);

/**
 * @brief Erase a flash sector (64KB).
 * 
 * @param base_addr Base address of the sector to erase.
 */
void flash_erase_sector(uint32_t base_addr);

/**
 * @brief Erase the entire flash memory.
 */
void flash_full_erase(void);

/**
 * @brief Print sector contents for debugging.
 * 
 * @param addr Any address within the sector to print.
 */
void flash_print_sector(uint32_t addr, uint32_t num_bytes);

#endif // FLASH_MEM_H
