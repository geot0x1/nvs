#ifndef CRC32_H
#define CRC32_H

#include <stddef.h>
#include <stdint.h>


/**
 * @brief Calculate CRC32 checksum for a given data buffer.
 *
 * Uses the standard Ethernet polynomial (0xEDB88320).
 *
 * @param data Pointer to the buffer.
 * @param len  Length of the data in bytes.
 * @return uint32_t Calculated CRC32 value.
 */
uint32_t crc32_gen(const void *data, size_t len);

#endif // CRC32_H
