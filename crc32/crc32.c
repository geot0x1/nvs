/**
 * @file crc32.c
 * @brief CRC32 implementation using the standard Ethernet reflected polynomial
 *        (0xEDB88320).
 *
 * The lookup table is initialised once on first use.  On bare-metal targets
 * this is safe because there is no concurrent initialisation.  If the module
 * is ever used in a multi-threaded environment the caller must ensure
 * crc32_gen() is first called from a single thread before concurrent use.
 */

#include "crc32.h"

#define CRC32_POLY 0xEDB88320u

static uint32_t s_table[256];
static int      s_table_ready = 0;

static void crc32_build_table(void)
{
    for (uint32_t i = 0u; i < 256u; i++)
    {
        uint32_t crc = i;
        for (unsigned j = 0u; j < 8u; j++)
        {
            crc = (crc & 1u) ? ((crc >> 1) ^ CRC32_POLY) : (crc >> 1);
        }
        s_table[i] = crc;
    }
    s_table_ready = 1;
}

uint32_t crc32_gen(const void *data, size_t len)
{
    if (!s_table_ready)
    {
        crc32_build_table();
    }

    const uint8_t *p   = (const uint8_t *)data;
    uint32_t       crc = 0xFFFFFFFFu;

    while (len--)
    {
        crc = (crc >> 8) ^ s_table[(crc ^ *p++) & 0xFFu];
    }

    return crc ^ 0xFFFFFFFFu;
}
