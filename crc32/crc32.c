#include "crc32.h"

static uint32_t crc32_table[256];
static int table_initialized = 0;

static void crc32_init_table(void) {
  uint32_t polynomial = 0xEDB88320;
  for (uint32_t i = 0; i < 256; i++) {
    uint32_t crc = i;
    for (uint32_t j = 0; j < 8; j++) {
      if (crc & 1) {
        crc = (crc >> 1) ^ polynomial;
      } else {
        crc >>= 1;
      }
    }
    crc32_table[i] = crc;
  }
  table_initialized = 1;
}

uint32_t crc32_gen(const void *data, size_t len) {
  if (!table_initialized) {
    crc32_init_table();
  }

  const uint8_t *p = (const uint8_t *)data;
  uint32_t crc = 0xFFFFFFFF;

  while (len--) {
    crc = (crc >> 8) ^ crc32_table[(crc ^ *p++) & 0xFF];
  }

  return crc ^ 0xFFFFFFFF;
}
