#ifndef NVS_INTERNAL_H
#define NVS_INTERNAL_H

/** Sector header magic word: "NVS!" in little-endian */
#define NVS_MAGIC_WORD          (0x4E565321U)

/** Sector states (bit-flip progression: 1 -> 0 only) */
#define NVS_SECTOR_ACTIVE       (0xFFFFFF00U)
#define NVS_SECTOR_FULL         (0xFFFF0000U)
/** Source sector being reclaimed by GC. Bit-flip reachable from FULL. */
#define NVS_SECTOR_FREEING      (0xFF000000U)

/** Entry states (bit-flip progression: 1 -> 0 only) */
#define NVS_ENTRY_WRITING       (0xFFU)
#define NVS_ENTRY_VALID         (0xFEU)
#define NVS_ENTRY_DELETED       (0x00U)

/** Sector header size in bytes */
#define NVS_SECTOR_HDR_SIZE     (16U)

/** Entry fixed header size in bytes (state + key_len + data_len + reserved + crc32) */
#define NVS_ENTRY_HDR_SIZE      (8U)

#endif /* NVS_INTERNAL_H */
