#ifndef NVS_H
#define NVS_H

#include <stdint.h>
#include <stddef.h>

/*===========================================================================
 *  Constants
 *===========================================================================*/

/** Sector header magic word: "NVS!" in little-endian */
#define NVS_MAGIC_WORD          (0x4E565321U)

/** Sector states (bit-flip progression: 1 -> 0 only) */
#define NVS_SECTOR_EMPTY        (0xFFFFFFFFU)
#define NVS_SECTOR_ACTIVE       (0xFFFFFF00U)
#define NVS_SECTOR_FULL         (0xFFFF0000U)

/** Entry states (bit-flip progression: 1 -> 0 only) */
#define NVS_ENTRY_WRITING       (0xFFU)
#define NVS_ENTRY_VALID         (0xFEU)
#define NVS_ENTRY_DELETED       (0x00U)

/** Size limits */
#define NVS_MAX_KEY_LEN         (15U)
#define NVS_MAX_DATA_LEN        (128U)

/** Sector header size in bytes */
#define NVS_SECTOR_HDR_SIZE     (12U)

/** Entry fixed header size in bytes (state + key_len + data_len + reserved + crc32) */
#define NVS_ENTRY_HDR_SIZE      (8U)

/*===========================================================================
 *  Types
 *===========================================================================*/

/** Error codes */
typedef enum
{
    NVS_OK = 0,
    NVS_ERR_NOT_FOUND,
    NVS_ERR_NO_SPACE,
    NVS_ERR_FLASH,
    NVS_ERR_CRC,
    NVS_ERR_INVALID_ARG
} nvs_err_t;

/*===========================================================================
 *  Packed on-flash structures (for documentation; actual I/O uses byte
 *  arrays to avoid compiler alignment pitfalls)
 *===========================================================================*/

/**
 * Sector header layout (12 bytes):
 *
 *   Offset  Field           Size
 *   0x00    magic           4 B   (0x4E565321)
 *   0x04    seq_num         4 B   (monotonically increasing)
 *   0x08    state           4 B   (Empty / Active / Full)
 */

/**
 * Entry layout (8 B fixed header + key + data + padding):
 *
 *   Offset  Field           Size
 *   0x00    state           1 B   (Writing / Valid / Deleted)
 *   0x01    key_len         1 B
 *   0x02    data_len        1 B   (max 128)
 *   0x03    reserved        1 B   (0xFF)
 *   0x04    crc32           4 B   (over key_len + data_len + key + data)
 *   0x08    key[]           key_len B
 *   0x08+K  data[]          data_len B
 *           padding         P B   (0xFF to 4-byte align total)
 */

/*===========================================================================
 *  RAM context — 12 bytes total
 *===========================================================================*/

typedef struct
{
    uint32_t active_sector_addr;    /**< Base address of the current active sector  */
    uint32_t write_offset;          /**< Next free byte offset within active sector */
    uint32_t seq_counter;           /**< Highest sequence number seen               */
} nvs_context_t;

/*===========================================================================
 *  Public API
 *===========================================================================*/

/**
 * @brief Mount / initialize the NVS system.
 *
 * Scans all flash sectors, locates (or creates) the active sector,
 * and reconstructs the minimal RAM context.
 *
 * @return NVS_OK on success.
 */
nvs_err_t nvs_mount(void);

/**
 * @brief Write a key-value pair.
 *
 * Appends a new entry.  If the key already exists, the old entry is
 * invalidated.  Handles sector-boundary skip logic internally.
 *
 * @param key   Null-terminated key string (max 15 chars).
 * @param data  Pointer to binary payload.
 * @param len   Payload length in bytes (max 128).
 * @return NVS_OK on success, NVS_ERR_NO_SPACE if flash is full.
 */
nvs_err_t nvs_write(const char *key, const void *data, uint8_t len);

/**
 * @brief Read the latest value for a key.
 *
 * Scans flash in reverse-chronological order.  Verifies CRC32 before
 * returning data.
 *
 * @param key       Null-terminated key string.
 * @param buf       Destination buffer.
 * @param buf_size  Size of the destination buffer.
 * @param out_len   [out] Actual data length written to buf.
 * @return NVS_OK on success, NVS_ERR_NOT_FOUND if key does not exist.
 */
nvs_err_t nvs_read(const char *key, void *buf, uint8_t buf_size, uint8_t *out_len);

/**
 * @brief Delete a key (mark all its valid entries as deleted).
 *
 * @param key  Null-terminated key string.
 * @return NVS_OK on success, NVS_ERR_NOT_FOUND if key does not exist.
 */
nvs_err_t nvs_delete(const char *key);

#endif /* NVS_H */
