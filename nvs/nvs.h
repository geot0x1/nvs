#ifndef NVS_H
#define NVS_H

#include <stdint.h>
#include <stddef.h>

/*===========================================================================
 *  Constants
 *===========================================================================*/

/** Maximum key length (null terminator not included). */
#define NVS_MAX_KEY_LEN         (15U)

/** Maximum value payload size in bytes. */
#define NVS_MAX_DATA_LEN        (128U)

/** Maximum number of flash sectors that can be assigned to NVS. */
#define NVS_MAX_SECTORS         (16U)

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
    NVS_ERR_INVALID_ARG,
    NVS_ERR_TOO_MANY_SECTORS
} nvs_err_t;

/** Per-partition sector health summary, populated by nvs_get_stats(). */
typedef struct
{
    uint8_t total_sectors;   /**< sector_count from the mounted driver */
    uint8_t active_sectors;  /**< sectors with a valid header (any state) */
    uint8_t corrupt_sectors; /**< sectors skipped at mount due to bad CRC */
    uint8_t free_sectors;    /**< sectors that are fully blank (0xFF) */
} NvsSectorStats;

/*===========================================================================
 *  Flash driver interface — injected at mount time
 *===========================================================================*/

/**
 * The flash driver provides all hardware-specific I/O operations.
 * The caller fills in the function pointers and flash geometry,
 * then passes a pointer to nvs_mount().  The NVS module stores
 * a copy internally and never references a concrete flash HAL.
 *
 * Thread safety: all public API calls (nvs_mount, nvs_read, nvs_write,
 * nvs_delete, nvs_format) must be serialized by the caller unless the
 * optional lock/unlock hooks below are populated.
 */
typedef struct
{
    /** Write `len` bytes from `data` to flash address `addr`. */
    void (*write)(uint32_t addr, const void *data, uint16_t len);

    /** Read `len` bytes from flash address `addr` into `data`. */
    void (*read)(uint32_t addr, void *data, uint16_t len);

    /** Erase the sector that contains `addr`. */
    void (*erase_sector)(uint32_t addr);

    /** Size of one flash sector in bytes (e.g. 4096). */
    uint32_t sector_size;

    /** Number of sectors allocated to NVS. */
    uint8_t  sector_count;

    /**
     * Acquire the NVS lock before a public API call.
     * Optional — set to NULL for single-threaded use.
     */
    void (*lock)(void);

    /**
     * Release the NVS lock after a public API call.
     * Optional — set to NULL for single-threaded use.
     */
    void (*unlock)(void);
} nvs_flash_driver_t;

/*===========================================================================
 *  Public API
 *===========================================================================*/

/**
 * @brief Mount / initialize the NVS system.
 *
 * Stores a copy of the flash driver, scans all sectors, locates
 * (or creates) the active sector, and reconstructs the RAM context.
 *
 * @param driver  Pointer to a populated flash driver struct.
 * @return NVS_OK on success.
 */
nvs_err_t nvs_mount(const nvs_flash_driver_t *driver);

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
 * **CRC Policy (fail-safe):** If the newest copy of a key fails CRC verification,
 * NVS_ERR_CRC is returned immediately. No fallback to older copies is attempted.
 * Rationale: returning stale data silently when corruption is detected is considered
 * more dangerous than surfacing the corruption to the caller, allowing them to decide
 * recovery or retry logic.
 *
 * @param key       Null-terminated key string.
 * @param buf       Destination buffer.
 * @param buf_size  Size of the destination buffer.
 * @param out_len   [out] Actual data length written to buf.
 * @return NVS_OK on success, NVS_ERR_NOT_FOUND if key does not exist,
 *         NVS_ERR_CRC if the newest copy fails CRC verification.
 */
nvs_err_t nvs_read(const char *key, void *buf, uint8_t buf_size, uint8_t *out_len);

/**
 * @brief Delete a key (mark all its valid entries as deleted).
 *
 * @param key  Null-terminated key string.
 * @return NVS_OK on success, NVS_ERR_NOT_FOUND if key does not exist.
 */
nvs_err_t nvs_delete(const char *key);

/**
 * @brief Erase all NVS sectors and re-initialize the first sector as ACTIVE.
 *
 * All stored key-value pairs are permanently destroyed.  The NVS driver must
 * have been mounted before calling this function.
 *
 * @return NVS_OK on success, NVS_ERR_INVALID_ARG if the driver is not mounted.
 */
nvs_err_t nvs_format(void);

/**
 * @brief Query the stored data length for a key without reading the data.
 *
 * Performs the same locate-and-CRC-verify as nvs_read() but writes only the
 * data length to *out_size, leaving the caller free to allocate an exact-fit
 * buffer before calling nvs_read().
 *
 * @param key       Null-terminated key string.
 * @param out_size  [out] Stored data length in bytes.
 * @return NVS_OK on success, NVS_ERR_NOT_FOUND if key does not exist,
 *         NVS_ERR_CRC if the newest copy fails CRC verification.
 */
nvs_err_t nvs_get_size(const char *key, uint8_t *out_size);

/**
 * @brief Return a snapshot of sector health for the mounted partition.
 *
 * corrupt_sectors counts sectors that had a recognisable magic word at mount
 * time but failed CRC verification — these sectors are inaccessible and their
 * former contents are lost.  A non-zero value indicates flash degradation or
 * a torn sector-header write that was never cleaned up.
 *
 * @param out_stats  [out] Populated sector health struct.
 * @return NVS_OK on success, NVS_ERR_INVALID_ARG if out_stats is NULL or
 *         the driver is not mounted.
 */
nvs_err_t nvs_get_stats(NvsSectorStats *out_stats);

#endif /* NVS_H */
