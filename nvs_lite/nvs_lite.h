/**
 * @file nvs_lite.h
 * @brief Public API for the portable NVS (Non-Volatile Storage) module.
 *
 * Usage:
 *   1. Populate an nvs_config_t with your hardware flash callbacks and
 *      partition geometry.
 *   2. Call nvs_init() once at startup.
 *   3. Open namespaces with nvs_open(), then use set/get functions.
 *   4. Call nvs_commit() before power-down to guarantee data is flushed.
 *
 * All flash I/O is routed exclusively through the function pointers in
 * nvs_config_t — no direct hardware calls exist inside the module.
 */

#ifndef NVS_LITE_H
#define NVS_LITE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* -----------------------------------------------------------------------
 * Error codes
 * --------------------------------------------------------------------- */

#define NVS_OK                   0
#define NVS_ERR_NOT_INIT        -1   /**< nvs_init() not called yet        */
#define NVS_ERR_INVALID_ARG     -2   /**< NULL pointer or bad argument      */
#define NVS_ERR_NOT_FOUND       -3   /**< Key does not exist               */
#define NVS_ERR_NO_SPACE        -4   /**< Partition is full even after GC  */
#define NVS_ERR_HANDLE          -5   /**< Invalid or closed handle         */
#define NVS_ERR_READ_ONLY       -6   /**< Write attempted on RO handle     */
#define NVS_ERR_CORRUPT         -7   /**< CRC failure on existing entry    */
#define NVS_ERR_FLASH           -8   /**< Hardware flash operation failed  */
#define NVS_ERR_KEY_TOO_LONG    -9   /**< Key exceeds NVS_KEY_MAX_LEN      */
#define NVS_ERR_VALUE_TOO_LARGE -10  /**< Value too large for NVS entry    */
#define NVS_ERR_NS_FULL         -11  /**< Namespace table is full          */
#define NVS_ERR_BUF_TOO_SMALL   -12  /**< Caller buffer too small          */

/* -----------------------------------------------------------------------
 * Limits
 * --------------------------------------------------------------------- */

/** Maximum key length (null terminator not counted). */
#define NVS_KEY_MAX_LEN         15u

/** Maximum number of user namespaces (index 1–254; 0 = NS registry). */
#define NVS_MAX_NAMESPACES      254u

/** Maximum number of simultaneously open handles. */
#define NVS_MAX_HANDLES         8u

/* -----------------------------------------------------------------------
 * Hardware abstraction — must be populated by the caller
 * --------------------------------------------------------------------- */

/**
 * @brief Flash hardware configuration.
 *
 * All fields are mandatory. The module will not operate without valid
 * function pointers and a non-zero sector_size.
 *
 * Function pointer contracts:
 *   read  — copy @p len bytes from flash address @p addr into @p buf.
 *            Returns 0 on success, non-zero on failure.
 *   write — program @p len bytes from @p buf into flash at @p addr.
 *            The target range must already be erased (0xFF).
 *            Returns 0 on success, non-zero on failure.
 *   erase — erase exactly one sector whose base address is @p addr.
 *            @p addr must be sector-aligned.
 *            Returns 0 on success, non-zero on failure.
 */
typedef struct
{
    uint32_t sector_size;       /**< Bytes per erasable flash sector/page  */
    uint32_t num_sectors;       /**< Number of sectors in the NVS partition */
    uint32_t base_address;      /**< Absolute start address of the partition */

    int (*read) (uint32_t addr, void       *buf, uint32_t len);
    int (*write)(uint32_t addr, const void *buf, uint32_t len);
    int (*erase)(uint32_t addr);
} nvs_config_t;

/* -----------------------------------------------------------------------
 * Handle & mode
 * --------------------------------------------------------------------- */

/** Opaque handle returned by nvs_open(). */
typedef uint32_t nvs_handle_t;

/** Access mode for nvs_open(). */
typedef enum
{
    NVS_READONLY  = 0,
    NVS_READWRITE = 1
} nvs_open_mode_t;

/* -----------------------------------------------------------------------
 * Lifecycle
 * --------------------------------------------------------------------- */

/**
 * @brief Initialise the NVS module.
 *
 * Scans the entire partition via config->read, validates page headers,
 * rebuilds the in-RAM lookup table of all Written entries, and selects
 * the current Active page.  Must be called once before any other API.
 *
 * @param config  Pointer to a fully-populated hardware configuration struct.
 * @return NVS_OK on success, negative error code otherwise.
 */
int nvs_init(const nvs_config_t *config);

/**
 * @brief Open a namespace.
 *
 * If the namespace does not exist and mode is NVS_READWRITE, it is
 * created.  If mode is NVS_READONLY and the namespace does not exist,
 * NVS_ERR_NOT_FOUND is returned.
 *
 * @param name        Null-terminated namespace name (max NVS_KEY_MAX_LEN).
 * @param mode        NVS_READONLY or NVS_READWRITE.
 * @param out_handle  Receives the handle on success.
 * @return NVS_OK on success, negative error code otherwise.
 */
int nvs_open(const char *name, nvs_open_mode_t mode, nvs_handle_t *out_handle);

/**
 * @brief Commit pending writes for the given handle.
 *
 * In the current implementation all writes are immediately programmed
 * to flash; commit() issues a final config->write fence and validates
 * that the last-written entry's CRC is readable.
 *
 * @param handle  Handle obtained from nvs_open().
 * @return NVS_OK on success, negative error code otherwise.
 */
int nvs_commit(nvs_handle_t handle);

/**
 * @brief Close a handle and release its resources.
 *
 * @param handle  Handle obtained from nvs_open().
 */
void nvs_close(nvs_handle_t handle);

/* -----------------------------------------------------------------------
 * Integer primitives
 * --------------------------------------------------------------------- */

int nvs_set_u8 (nvs_handle_t handle, const char *key, uint8_t  value);
int nvs_get_u8 (nvs_handle_t handle, const char *key, uint8_t  *out_value);

int nvs_set_i8 (nvs_handle_t handle, const char *key, int8_t   value);
int nvs_get_i8 (nvs_handle_t handle, const char *key, int8_t   *out_value);

int nvs_set_u16(nvs_handle_t handle, const char *key, uint16_t value);
int nvs_get_u16(nvs_handle_t handle, const char *key, uint16_t *out_value);

int nvs_set_i16(nvs_handle_t handle, const char *key, int16_t  value);
int nvs_get_i16(nvs_handle_t handle, const char *key, int16_t  *out_value);

int nvs_set_u32(nvs_handle_t handle, const char *key, uint32_t value);
int nvs_get_u32(nvs_handle_t handle, const char *key, uint32_t *out_value);

int nvs_set_i32(nvs_handle_t handle, const char *key, int32_t  value);
int nvs_get_i32(nvs_handle_t handle, const char *key, int32_t  *out_value);

int nvs_set_u64(nvs_handle_t handle, const char *key, uint64_t value);
int nvs_get_u64(nvs_handle_t handle, const char *key, uint64_t *out_value);

int nvs_set_i64(nvs_handle_t handle, const char *key, int64_t  value);
int nvs_get_i64(nvs_handle_t handle, const char *key, int64_t  *out_value);

/* -----------------------------------------------------------------------
 * String / blob
 * --------------------------------------------------------------------- */

/**
 * @brief Write a null-terminated string.
 *
 * The string (including its null terminator) is serialised across as
 * many consecutive 32-byte entries as required (Span field).
 *
 * @param handle  Open read-write handle.
 * @param key     Key string (max NVS_KEY_MAX_LEN characters).
 * @param value   Null-terminated string to store.
 * @return NVS_OK on success, negative error code otherwise.
 */
int nvs_set_str(nvs_handle_t handle, const char *key, const char *value);

/**
 * @brief Read a null-terminated string.
 *
 * If @p buf is NULL, @p len is set to the required buffer size
 * (including the null terminator) and NVS_OK is returned — the caller
 * can then allocate and call again.
 *
 * @param handle  Open handle (any mode).
 * @param key     Key string.
 * @param buf     Destination buffer, or NULL to query required size.
 * @param len     In/out: buffer size on entry, actual length on exit.
 * @return NVS_OK on success, negative error code otherwise.
 */
int nvs_get_str(nvs_handle_t handle, const char *key, char *buf, size_t *len);

/**
 * @brief Erase a single key from a namespace.
 *
 * Marks the entry (and all its span entries) as Erased in the state
 * bitmap and removes it from the in-RAM lookup table.
 *
 * @param handle  Open read-write handle.
 * @param key     Key to erase.
 * @return NVS_OK, NVS_ERR_NOT_FOUND, or other error code.
 */
int nvs_erase_key(nvs_handle_t handle, const char *key);

/**
 * @brief Erase all keys belonging to a namespace.
 *
 * @param handle  Open read-write handle.
 * @return NVS_OK on success, negative error code otherwise.
 */
int nvs_erase_all(nvs_handle_t handle);

/* -----------------------------------------------------------------------
 * Binary blob
 * --------------------------------------------------------------------- */

/**
 * @brief Write a binary blob.
 *
 * The blob is serialised across as many consecutive 32-byte entries as
 * required (Span field), identical to the string encoding but without a
 * null terminator.
 *
 * @param handle  Open read-write handle.
 * @param key     Key string (max NVS_KEY_MAX_LEN characters).
 * @param data    Pointer to the data to store.
 * @param len     Number of bytes to store.
 * @return NVS_OK on success, negative error code otherwise.
 */
int nvs_set_blob(nvs_handle_t handle, const char *key,
                 const void *data, size_t len);

/**
 * @brief Read a binary blob.
 *
 * If @p buf is NULL, @p len is set to the required buffer size and
 * NVS_OK is returned — the caller can then allocate and call again.
 *
 * @param handle  Open handle (any mode).
 * @param key     Key string.
 * @param buf     Destination buffer, or NULL to query required size.
 * @param len     In/out: buffer size on entry, actual length on exit.
 * @return NVS_OK on success, negative error code otherwise.
 */
int nvs_get_blob(nvs_handle_t handle, const char *key,
                 void *buf, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* NVS_LITE_H */
