/**
 * @file nvs_internal.h
 * @brief Internal binary layout definitions for the NVS module.
 *
 * This header is private to nvs_lite.c. Do not include it from
 * application code.
 *
 * Flash layout (base_address = start of partition):
 *
 *   [Page 0]
 *   +---------------------------------+  Offset 0
 *   |  Page Header (32 bytes)         |
 *   +---------------------------------+  Offset 32
 *   |  State Bitmap                   |  2 bits per entry slot
 *   |  (ceil(N_ENTRIES/4) bytes,      |
 *   |   padded to 32-byte alignment)  |
 *   +---------------------------------+  Offset 32 + bitmap_size
 *   |  Entry[0]  (32 bytes)           |
 *   |  Entry[1]  (32 bytes)           |
 *   |  ...                            |
 *   |  Entry[N-1](32 bytes)           |
 *   +---------------------------------+
 *   [Page 1] ...
 *
 * State bitmap bit-pair encoding (per entry, MSB first within byte):
 *   11 = Empty   (erased flash, no data)
 *   10 = Written (valid data)
 *   00 = Erased  (logically deleted)
 *   01 = Reserved (treated as Erased on scan)
 *
 * This matches NOR-flash physics: bits can only go 1→0, never 0→1
 * without a sector erase. Atomicity is guaranteed:
 *   Step 1: write entry payload  (bits remain 11)
 *   Step 2: set bits to 10       (now visible as Written)
 * Power failure between steps leaves bits at 11 → entry is ignored.
 */

#ifndef NVS_INTERNAL_H
#define NVS_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "nvs_lite.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Compile-time geometry constants
 * --------------------------------------------------------------------- */

/** Magic word written at the start of every valid page header. */
#define NVS_PAGE_MAGIC          UINT32_C(0xDEADBEEF)

/** Size of every on-flash structure — always 32 bytes. */
#define NVS_ENTRY_SIZE          32u

/** Maximum number of key-value pairs in the in-RAM lookup table. */
#define NVS_MAX_KEYS            512u

/* -----------------------------------------------------------------------
 * Entry type codes  (stored in nvs_entry_hdr_t::type)
 * --------------------------------------------------------------------- */

#define NVS_TYPE_U8             0x01u
#define NVS_TYPE_I8             0x02u
#define NVS_TYPE_U16            0x03u
#define NVS_TYPE_I16            0x04u
#define NVS_TYPE_U32            0x05u
#define NVS_TYPE_I32            0x06u
#define NVS_TYPE_U64            0x07u
#define NVS_TYPE_I64            0x08u
#define NVS_TYPE_STR            0x10u   /**< Variable-length string         */
#define NVS_TYPE_BLOB           0x20u   /**< Variable-length binary blob    */
#define NVS_TYPE_ANY            0xFFu   /**< Wildcard for internal searches */

/* -----------------------------------------------------------------------
 * Page states (stored in nvs_page_hdr_t::state)
 * Each state is one step further from 0xFF, matching NOR-flash.
 * --------------------------------------------------------------------- */

#define NVS_PAGE_STATE_EMPTY    0xFFu   /**< Freshly erased, no header yet  */
#define NVS_PAGE_STATE_ACTIVE   0xFEu   /**< Currently accepting writes      */
#define NVS_PAGE_STATE_FULL     0xFCu   /**< No free slots remain            */
#define NVS_PAGE_STATE_ERASING  0xF8u   /**< GC in progress, do not read     */

/* -----------------------------------------------------------------------
 * State bitmap helpers
 * --------------------------------------------------------------------- */

#define NVS_BITMAP_EMPTY        0x3u    /**< 2-bit pattern: 11 — slot free   */
#define NVS_BITMAP_WRITTEN      0x2u    /**< 2-bit pattern: 10 — valid data  */
#define NVS_BITMAP_ERASED       0x0u    /**< 2-bit pattern: 00 — deleted     */

/* -----------------------------------------------------------------------
 * On-flash structures — all must remain exactly 32 bytes.
 * Use static_assert in nvs_lite.c to enforce this at compile time.
 * --------------------------------------------------------------------- */

/**
 * @brief Page header — occupies the first 32 bytes of every sector.
 *
 * CRC32 covers bytes [5..31] (i.e., everything after the crc field itself).
 */
typedef struct __attribute__((packed))
{
    uint32_t magic;         /**< NVS_PAGE_MAGIC                           */
    uint32_t sequence_no;   /**< Monotonically increasing write counter   */
    uint8_t  state;         /**< NVS_PAGE_STATE_* value                   */
    uint8_t  reserved[19];  /**< Must be 0xFF (erased)                    */
    uint32_t crc32;         /**< CRC32 of bytes [0..27] of this struct    */
} nvs_page_hdr_t;

/* Size check constant — validated by static_assert inside nvs_lite.c */
#define NVS_PAGE_HDR_SIZE       32u

/**
 * @brief One 32-byte NVS entry.
 *
 * For scalar types (U8..I64) the value is stored inline in the 8-byte
 * value field (little-endian, zero-padded).
 *
 * For strings/blobs:
 *   - span  = total number of entries consumed (1 header + N data entries)
 *   - value.str.total_size = byte length including null terminator
 *   - The raw payload bytes immediately follow in the next (span-1) slots
 *     at the same 32-byte granularity, each fully utilised.
 *
 * CRC32 covers bytes [8..31] (key + value).
 */
typedef struct __attribute__((packed))
{
    uint8_t  ns_index;          /**< Namespace index; 0 = NS registry     */
    uint8_t  type;              /**< NVS_TYPE_* code                       */
    uint8_t  span;              /**< Entry count for this key (>=1)        */
    uint8_t  chunk_index;       /**< For future blob chunking; 0 = single  */
    char     key[16];           /**< Null-terminated key (max 15 chars)    */
    union
    {
        uint8_t  u8;
        int8_t   i8;
        uint16_t u16;
        int16_t  i16;
        uint32_t u32;
        int32_t  i32;
        uint64_t u64;
        int64_t  i64;
        struct
        {
            uint32_t total_size;    /**< Byte length of string w/ '\0'     */
            uint32_t reserved;
        } str;
        uint8_t  raw[8];
    } value;                        /**< 8 bytes — inline or descriptor    */
    uint32_t crc32;             /**< CRC32 of bytes [0..27]                */
} nvs_entry_hdr_t;

/* Size check constant — validated by static_assert inside nvs_lite.c */
#define NVS_ENTRY_HDR_SIZE      32u

/* -----------------------------------------------------------------------
 * Data-continuation slot
 * These are the entry slots that follow a multi-entry (span > 1) header.
 * They hold raw payload bytes with no additional header overhead.
 * The payload bytes per continuation slot = NVS_ENTRY_SIZE (32 bytes).
 * --------------------------------------------------------------------- */
#define NVS_DATA_BYTES_PER_SLOT NVS_ENTRY_SIZE   /* 32 */

/* -----------------------------------------------------------------------
 * In-RAM state structures
 * --------------------------------------------------------------------- */

/**
 * @brief One record in the in-RAM lookup table.
 *
 * Built by nvs_init() by scanning all Written entries whose CRC32
 * validates.  The latest written entry for a given (ns_index, key)
 * pair wins.
 */
typedef struct
{
    char     key[NVS_KEY_MAX_LEN + 1];  /**< Null-terminated key           */
    uint8_t  ns_index;                   /**< Owning namespace index        */
    uint8_t  type;                       /**< NVS_TYPE_*                    */
    uint8_t  span;                       /**< Entry count (for strings)     */
    uint32_t flash_addr;                 /**< Absolute address of hdr entry */
} nvs_lookup_t;

/**
 * @brief Per-namespace record.
 *
 * Index 0 is the namespace registry itself (stores NS name→index mapping).
 * User namespaces occupy indices 1–NVS_MAX_NAMESPACES.
 */
typedef struct
{
    char    name[NVS_KEY_MAX_LEN + 1];  /**< Namespace name (human-readable) */
    uint8_t index;                       /**< Assigned NS index               */
    uint8_t in_use;                      /**< 1 if this slot is occupied      */
} nvs_namespace_t;

/**
 * @brief Per-open-handle record.
 */
typedef struct
{
    uint8_t         in_use;    /**< 1 if this handle slot is occupied     */
    nvs_open_mode_t mode;      /**< NVS_READONLY or NVS_READWRITE         */
    uint8_t         ns_index;  /**< Namespace this handle is bound to     */
} nvs_handle_rec_t;

/**
 * @brief Per-page runtime state tracked in RAM.
 */
typedef struct
{
    uint8_t  state;         /**< NVS_PAGE_STATE_* (mirrors flash)          */
    uint32_t seq_no;        /**< Sequence number from page header          */
    uint16_t free_count;    /**< Number of Empty entry slots remaining      */
    uint16_t written_count; /**< Number of Written entry slots             */
    uint16_t erased_count;  /**< Number of Erased entry slots              */
    uint16_t entry_count;   /**< Total entry slots in this page            */
    uint32_t base_addr;     /**< Absolute address of this page's start     */
    uint32_t data_start;    /**< Absolute address of Entry[0]              */
} nvs_page_t;

/* -----------------------------------------------------------------------
 * Global module state (defined in nvs_lite.c)
 * --------------------------------------------------------------------- */

#define NVS_INVALID_HANDLE      ((nvs_handle_t)0u)

#ifdef __cplusplus
}
#endif

#endif /* NVS_INTERNAL_H */
