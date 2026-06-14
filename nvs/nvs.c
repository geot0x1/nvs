#include "nvs.h"
#include "crc32.h"

#include <string.h>

/*===========================================================================
 *  Module-level state
 *===========================================================================*/

static nvs_context_t g_nvs;

/*===========================================================================
 *  Convenience macros for driver calls
 *===========================================================================*/

#define DRV_WRITE(addr, data, len)   g_nvs.driver.write((addr), (data), (len))
#define DRV_READ(addr, data, len)    g_nvs.driver.read((addr), (data), (len))
#define DRV_ERASE(addr)              g_nvs.driver.erase_sector((addr))
#define SECTOR_SIZE                  g_nvs.driver.sector_size
#define SECTOR_COUNT                 g_nvs.driver.sector_count

/*===========================================================================
 *  Internal helpers — sector addressing
 *===========================================================================*/

/** Return the base flash address for a given sector index (0-based). */
static inline uint32_t sector_addr(uint8_t idx)
{
    return (uint32_t)idx * SECTOR_SIZE;
}

/** Align a value up to the next multiple of 4. */
static inline uint32_t align4(uint32_t v)
{
    return (v + 3U) & ~3U;
}

/** Calculate the total on-flash size of an entry. */
static inline uint32_t entry_total_size(uint8_t key_len, uint8_t data_len)
{
    return align4(NVS_ENTRY_HDR_SIZE + (uint32_t)key_len + (uint32_t)data_len);
}

/*===========================================================================
 *  Internal helpers — sector header I/O
 *===========================================================================*/

/**
 * Read a sector header (all 16 bytes) and verify CRC.
 * Returns 1 if magic matches and either:
 *   - CRC is valid (fresh header write), OR
 *   - State is not 0xFF (header was state-transitioned after CRC was written)
 * Returns 0 if magic doesn't match or header is clearly corrupted.
 */
static int read_sector_hdr(uint32_t base,
                           uint32_t *magic,
                           uint32_t *seq,
                           uint32_t *state)
{
    uint8_t buf[NVS_SECTOR_HDR_SIZE];
    DRV_READ(base, buf, NVS_SECTOR_HDR_SIZE);

    memcpy(magic, buf + 0, 4);
    memcpy(seq,   buf + 4, 4);
    memcpy(state, buf + 8, 4);

    if (*magic != NVS_MAGIC_WORD)
    {
        return 0;
    }

    uint32_t stored_crc;
    memcpy(&stored_crc, buf + 12, 4);
    uint32_t calc_crc = crc32_gen(buf, 12);

    if (calc_crc == stored_crc)
    {
        return 1; /* Fresh write with valid CRC */
    }

    if (*state != 0xFFFFFFFFU)
    {
        return 1; /* State was transitioned after CRC was written — valid */
    }

    return 0; /* CRC mismatch on fresh header (torn write) */
}

/** Write a full sector header (magic + seq + state + CRC). */
static void write_sector_hdr(uint32_t base, uint32_t seq, uint32_t state)
{
    uint8_t hdr[NVS_SECTOR_HDR_SIZE];
    uint32_t magic = NVS_MAGIC_WORD;
    uint32_t crc;

    memcpy(hdr + 0,  &magic, 4);
    memcpy(hdr + 4,  &seq,   4);
    memcpy(hdr + 8,  &state, 4);

    crc = crc32_gen(hdr, 12);
    memcpy(hdr + 12, &crc,   4);

    DRV_WRITE(base, hdr, NVS_SECTOR_HDR_SIZE);
}

/** Transition a sector to a new state (bit-flip only, no erase needed). */
static void set_sector_state(uint32_t base, uint32_t new_state)
{
    DRV_WRITE(base + 8, &new_state, sizeof(new_state));
}

/*===========================================================================
 *  Internal helpers — entry I/O
 *===========================================================================*/

/**
 * Read an entry header (first 8 bytes) from flash.
 * Outputs the individual fields; returns the state byte.
 */
static uint8_t read_entry_hdr(uint32_t addr,
                              uint8_t *key_len,
                              uint8_t *data_len,
                              uint32_t *crc)
{
    uint8_t hdr[NVS_ENTRY_HDR_SIZE];
    DRV_READ(addr, hdr, NVS_ENTRY_HDR_SIZE);

    *key_len  = hdr[1];
    *data_len = hdr[2];

    /* CRC32 is stored at bytes 4..7, little-endian */
    *crc = (uint32_t)hdr[4]
         | ((uint32_t)hdr[5] << 8)
         | ((uint32_t)hdr[6] << 16)
         | ((uint32_t)hdr[7] << 24);

    return hdr[0]; /* state */
}

/**
 * Compute the CRC32 for an entry.
 * The CRC covers: key_len (1 B) + data_len (1 B) + key[] + data[].
 */
static uint32_t compute_entry_crc(uint8_t key_len, uint8_t data_len,
                                  const uint8_t *key, const uint8_t *data)
{
    /*
     * Build a contiguous buffer on the stack.
     * Max size: 2 + 15 + 128 = 145 bytes.
     */
    uint8_t buf[2 + NVS_MAX_KEY_LEN + NVS_MAX_DATA_LEN];
    uint32_t len = 0;

    buf[len++] = key_len;
    buf[len++] = data_len;
    memcpy(&buf[len], key, key_len);
    len += key_len;
    memcpy(&buf[len], data, data_len);
    len += data_len;

    return crc32_gen(buf, len);
}

/** Set an entry's state byte (single flash byte write). */
static void set_entry_state(uint32_t entry_addr, uint8_t new_state)
{
    DRV_WRITE(entry_addr, &new_state, 1);
}

/*===========================================================================
 *  Internal helpers — sector scanning
 *===========================================================================*/

/**
 * Compare a key against the key stored at a flash entry address.
 * Returns 1 if they match, 0 otherwise.
 */
static int key_matches_flash(uint32_t entry_addr, const char *key, uint8_t key_len)
{
    uint8_t flash_key[NVS_MAX_KEY_LEN];
    DRV_READ(entry_addr + NVS_ENTRY_HDR_SIZE, flash_key, key_len);
    return memcmp(flash_key, key, key_len) == 0;
}

/**
 * Callback type for walk_sector_entries().
 *
 * @param base       Sector base address.
 * @param off        Byte offset of the current entry within the sector.
 * @param st         Entry state byte.
 * @param kl         key_len field from entry header.
 * @param dl         data_len field from entry header.
 * @param crc        CRC32 field from entry header.
 * @param ctx        Caller-supplied context pointer.
 * @return  0 — continue walking; 1 — stop immediately.
 */
typedef int (*entry_visitor_t)(uint32_t base, uint32_t off,
                               uint8_t st, uint8_t kl, uint8_t dl,
                               uint32_t crc, void *ctx);

/**
 * Walk all entries in a sector, invoking visitor() for each one.
 * Stops when an WRITING entry is hit, sizes are out-of-range, or the
 * visitor returns 1.
 */
static void walk_sector_entries(uint32_t base, entry_visitor_t visitor, void *ctx)
{
    uint32_t off = NVS_SECTOR_HDR_SIZE;
    while (off < SECTOR_SIZE)
    {
        uint8_t  kl, dl;
        uint32_t crc;
        uint8_t  st = read_entry_hdr(base + off, &kl, &dl, &crc);

        if (st == NVS_ENTRY_WRITING)
        {
            break;
        }
        if (kl == 0 || kl > NVS_MAX_KEY_LEN || dl > NVS_MAX_DATA_LEN)
        {
            break;
        }

        if (visitor(base, off, st, kl, dl, crc, ctx))
        {
            break;
        }

        off += entry_total_size(kl, dl);
    }
}

/**
 * Write a key-value entry to the active sector: build the on-flash layout,
 * write it, then commit the state to VALID.
 * Advances g_nvs.write_offset by the entry's total size.
 *
 * @return The flash address at which the entry was written.
 */
static uint32_t write_entry_to_active(uint8_t key_len, uint8_t data_len,
                                      const uint8_t *key, const uint8_t *data)
{
    uint32_t esz = entry_total_size(key_len, data_len);
    uint32_t dest = g_nvs.active_sector_addr + g_nvs.write_offset;

    uint8_t entry[NVS_ENTRY_HDR_SIZE + NVS_MAX_KEY_LEN + NVS_MAX_DATA_LEN + 4];
    memset(entry, 0xFF, esz);

    entry[0] = NVS_ENTRY_WRITING;
    entry[1] = key_len;
    entry[2] = data_len;
    entry[3] = 0xFF;

    uint32_t crc = compute_entry_crc(key_len, data_len, key, data);
    entry[4] = (uint8_t)(crc);
    entry[5] = (uint8_t)(crc >> 8);
    entry[6] = (uint8_t)(crc >> 16);
    entry[7] = (uint8_t)(crc >> 24);

    memcpy(&entry[NVS_ENTRY_HDR_SIZE], key, key_len);
    memcpy(&entry[NVS_ENTRY_HDR_SIZE + key_len], data, data_len);

    DRV_WRITE(dest, entry, (uint16_t)esz);
    set_entry_state(dest, NVS_ENTRY_VALID);

    g_nvs.write_offset += esz;
    return dest;
}

/**
 * Build an ordered list of sector indices sorted by sequence number
 * (descending).  Only sectors with a valid header are included.
 *
 * @param out_indices   Output array (caller must size to sector_count).
 * @param out_count     Number of valid sectors found.
 */
static void get_sectors_by_seq_desc(uint8_t *out_indices, uint8_t *out_count)
{
    uint32_t seqs[NVS_MAX_SECTORS];
    uint8_t  valid[NVS_MAX_SECTORS];
    uint8_t  n = 0;

    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t magic, seq, state;
        if (read_sector_hdr(sector_addr(i), &magic, &seq, &state))
        {
            valid[n] = i;
            seqs[n]  = seq;
            n++;
        }
    }

    /* Simple insertion sort (trivial for small N). */
    for (uint8_t i = 1; i < n; i++)
    {
        uint32_t s = seqs[i];
        uint8_t  v = valid[i];
        int j = (int)i - 1;
        while (j >= 0 && seqs[j] < s)
        {
            seqs[j + 1]  = seqs[j];
            valid[j + 1] = valid[j];
            j--;
        }
        seqs[j + 1]  = s;
        valid[j + 1] = v;
    }

    memcpy(out_indices, valid, n);
    *out_count = n;
}

/*===========================================================================
 *  Internal — garbage collection (called automatically, not part of API)
 *===========================================================================*/

/* Forward declarations */
static int newer_copy_exists(const char *key, uint8_t key_len, uint32_t src_seq);

typedef struct
{
    uint32_t target_seq;
    int      all_copied;
} gc_resume_ctx_t;

typedef struct
{
    const char *key;
    uint8_t     key_len;
    uint32_t    skip_addr; /* pass UINT32_MAX to invalidate all matches */
    int         found;
} invalidate_ctx_t;

typedef struct
{
    const char *key;
    uint8_t     key_len;
    uint32_t    match_off;
    uint8_t     match_dl;
    int         found;
} find_last_ctx_t;

static int invalidate_visitor(uint32_t base, uint32_t off,
                              uint8_t st, uint8_t kl, uint8_t dl,
                              uint32_t crc, void *ctx)
{
    (void)dl; (void)crc;
    invalidate_ctx_t *c = (invalidate_ctx_t *)ctx;

    if (st == NVS_ENTRY_VALID && kl == c->key_len
        && (base + off) != c->skip_addr
        && key_matches_flash(base + off, c->key, kl))
    {
        set_entry_state(base + off, NVS_ENTRY_DELETED);
        c->found = 1;
    }
    return 0;
}

static int find_last_visitor(uint32_t base, uint32_t off,
                             uint8_t st, uint8_t kl, uint8_t dl,
                             uint32_t crc, void *ctx)
{
    (void)crc;
    find_last_ctx_t *c = (find_last_ctx_t *)ctx;

    if (st == NVS_ENTRY_VALID && kl == c->key_len
        && key_matches_flash(base + off, c->key, kl))
    {
        c->match_off = off;
        c->match_dl  = dl;
        c->found     = 1;
    }
    return 0;
}

static int gc_resume_visitor(uint32_t base, uint32_t off,
                             uint8_t st, uint8_t kl, uint8_t dl,
                             uint32_t crc, void *ctx)
{
    (void)crc;
    gc_resume_ctx_t *c = (gc_resume_ctx_t *)ctx;

    if (st != NVS_ENTRY_VALID)
    {
        return 0;
    }

    uint8_t key_buf[NVS_MAX_KEY_LEN];
    uint8_t data_buf[NVS_MAX_DATA_LEN];
    DRV_READ(base + off + NVS_ENTRY_HDR_SIZE, key_buf, kl);
    DRV_READ(base + off + NVS_ENTRY_HDR_SIZE + kl, data_buf, dl);

    if (newer_copy_exists((const char *)key_buf, kl, c->target_seq))
    {
        return 0;
    }

    if (g_nvs.write_offset + entry_total_size(kl, dl) > SECTOR_SIZE)
    {
        c->all_copied = 0;
        return 1; /* stop — cannot fit, abort GC */
    }

    write_entry_to_active(kl, dl, key_buf, data_buf);
    return 0;
}

/**
 * Resume GC: copy valid entries from target sector to active sector, then erase.
 * Called after a target sector has been selected and a FREEING marker written.
 */
static nvs_err_t nvs_gc_resume(uint32_t target_base, uint32_t target_seq)
{
    set_sector_state(target_base, NVS_SECTOR_FREEING);

    gc_resume_ctx_t ctx = { .target_seq = target_seq, .all_copied = 1 };
    walk_sector_entries(target_base, gc_resume_visitor, &ctx);

    if (!ctx.all_copied)
    {
        return NVS_ERR_NO_SPACE;
    }

    DRV_ERASE(target_base);
    return NVS_OK;
}

typedef struct
{
    const char *key;
    uint8_t     key_len;
    int         found;
} newer_copy_ctx_t;

static int newer_copy_visitor(uint32_t base, uint32_t off,
                              uint8_t st, uint8_t kl, uint8_t dl,
                              uint32_t crc, void *ctx)
{
    (void)dl; (void)crc;
    newer_copy_ctx_t *c = (newer_copy_ctx_t *)ctx;

    if (st == NVS_ENTRY_VALID && kl == c->key_len
        && key_matches_flash(base + off, c->key, kl))
    {
        c->found = 1;
        return 1; /* stop */
    }
    return 0;
}

/**
 * Check if a newer valid copy of a key exists in any sector with a
 * sequence number higher than `src_seq`.
 */
static int newer_copy_exists(const char *key, uint8_t key_len, uint32_t src_seq)
{
    newer_copy_ctx_t ctx = { .key = key, .key_len = key_len, .found = 0 };

    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t base = sector_addr(i);
        uint32_t magic, seq, state;

        if (!read_sector_hdr(base, &magic, &seq, &state))
        {
            continue;
        }
        if (seq <= src_seq)
        {
            continue;
        }

        walk_sector_entries(base, newer_copy_visitor, &ctx);
        if (ctx.found)
        {
            return 1;
        }
    }
    return 0;
}

/**
 * Internal garbage collection.
 *
 * Finds the Full sector with the lowest sequence number and calls nvs_gc_resume()
 * to copy valid entries and erase the old sector.
 *
 * @return NVS_OK if a sector was reclaimed, NVS_ERR_NO_SPACE otherwise.
 */
static nvs_err_t nvs_gc(void)
{
    /* Find the Full sector with the lowest sequence number. */
    uint32_t lowest_seq  = 0xFFFFFFFF;
    int      target_idx  = -1;

    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t base = sector_addr(i);
        uint32_t magic, seq, state;

        if (!read_sector_hdr(base, &magic, &seq, &state))
        {
            continue;
        }
        if (state == NVS_SECTOR_FULL && seq < lowest_seq)
        {
            lowest_seq = seq;
            target_idx = (int)i;
        }
    }

    if (target_idx < 0)
    {
        return NVS_ERR_NO_SPACE; /* nothing to collect */
    }

    uint32_t target_base = sector_addr((uint8_t)target_idx);
    uint32_t target_seq  = lowest_seq;

    return nvs_gc_resume(target_base, target_seq);
}

/*===========================================================================
 *  Internal — activate a new empty sector
 *===========================================================================*/

/**
 * Scan for an erased sector and format it ACTIVE.
 * Does NOT call nvs_gc(); used by nvs_gc_resume() to avoid recursion.
 *
 * @return NVS_OK if an empty sector was found and activated, NVS_ERR_NO_SPACE otherwise.
 */
static nvs_err_t activate_empty_sector_only(void)
{
    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t base = sector_addr(i);
        uint32_t magic_val;
        DRV_READ(base, &magic_val, sizeof(magic_val));

        if (magic_val == 0xFFFFFFFF) /* entire header is erased */
        {
            g_nvs.seq_counter++;
            write_sector_hdr(base, g_nvs.seq_counter, NVS_SECTOR_ACTIVE);
            g_nvs.active_sector_addr = base;
            g_nvs.write_offset       = NVS_SECTOR_HDR_SIZE;
            return NVS_OK;
        }
    }

    return NVS_ERR_NO_SPACE;
}

/**
 * Find an Empty sector, format it as Active, and update the RAM context.
 * If no Empty sector exists, run GC first.
 *
 * @return NVS_OK on success, NVS_ERR_NO_SPACE if all sectors are in use
 *         and GC could not free one.
 */
static nvs_err_t activate_next_sector(void)
{
    /* First pass: look for an already-empty sector. */
    nvs_err_t rc = activate_empty_sector_only();
    if (rc == NVS_OK)
    {
        return NVS_OK;
    }

    /* No empty sector — try garbage collection. */
    rc = nvs_gc();
    if (rc != NVS_OK)
    {
        return NVS_ERR_NO_SPACE;
    }

    /* After GC there should be an empty sector — try again. */
    return activate_empty_sector_only();
}

/*===========================================================================
 *  Public API — nvs_mount
 *===========================================================================*/

nvs_err_t nvs_mount(const nvs_flash_driver_t *driver)
{
    if (driver == NULL ||
        driver->write == NULL ||
        driver->read  == NULL ||
        driver->erase_sector == NULL ||
        driver->sector_size == 0 ||
        driver->sector_count == 0 ||
        driver->sector_count > NVS_MAX_SECTORS)
    {
        return NVS_ERR_INVALID_ARG;
    }

    /* Store a copy of the driver so callers don't need to keep it alive. */
    g_nvs.driver = *driver;
    g_nvs.seq_counter = 0;

    uint32_t best_seq  = 0;
    int      best_idx  = -1;

    /* Scan all sector headers. */
    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t magic, seq, state;
        if (read_sector_hdr(sector_addr(i), &magic, &seq, &state))
        {
            if (state == NVS_SECTOR_ACTIVE && seq >= best_seq)
            {
                best_seq = seq;
                best_idx = (int)i;
            }
            /* Track the global highest sequence number regardless of state. */
            if (seq > g_nvs.seq_counter)
            {
                g_nvs.seq_counter = seq;
            }
        }
    }

    if (best_idx < 0)
    {
        /* No active sector found. Check if flash is truly blank or has FULL sectors. */
        int has_full = 0;
        for (uint8_t i = 0; i < SECTOR_COUNT; i++)
        {
            uint32_t magic, seq, state;
            if (read_sector_hdr(sector_addr(i), &magic, &seq, &state)
                && state == NVS_SECTOR_FULL)
            {
                has_full = 1;
                break;
            }
        }

        if (has_full)
        {
            /* Flash is not blank — run GC to reclaim a FULL sector. */
            return activate_next_sector();
        }

        /* Truly blank flash — first-time format. */
        g_nvs.seq_counter = 1;
        write_sector_hdr(sector_addr(0), 1, NVS_SECTOR_ACTIVE);
        g_nvs.active_sector_addr = sector_addr(0);
        g_nvs.write_offset       = NVS_SECTOR_HDR_SIZE;
        return NVS_OK;
    }

    g_nvs.active_sector_addr = sector_addr((uint8_t)best_idx);

    /* Walk entries to find write_offset (first free byte). */
    uint32_t off = NVS_SECTOR_HDR_SIZE;
    while (off < SECTOR_SIZE)
    {
        uint8_t  kl, dl;
        uint32_t crc;
        uint8_t  st = read_entry_hdr(g_nvs.active_sector_addr + off, &kl, &dl, &crc);

        if (st == NVS_ENTRY_WRITING)
        {
            /* Torn write from power loss. Validate sizes before invalidating. */
            if (kl == 0 || kl > NVS_MAX_KEY_LEN || dl > NVS_MAX_DATA_LEN)
            {
                break; /* cannot determine extent — rest of sector unusable */
            }

            /* Plausible sizes: zero the state byte to prevent AND-corruption. */
            uint8_t del = NVS_ENTRY_DELETED;
            DRV_WRITE(g_nvs.active_sector_addr + off, &del, 1);

            off += entry_total_size(kl, dl);
            continue; /* keep scanning; multiple torn slots are possible */
        }

        if (kl == 0 || kl > NVS_MAX_KEY_LEN || dl > NVS_MAX_DATA_LEN)
        {
            break;
        }

        uint32_t esz = entry_total_size(kl, dl);
        if (esz == 0 || off + esz > SECTOR_SIZE)
        {
            break;
        }

        off += esz;
    }

    g_nvs.write_offset = off;
    return NVS_OK;
}

/*===========================================================================
 *  Public API — nvs_write
 *===========================================================================*/

nvs_err_t nvs_write(const char *key, const void *data, uint8_t len)
{
    if (key == NULL || data == NULL)
    {
        return NVS_ERR_INVALID_ARG;
    }

    uint8_t key_len = (uint8_t)strlen(key);
    if (key_len == 0 || key_len > NVS_MAX_KEY_LEN)
    {
        return NVS_ERR_INVALID_ARG;
    }
    if (len > NVS_MAX_DATA_LEN)
    {
        return NVS_ERR_INVALID_ARG;
    }

    uint32_t esz = entry_total_size(key_len, len);

    /* ---- Sector boundary / skip logic ---- */
    if (g_nvs.write_offset + esz > SECTOR_SIZE)
    {
        /* Mark current sector as Full. */
        set_sector_state(g_nvs.active_sector_addr, NVS_SECTOR_FULL);

        /* Activate a new sector (may trigger GC internally). */
        nvs_err_t rc = activate_next_sector();
        if (rc != NVS_OK)
        {
            return rc;
        }
    }

    /* ---- Write the entry and commit ---- */
    uint32_t new_entry_addr = write_entry_to_active(key_len, len,
                                                    (const uint8_t *)key,
                                                    (const uint8_t *)data);

    /* ---- Invalidate older versions of this key ---- */
    invalidate_ctx_t inv_ctx = { .key = key, .key_len = key_len, .skip_addr = new_entry_addr, .found = 0 };

    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t base = sector_addr(i);
        uint32_t magic, seq, state;

        if (!read_sector_hdr(base, &magic, &seq, &state))
        {
            continue;
        }

        walk_sector_entries(base, invalidate_visitor, &inv_ctx);
    }

    return NVS_OK;
}

/*===========================================================================
 *  Public API — nvs_read
 *===========================================================================*/

nvs_err_t nvs_read(const char *key, void *buf, uint8_t buf_size, uint8_t *out_len)
{
    if (key == NULL || buf == NULL || out_len == NULL)
    {
        return NVS_ERR_INVALID_ARG;
    }

    uint8_t key_len = (uint8_t)strlen(key);
    if (key_len == 0 || key_len > NVS_MAX_KEY_LEN)
    {
        return NVS_ERR_INVALID_ARG;
    }

    /* Get sectors ordered by descending sequence number. */
    uint8_t indices[NVS_MAX_SECTORS];
    uint8_t count;
    get_sectors_by_seq_desc(indices, &count);

    for (uint8_t s = 0; s < count; s++)
    {
        uint32_t base = sector_addr(indices[s]);

        find_last_ctx_t ctx = { .key = key, .key_len = key_len,
                                .match_off = 0, .match_dl = 0, .found = 0 };
        walk_sector_entries(base, find_last_visitor, &ctx);

        if (ctx.found)
        {
            /* Verify CRC before returning. */
            uint8_t  kl2, dl2;
            uint32_t stored_crc;
            read_entry_hdr(base + ctx.match_off, &kl2, &dl2, &stored_crc);

            if (kl2 > NVS_MAX_KEY_LEN || dl2 > NVS_MAX_DATA_LEN)
            {
                return NVS_ERR_CRC; /* treat oversized fields as corruption */
            }

            uint8_t key_buf[NVS_MAX_KEY_LEN];
            uint8_t data_buf[NVS_MAX_DATA_LEN];
            DRV_READ(base + ctx.match_off + NVS_ENTRY_HDR_SIZE, key_buf, kl2);
            DRV_READ(base + ctx.match_off + NVS_ENTRY_HDR_SIZE + kl2, data_buf, dl2);

            uint32_t calc_crc = compute_entry_crc(kl2, dl2, key_buf, data_buf);
            if (calc_crc != stored_crc)
            {
                return NVS_ERR_CRC;
            }

            if (ctx.match_dl > buf_size)
            {
                return NVS_ERR_INVALID_ARG;
            }

            memcpy(buf, data_buf, ctx.match_dl);
            *out_len = ctx.match_dl;
            return NVS_OK;
        }
    }

    return NVS_ERR_NOT_FOUND;
}

/*===========================================================================
 *  Public API — nvs_delete
 *===========================================================================*/

nvs_err_t nvs_delete(const char *key)
{
    if (key == NULL)
    {
        return NVS_ERR_INVALID_ARG;
    }

    uint8_t key_len = (uint8_t)strlen(key);
    if (key_len == 0 || key_len > NVS_MAX_KEY_LEN)
    {
        return NVS_ERR_INVALID_ARG;
    }

    invalidate_ctx_t ctx = { .key = key, .key_len = key_len,
                             .skip_addr = 0xFFFFFFFFU, .found = 0 };

    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t base = sector_addr(i);
        uint32_t magic, seq, state;

        if (!read_sector_hdr(base, &magic, &seq, &state))
        {
            continue;
        }

        walk_sector_entries(base, invalidate_visitor, &ctx);
    }

    return ctx.found ? NVS_OK : NVS_ERR_NOT_FOUND;
}
