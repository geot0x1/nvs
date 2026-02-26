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
 * Read the three 32-bit fields of a sector header.
 * Returns true if the magic word matches NVS_MAGIC_WORD.
 */
static int read_sector_hdr(uint32_t base,
                           uint32_t *magic,
                           uint32_t *seq,
                           uint32_t *state)
{
    DRV_READ(base + 0, magic,  sizeof(*magic));
    DRV_READ(base + 4, seq,    sizeof(*seq));
    DRV_READ(base + 8, state,  sizeof(*state));
    return (*magic == NVS_MAGIC_WORD);
}

/** Write a full sector header (magic + seq + state). */
static void write_sector_hdr(uint32_t base, uint32_t seq, uint32_t state)
{
    uint32_t magic = NVS_MAGIC_WORD;
    DRV_WRITE(base + 0, &magic, sizeof(magic));
    DRV_WRITE(base + 4, &seq,   sizeof(seq));
    DRV_WRITE(base + 8, &state, sizeof(state));
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
 * Build an ordered list of sector indices sorted by sequence number
 * (descending).  Only sectors with a valid header are included.
 *
 * @param out_indices   Output array (caller must size to sector_count).
 * @param out_count     Number of valid sectors found.
 */
static void get_sectors_by_seq_desc(uint8_t *out_indices, uint8_t *out_count)
{
    uint32_t seqs[16];      /* supports up to 16 sectors */
    uint8_t  valid[16];
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

/**
 * Check if a newer valid copy of a key exists in any sector with a
 * sequence number higher than `src_seq`.
 */
static int newer_copy_exists(const char *key, uint8_t key_len, uint32_t src_seq)
{
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

        /* Walk entries in this higher-seq sector. */
        uint32_t off = NVS_SECTOR_HDR_SIZE;
        while (off < SECTOR_SIZE)
        {
            uint8_t  kl, dl;
            uint32_t crc;
            uint8_t  st = read_entry_hdr(base + off, &kl, &dl, &crc);

            if (st == NVS_ENTRY_WRITING)
            {
                break; /* end of written area */
            }

            if (st == NVS_ENTRY_VALID && kl == key_len)
            {
                uint8_t flash_key[NVS_MAX_KEY_LEN];
                DRV_READ(base + off + NVS_ENTRY_HDR_SIZE, flash_key, kl);
                if (memcmp(flash_key, key, kl) == 0)
                {
                    return 1; /* newer copy found */
                }
            }
            off += entry_total_size(kl, dl);
        }
    }
    return 0;
}

/**
 * Internal garbage collection.
 *
 * Finds the Full sector with the lowest sequence number, copies any
 * still-valid entries to the active sector, then erases the old sector.
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

    /* Walk entries in the target sector, copy valid ones that have
       no newer version elsewhere. */
    uint32_t off = NVS_SECTOR_HDR_SIZE;
    int all_copied = 1;
    while (off < SECTOR_SIZE)
    {
        uint8_t  kl, dl;
        uint32_t crc;
        uint8_t  st = read_entry_hdr(target_base + off, &kl, &dl, &crc);

        if (st == NVS_ENTRY_WRITING)
        {
            break;
        }

        if (st == NVS_ENTRY_VALID)
        {
            /* Read key + data from the old sector. */
            uint8_t key_buf[NVS_MAX_KEY_LEN];
            uint8_t data_buf[NVS_MAX_DATA_LEN];

            DRV_READ(target_base + off + NVS_ENTRY_HDR_SIZE, key_buf, kl);
            DRV_READ(target_base + off + NVS_ENTRY_HDR_SIZE + kl, data_buf, dl);

            /* Only copy if no newer version exists. */
            if (!newer_copy_exists((const char *)key_buf, kl, target_seq))
            {
                /* Write directly into the active sector (bypass the
                   public nvs_write to avoid re-invalidation loops). */
                uint32_t esz = entry_total_size(kl, dl);

                /* Sector-boundary check for the active sector. */
                if (g_nvs.write_offset + esz > SECTOR_SIZE)
                {
                    /* Cannot fit — this live entry would be lost.
                       Abort GC to prevent data loss. */
                    all_copied = 0;
                    break;
                }

                /* Build entry on stack. */
                uint8_t entry[NVS_ENTRY_HDR_SIZE + NVS_MAX_KEY_LEN + NVS_MAX_DATA_LEN + 4];
                memset(entry, 0xFF, esz);

                entry[0] = NVS_ENTRY_WRITING;
                entry[1] = kl;
                entry[2] = dl;
                entry[3] = 0xFF; /* reserved */

                uint32_t c = compute_entry_crc(kl, dl, key_buf, data_buf);
                entry[4] = (uint8_t)(c);
                entry[5] = (uint8_t)(c >> 8);
                entry[6] = (uint8_t)(c >> 16);
                entry[7] = (uint8_t)(c >> 24);

                memcpy(&entry[NVS_ENTRY_HDR_SIZE], key_buf, kl);
                memcpy(&entry[NVS_ENTRY_HDR_SIZE + kl], data_buf, dl);

                /* Flash-write the entry. */
                DRV_WRITE(g_nvs.active_sector_addr + g_nvs.write_offset,
                          entry, (uint16_t)esz);

                /* Commit: flip state to Valid. */
                set_entry_state(g_nvs.active_sector_addr + g_nvs.write_offset,
                                NVS_ENTRY_VALID);

                g_nvs.write_offset += esz;
            }
        }

        off += entry_total_size(kl, dl);
    }

    if (!all_copied)
    {
        /* Could not move all live entries — do NOT erase the source
           sector, otherwise we would lose data.  Report no space. */
        return NVS_ERR_NO_SPACE;
    }

    /* Erase the old sector — all live data has been safely moved. */
    DRV_ERASE(target_base);

    return NVS_OK;
}

/*===========================================================================
 *  Internal — activate a new empty sector
 *===========================================================================*/

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

    /* No empty sector — try garbage collection. */
    nvs_err_t rc = nvs_gc();
    if (rc != NVS_OK)
    {
        return NVS_ERR_NO_SPACE;
    }

    /* After GC there should be an empty sector — try again. */
    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t base = sector_addr(i);
        uint32_t magic_val;
        DRV_READ(base, &magic_val, sizeof(magic_val));

        if (magic_val == 0xFFFFFFFF)
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
        driver->sector_count == 0)
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
        /* No active sector — first-time format. */
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
            /* Incomplete write from a power loss — treat as end. */
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

    /* ---- Build the entry on the stack ---- */
    uint8_t entry[NVS_ENTRY_HDR_SIZE + NVS_MAX_KEY_LEN + NVS_MAX_DATA_LEN + 4];
    memset(entry, 0xFF, esz);

    entry[0] = NVS_ENTRY_WRITING;   /* state — not yet committed  */
    entry[1] = key_len;
    entry[2] = len;
    entry[3] = 0xFF;                 /* reserved                    */

    uint32_t crc = compute_entry_crc(key_len, len,
                                     (const uint8_t *)key,
                                     (const uint8_t *)data);
    entry[4] = (uint8_t)(crc);
    entry[5] = (uint8_t)(crc >> 8);
    entry[6] = (uint8_t)(crc >> 16);
    entry[7] = (uint8_t)(crc >> 24);

    memcpy(&entry[NVS_ENTRY_HDR_SIZE], key, key_len);
    memcpy(&entry[NVS_ENTRY_HDR_SIZE + key_len], data, len);

    /* ---- Write the entry (state is still 0xFF = Writing) ---- */
    DRV_WRITE(g_nvs.active_sector_addr + g_nvs.write_offset,
              entry, (uint16_t)esz);

    /* ---- Commit: flip state to Valid ---- */
    set_entry_state(g_nvs.active_sector_addr + g_nvs.write_offset,
                    NVS_ENTRY_VALID);

    uint32_t new_entry_addr = g_nvs.active_sector_addr + g_nvs.write_offset;
    g_nvs.write_offset += esz;

    /* ---- Invalidate older versions of this key ---- */
    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t base = sector_addr(i);
        uint32_t magic, seq, state;

        if (!read_sector_hdr(base, &magic, &seq, &state))
        {
            continue;
        }

        uint32_t off = NVS_SECTOR_HDR_SIZE;
        while (off < SECTOR_SIZE)
        {
            uint8_t  kl, dl;
            uint32_t entry_crc;
            uint8_t  st = read_entry_hdr(base + off, &kl, &dl, &entry_crc);

            if (st == NVS_ENTRY_WRITING)
            {
                break;
            }

            /* Skip the entry we just wrote. */
            if ((base + off) != new_entry_addr &&
                st == NVS_ENTRY_VALID &&
                kl == key_len)
            {
                uint8_t flash_key[NVS_MAX_KEY_LEN];
                DRV_READ(base + off + NVS_ENTRY_HDR_SIZE, flash_key, kl);
                if (memcmp(flash_key, key, kl) == 0)
                {
                    set_entry_state(base + off, NVS_ENTRY_DELETED);
                }
            }

            off += entry_total_size(kl, dl);
        }
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
    uint8_t indices[16];
    uint8_t count;
    get_sectors_by_seq_desc(indices, &count);

    for (uint8_t s = 0; s < count; s++)
    {
        uint32_t base = sector_addr(indices[s]);
        uint32_t off  = NVS_SECTOR_HDR_SIZE;

        /*
         * Walk forward through the sector.  Because the append-only log
         * writes newer entries at higher offsets, we keep track of the
         * *last* valid match — that is the most recent in this sector.
         */
        uint32_t match_off  = 0;
        uint8_t  match_dl   = 0;
        int      found_here = 0;

        while (off < SECTOR_SIZE)
        {
            uint8_t  kl, dl;
            uint32_t entry_crc;
            uint8_t  st = read_entry_hdr(base + off, &kl, &dl, &entry_crc);

            if (st == NVS_ENTRY_WRITING)
            {
                break;
            }

            if (st == NVS_ENTRY_VALID && kl == key_len)
            {
                uint8_t flash_key[NVS_MAX_KEY_LEN];
                DRV_READ(base + off + NVS_ENTRY_HDR_SIZE, flash_key, kl);
                if (memcmp(flash_key, key, kl) == 0)
                {
                    match_off  = off;
                    match_dl   = dl;
                    found_here = 1;
                }
            }

            off += entry_total_size(kl, dl);
        }

        if (found_here)
        {
            /* Verify CRC before returning. */
            uint8_t  kl2, dl2;
            uint32_t stored_crc;
            read_entry_hdr(base + match_off, &kl2, &dl2, &stored_crc);

            uint8_t key_buf[NVS_MAX_KEY_LEN];
            uint8_t data_buf[NVS_MAX_DATA_LEN];
            DRV_READ(base + match_off + NVS_ENTRY_HDR_SIZE, key_buf, kl2);
            DRV_READ(base + match_off + NVS_ENTRY_HDR_SIZE + kl2, data_buf, dl2);

            uint32_t calc_crc = compute_entry_crc(kl2, dl2, key_buf, data_buf);
            if (calc_crc != stored_crc)
            {
                return NVS_ERR_CRC;
            }

            if (match_dl > buf_size)
            {
                return NVS_ERR_INVALID_ARG;
            }

            memcpy(buf, data_buf, match_dl);
            *out_len = match_dl;
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

    int found = 0;

    for (uint8_t i = 0; i < SECTOR_COUNT; i++)
    {
        uint32_t base = sector_addr(i);
        uint32_t magic, seq, state;

        if (!read_sector_hdr(base, &magic, &seq, &state))
        {
            continue;
        }

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

            if (st == NVS_ENTRY_VALID && kl == key_len)
            {
                uint8_t flash_key[NVS_MAX_KEY_LEN];
                DRV_READ(base + off + NVS_ENTRY_HDR_SIZE, flash_key, kl);
                if (memcmp(flash_key, key, kl) == 0)
                {
                    set_entry_state(base + off, NVS_ENTRY_DELETED);
                    found = 1;
                }
            }

            off += entry_total_size(kl, dl);
        }
    }

    return found ? NVS_OK : NVS_ERR_NOT_FOUND;
}
