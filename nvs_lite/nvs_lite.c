/**
 * @file nvs_lite.c
 * @brief Portable NVS (Non-Volatile Storage) implementation.
 *
 * All flash I/O is routed through the function pointers in nvs_config_t.
 * No direct hardware calls exist in this file.
 */

#include "nvs_lite.h"
#include "nvs_internal.h"
#include "crc32.h"
#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Compile-time size assertions
 * --------------------------------------------------------------------- */

_Static_assert(sizeof(nvs_page_hdr_t)  == NVS_PAGE_HDR_SIZE,
               "nvs_page_hdr_t must be exactly 32 bytes");
_Static_assert(sizeof(nvs_entry_hdr_t) == NVS_ENTRY_HDR_SIZE,
               "nvs_entry_hdr_t must be exactly 32 bytes");

/* -----------------------------------------------------------------------
 * Logging — define NVS_DEBUG at compile time to enable verbose output
 * --------------------------------------------------------------------- */

#ifdef NVS_DEBUG
#  define NVS_LOG(fmt, ...) printf("[NVS] " fmt "\n", ##__VA_ARGS__)
#else
#  define NVS_LOG(fmt, ...) ((void)0)
#endif

/* -----------------------------------------------------------------------
 * Global state
 * --------------------------------------------------------------------- */

static nvs_config_t     g_config;
static int              g_initialized  = 0;
static uint32_t         g_num_pages;
static int32_t          g_active_page  = -1;

static nvs_page_t       g_pages[64];
static nvs_namespace_t  g_namespaces[NVS_MAX_NAMESPACES + 1];
static uint8_t          g_ns_count     = 0;

static nvs_lookup_t     g_lookup[NVS_MAX_KEYS];
static uint32_t         g_lookup_count = 0;

static nvs_handle_rec_t g_handles[NVS_MAX_HANDLES];
static uint32_t         g_write_seq    = 0;

/* -----------------------------------------------------------------------
 * CRC32 helpers
 * --------------------------------------------------------------------- */

/**
 * CRC covers only the immutable fields: magic and sequence_no (8 bytes).
 * The 'state' field is intentionally excluded so it can be updated
 * in-place (1→0 NOR transitions) without invalidating the checksum.
 */
static uint32_t nvs_page_hdr_crc(const nvs_page_hdr_t *h)
{
    return crc32_gen((const uint8_t *)h, 8u);
}

/** CRC covers bytes [0..27] of the entry header (everything before crc32). */
static uint32_t nvs_entry_crc(const nvs_entry_hdr_t *e)
{
    return crc32_gen((const uint8_t *)e, 28u);
}

/* -----------------------------------------------------------------------
 * Geometry and address helpers
 * --------------------------------------------------------------------- */

static uint32_t nvs_page_entries_per_page(void)
{
    /*
     * Solve for N:
     *   N * NVS_ENTRY_SIZE + ceil(N*2/8 rounded to 32) + NVS_PAGE_HDR_SIZE
     *       <= sector_size
     *
     * Simplified closed form (bitmap rounded to 32-byte blocks):
     *   N = (available * 4) / (NVS_ENTRY_SIZE * 4 + 1)
     */
    uint32_t available = g_config.sector_size - NVS_PAGE_HDR_SIZE;
    return (available * 4u) / (NVS_ENTRY_SIZE * 4u + 1u);
}

static uint32_t nvs_page_bitmap_size(uint32_t num_entries)
{
    /* 2 bits per entry, rounded up to 32-byte alignment */
    uint32_t bytes = (num_entries * 2u + 7u) / 8u;
    return (bytes + 31u) & ~31u;
}

static uint32_t nvs_page_data_start(uint32_t page_base)
{
    return page_base + NVS_PAGE_HDR_SIZE
           + nvs_page_bitmap_size(nvs_page_entries_per_page());
}

static uint32_t nvs_page_entry_addr(uint32_t page_idx, uint16_t entry_idx)
{
    return g_pages[page_idx].data_start + (uint32_t)entry_idx * NVS_ENTRY_SIZE;
}

/**
 * Convert an absolute flash address to the page index that contains it.
 * Returns UINT32_MAX if the address is out of range.
 */
static uint32_t nvs_flash_addr_to_page(uint32_t flash_addr)
{
    if (flash_addr < g_config.base_address)
    {
        return UINT32_MAX;
    }
    uint32_t idx = (flash_addr - g_config.base_address) / g_config.sector_size;
    return (idx < g_num_pages) ? idx : UINT32_MAX;
}

/* -----------------------------------------------------------------------
 * Bitmap state management
 * --------------------------------------------------------------------- */

static uint32_t nvs_bitmap_addr(uint32_t page_idx, uint16_t entry_idx,
                                uint8_t *out_shift)
{
    /* 2 bits per entry; entry 0 occupies bits 7:6 of byte 0 (MSB first). */
    uint32_t byte_offset = entry_idx / 4u;
    *out_shift = (uint8_t)((3u - (entry_idx % 4u)) * 2u);
    return g_pages[page_idx].base_addr + NVS_PAGE_HDR_SIZE + byte_offset;
}

static int nvs_bitmap_get(uint32_t page_idx, uint16_t entry_idx,
                           uint8_t *out_bits)
{
    uint8_t  shift;
    uint32_t addr = nvs_bitmap_addr(page_idx, entry_idx, &shift);
    uint8_t  byte;

    if (g_config.read(addr, &byte, 1u) != 0)
    {
        return NVS_ERR_FLASH;
    }
    *out_bits = (byte >> shift) & 0x3u;
    return NVS_OK;
}

static int nvs_bitmap_set(uint32_t page_idx, uint16_t entry_idx, uint8_t bits)
{
    uint8_t  shift;
    uint32_t addr = nvs_bitmap_addr(page_idx, entry_idx, &shift);
    uint8_t  byte;

    if (g_config.read(addr, &byte, 1u) != 0)
    {
        return NVS_ERR_FLASH;
    }
    /* NOR-flash: we can only clear bits (AND mask). */
    byte &= ~(uint8_t)(0x3u << shift);
    byte |=  (uint8_t)((bits & 0x3u) << shift);

    if (g_config.write(addr, &byte, 1u) != 0)
    {
        return NVS_ERR_FLASH;
    }
    return NVS_OK;
}

/* -----------------------------------------------------------------------
 * Page management helpers
 * --------------------------------------------------------------------- */

/**
 * Write the full page header to flash.
 * Only called when the page is freshly erased (all 0xFF), so no NOR
 * violation occurs.
 */
static int nvs_page_hdr_write(uint32_t page_idx, const nvs_page_hdr_t *hdr)
{
    if (g_config.write(g_pages[page_idx].base_addr, hdr,
                       sizeof(nvs_page_hdr_t)) != 0)
    {
        return NVS_ERR_FLASH;
    }
    return NVS_OK;
}

/**
 * Update only the 'state' byte of an existing page header in-place.
 *
 * Because the state field transitions are strictly 1→0 (ACTIVE→FULL→ERASING),
 * this is a valid NOR-flash operation and does not require re-writing the
 * entire header (which would violate NOR semantics for already-programmed
 * magic/sequence fields).
 */
static int nvs_page_state_update(uint32_t page_idx, uint8_t new_state)
{
    /* offsetof(nvs_page_hdr_t, state) = 8 (after magic[4] + sequence_no[4]) */
    uint32_t state_addr = g_pages[page_idx].base_addr
                          + offsetof(nvs_page_hdr_t, state);

    if (g_config.write(state_addr, &new_state, 1u) != 0)
    {
        return NVS_ERR_FLASH;
    }
    return NVS_OK;
}

static int nvs_page_init_empty(uint32_t page_idx)
{
    /* Erase the sector first so the full header write is valid. */
    if (g_config.erase(g_pages[page_idx].base_addr) != 0)
    {
        return NVS_ERR_FLASH;
    }

    nvs_page_hdr_t hdr;
    memset(&hdr, 0xFF, sizeof(hdr));
    hdr.magic       = NVS_PAGE_MAGIC;
    hdr.sequence_no = g_write_seq++;
    hdr.state       = NVS_PAGE_STATE_ACTIVE;
    hdr.crc32       = nvs_page_hdr_crc(&hdr);

    g_pages[page_idx].state         = hdr.state;
    g_pages[page_idx].seq_no        = hdr.sequence_no;
    g_pages[page_idx].data_start    = nvs_page_data_start(g_pages[page_idx].base_addr);
    g_pages[page_idx].entry_count   = (uint16_t)nvs_page_entries_per_page();
    g_pages[page_idx].free_count    = g_pages[page_idx].entry_count;
    g_pages[page_idx].written_count = 0;
    g_pages[page_idx].erased_count  = 0;

    return nvs_page_hdr_write(page_idx, &hdr);
}

static int nvs_page_mark_full(uint32_t page_idx)
{
    if (g_pages[page_idx].state == NVS_PAGE_STATE_FULL)
    {
        return NVS_OK;
    }
    g_pages[page_idx].state = NVS_PAGE_STATE_FULL;
    return nvs_page_state_update(page_idx, NVS_PAGE_STATE_FULL);
}

static int nvs_page_mark_erasing(uint32_t page_idx)
{
    g_pages[page_idx].state = NVS_PAGE_STATE_ERASING;
    return nvs_page_state_update(page_idx, NVS_PAGE_STATE_ERASING);
}

/* -----------------------------------------------------------------------
 * Lookup table management
 * --------------------------------------------------------------------- */

static void nvs_lookup_insert(uint8_t ns_index, const char *key,
                               uint8_t type, uint8_t span, uint32_t flash_addr)
{
    /* Update existing entry if present */
    for (uint32_t i = 0u; i < g_lookup_count; i++)
    {
        if (g_lookup[i].ns_index == ns_index &&
            strncmp(g_lookup[i].key, key, NVS_KEY_MAX_LEN) == 0)
        {
            g_lookup[i].flash_addr = flash_addr;
            g_lookup[i].type       = type;
            g_lookup[i].span       = span;
            return;
        }
    }

    /* New entry */
    if (g_lookup_count < NVS_MAX_KEYS)
    {
        nvs_lookup_t *e = &g_lookup[g_lookup_count++];
        e->ns_index   = ns_index;
        e->type       = type;
        e->span       = span;
        e->flash_addr = flash_addr;
        strncpy(e->key, key, NVS_KEY_MAX_LEN);
        e->key[NVS_KEY_MAX_LEN] = '\0';
    }
}

static void nvs_lookup_remove(uint8_t ns_index, const char *key)
{
    for (uint32_t i = 0u; i < g_lookup_count; i++)
    {
        if (g_lookup[i].ns_index == ns_index &&
            strncmp(g_lookup[i].key, key, NVS_KEY_MAX_LEN) == 0)
        {
            /* Replace with last element (order-independent removal). */
            g_lookup[i] = g_lookup[--g_lookup_count];
            return;
        }
    }
}

static int nvs_lookup_find(uint8_t ns_index, const char *key,
                            nvs_lookup_t **out_entry)
{
    for (uint32_t i = 0u; i < g_lookup_count; i++)
    {
        if (g_lookup[i].ns_index == ns_index &&
            strncmp(g_lookup[i].key, key, NVS_KEY_MAX_LEN) == 0)
        {
            *out_entry = &g_lookup[i];
            return NVS_OK;
        }
    }
    return NVS_ERR_NOT_FOUND;
}

static int nvs_read_entry_hdr(uint32_t flash_addr, nvs_entry_hdr_t *hdr)
{
    if (g_config.read(flash_addr, hdr, sizeof(nvs_entry_hdr_t)) != 0)
    {
        return NVS_ERR_FLASH;
    }
    return NVS_OK;
}

/* -----------------------------------------------------------------------
 * Partition scanning
 * --------------------------------------------------------------------- */

static int nvs_scan_page(uint32_t page_idx)
{
    nvs_page_t    *p = &g_pages[page_idx];
    nvs_page_hdr_t hdr;

    if (g_config.read(p->base_addr, &hdr, sizeof(hdr)) != 0)
    {
        return NVS_ERR_FLASH;
    }

    NVS_LOG("Scan page %u base=0x%08X magic=0x%08X state=%u seq=%u",
            page_idx, p->base_addr, hdr.magic, hdr.state, hdr.sequence_no);

    /* Blank or unrelated region */
    if (hdr.magic == 0xFFFFFFFFu || hdr.magic != NVS_PAGE_MAGIC)
    {
        p->state       = NVS_PAGE_STATE_EMPTY;
        p->free_count  = (uint16_t)nvs_page_entries_per_page();
        p->entry_count = (uint16_t)nvs_page_entries_per_page();
        p->data_start  = nvs_page_data_start(p->base_addr);
        return NVS_OK;
    }

    /* Validate header CRC */
    uint32_t calc = nvs_page_hdr_crc(&hdr);
    if (calc != hdr.crc32)
    {
        NVS_LOG("Page %u header CRC mismatch (calc=0x%08X stored=0x%08X) — treating as empty",
                page_idx, calc, hdr.crc32);
        p->state       = NVS_PAGE_STATE_EMPTY;
        p->free_count  = (uint16_t)nvs_page_entries_per_page();
        p->entry_count = (uint16_t)nvs_page_entries_per_page();
        p->data_start  = nvs_page_data_start(p->base_addr);
        return NVS_OK;
    }

    p->state       = hdr.state;
    p->seq_no      = hdr.sequence_no;
    p->entry_count = (uint16_t)nvs_page_entries_per_page();
    p->data_start  = nvs_page_data_start(p->base_addr);
    p->free_count  = 0;
    p->written_count = 0;
    p->erased_count  = 0;

    /* GC was interrupted — will be cleaned up after all pages are scanned */
    if (p->state == NVS_PAGE_STATE_ERASING)
    {
        return NVS_OK;
    }

    /* Advance global write-sequence counter */
    if (hdr.sequence_no >= g_write_seq)
    {
        g_write_seq = hdr.sequence_no + 1u;
    }

    /* Scan each entry slot */
    for (uint16_t i = 0u; i < p->entry_count; i++)
    {
        uint8_t bits;
        if (nvs_bitmap_get(page_idx, i, &bits) != NVS_OK)
        {
            continue;
        }

        if (bits == NVS_BITMAP_EMPTY)
        {
            p->free_count++;
            continue;
        }

        if (bits != NVS_BITMAP_WRITTEN)
        {
            /* NVS_BITMAP_ERASED or reserved pattern */
            p->erased_count++;
            continue;
        }

        /* Written slot — read and validate the entry header */
        nvs_entry_hdr_t entry;
        uint32_t eaddr = nvs_page_entry_addr(page_idx, i);
        if (nvs_read_entry_hdr(eaddr, &entry) != NVS_OK)
        {
            p->erased_count++;
            continue;
        }

        if (nvs_entry_crc(&entry) != entry.crc32)
        {
            NVS_LOG("Page %u entry %u CRC mismatch — treating as erased", page_idx, i);
            p->erased_count++;
            continue;
        }

        p->written_count++;

        if (entry.ns_index == 0u)
        {
            /* Namespace registry entry */
            uint8_t ns_idx = entry.value.u8;
            if (ns_idx > 0u && ns_idx <= NVS_MAX_NAMESPACES)
            {
                nvs_namespace_t *ns = &g_namespaces[ns_idx];
                if (!ns->in_use)
                {
                    strncpy(ns->name, entry.key, NVS_KEY_MAX_LEN);
                    ns->name[NVS_KEY_MAX_LEN] = '\0';
                    ns->index  = ns_idx;
                    ns->in_use = 1;
                    if (ns_idx > g_ns_count)
                    {
                        g_ns_count = ns_idx;
                    }
                }
            }
        }
        else
        {
            /* Regular key-value entry */
            nvs_lookup_insert(entry.ns_index, entry.key,
                              entry.type, entry.span, eaddr);
        }

        /* Skip over continuation slots for multi-entry values */
        if (entry.span > 1u)
        {
            uint16_t skip = entry.span - 1u;
            for (uint16_t s = 0u;
                 s < skip && (uint16_t)(i + 1u + s) < p->entry_count;
                 s++)
            {
                uint8_t sb;
                if (nvs_bitmap_get(page_idx, (uint16_t)(i + 1u + s), &sb) == NVS_OK)
                {
                    if (sb == NVS_BITMAP_WRITTEN)      { p->written_count++; }
                    else if (sb == NVS_BITMAP_ERASED)  { p->erased_count++;  }
                    else                               { p->free_count++;    }
                }
            }
            i = (uint16_t)(i + skip);
        }
    }

    return NVS_OK;
}

/* -----------------------------------------------------------------------
 * Garbage collection
 * --------------------------------------------------------------------- */

/* Forward declaration */
static int nvs_advance_active_page(void);

/**
 * Maximum number of live entries that can be snapshotted during one GC pass.
 * Each gc_entry_t holds a 32-byte header plus up to 32 continuation slots
 * (32 * 32 = 1 KB of payload), so the struct is ~1056 bytes.
 * With GC_MAX_ENTRIES = 128 the static buffer is ~132 KB — acceptable for
 * a hosted simulator; on a real MCU reduce this or use dynamic allocation.
 */
#define GC_MAX_ENTRIES 128u

typedef struct
{
    nvs_entry_hdr_t hdr;
    uint8_t         payload[NVS_ENTRY_SIZE * 32u];
    uint32_t        payload_len;    /* bytes of valid payload data */
    uint32_t        payload_slots;  /* continuation slot count     */
} gc_entry_t;

/* Static allocation avoids a large stack frame inside nvs_garbage_collect(). */
static gc_entry_t s_gc_buf[GC_MAX_ENTRIES];

/* Forward declaration — defined after nvs_garbage_collect(). */
static int nvs_find_free_slot(uint32_t page_idx, uint16_t span,
                               uint32_t *out_entry_idx);

static int nvs_garbage_collect(void)
{
    /* Pick the non-active page with the fewest live (Written) entries */
    int32_t  victim      = -1;
    uint16_t min_written = UINT16_MAX;

    for (uint32_t i = 0u; i < g_num_pages; i++)
    {
        if ((int32_t)i == g_active_page)
        {
            continue;
        }
        if (g_pages[i].state == NVS_PAGE_STATE_FULL ||
            g_pages[i].state == NVS_PAGE_STATE_ACTIVE)
        {
            if (g_pages[i].written_count < min_written)
            {
                min_written = g_pages[i].written_count;
                victim      = (int32_t)i;
            }
        }
    }

    if (victim < 0)
    {
        return NVS_ERR_NO_SPACE;
    }

    NVS_LOG("GC: victim page %d (written=%u erased=%u free=%u)",
            victim,
            g_pages[victim].written_count,
            g_pages[victim].erased_count,
            g_pages[victim].free_count);

    nvs_page_t *vp = &g_pages[victim];

    /* ---- Step 1: Snapshot all valid entries from the victim page ---- */
    uint32_t gc_count = 0u;

    for (uint16_t i = 0u;
         i < vp->entry_count && gc_count < GC_MAX_ENTRIES;
         i++)
    {
        uint8_t bits;
        if (nvs_bitmap_get((uint32_t)victim, i, &bits) != NVS_OK)
        {
            continue;
        }
        if (bits != NVS_BITMAP_WRITTEN)
        {
            continue;
        }

        uint32_t        src_addr = nvs_page_entry_addr((uint32_t)victim, i);
        nvs_entry_hdr_t hdr;
        if (nvs_read_entry_hdr(src_addr, &hdr) != NVS_OK)
        {
            continue;
        }
        if (nvs_entry_crc(&hdr) != hdr.crc32)
        {
            NVS_LOG("GC: skipping corrupt entry E%u at 0x%08X", i, src_addr);
            i += (hdr.span > 0u ? (uint16_t)(hdr.span - 1u) : 0u);
            continue;
        }

        uint32_t payload_slots = (hdr.span > 1u) ? (uint32_t)(hdr.span - 1u) : 0u;
        uint32_t payload_bytes = payload_slots * NVS_ENTRY_SIZE;

        gc_entry_t *ge    = &s_gc_buf[gc_count];
        ge->hdr           = hdr;
        ge->payload_slots = payload_slots;
        ge->payload_len   = payload_bytes;

        if (payload_bytes > 0u && payload_bytes <= sizeof(ge->payload))
        {
            for (uint32_t s = 0u; s < payload_slots; s++)
            {
                uint32_t sa = src_addr + (s + 1u) * NVS_ENTRY_SIZE;
                g_config.read(sa, ge->payload + s * NVS_ENTRY_SIZE,
                              NVS_ENTRY_SIZE);
            }
        }

        gc_count++;
        i = (uint16_t)(i + (uint16_t)payload_slots);
    }

    NVS_LOG("GC: snapshotted %u entries from victim page %d", gc_count, victim);

    /* ---- Step 2: Mark victim as Erasing, remove its entries from RAM ---- */
    if (nvs_page_mark_erasing((uint32_t)victim) != NVS_OK)
    {
        return NVS_ERR_FLASH;
    }

    /* Remove victim's entries from the in-RAM lookup table */
    for (uint32_t i = 0u; i < g_lookup_count; )
    {
        if (nvs_flash_addr_to_page(g_lookup[i].flash_addr) == (uint32_t)victim)
        {
            g_lookup[i] = g_lookup[--g_lookup_count];
        }
        else
        {
            i++;
        }
    }

    /* Erase and re-initialise the victim sector as the new Active page */
    if (g_config.erase(vp->base_addr) != 0)
    {
        return NVS_ERR_FLASH;
    }

    int rc = nvs_page_init_empty((uint32_t)victim);
    if (rc != NVS_OK)
    {
        return rc;
    }
    g_active_page = victim;

    /* ---- Step 3: Replay snapshot into the new Active page ---- */
    for (uint32_t g = 0u; g < gc_count; g++)
    {
        gc_entry_t *ge          = &s_gc_buf[g];
        uint32_t    total_slots = ge->hdr.span;

        uint32_t slot_idx;
        if (nvs_find_free_slot((uint32_t)g_active_page,
                               (uint16_t)total_slots, &slot_idx) != NVS_OK)
        {
            return NVS_ERR_NO_SPACE;
        }

        uint32_t dst_addr = nvs_page_entry_addr((uint32_t)g_active_page,
                                                (uint16_t)slot_idx);

        /* Write header */
        g_config.write(dst_addr, &ge->hdr, NVS_ENTRY_SIZE);

        /* Write continuation slots */
        for (uint32_t s = 0u; s < ge->payload_slots; s++)
        {
            uint32_t d = dst_addr + (s + 1u) * NVS_ENTRY_SIZE;
            g_config.write(d, ge->payload + s * NVS_ENTRY_SIZE, NVS_ENTRY_SIZE);
            nvs_bitmap_set((uint32_t)g_active_page,
                           (uint16_t)(slot_idx + 1u + s),
                           NVS_BITMAP_WRITTEN);
            g_pages[g_active_page].free_count--;
            g_pages[g_active_page].written_count++;
        }

        nvs_bitmap_set((uint32_t)g_active_page, (uint16_t)slot_idx,
                       NVS_BITMAP_WRITTEN);
        g_pages[g_active_page].free_count--;
        g_pages[g_active_page].written_count++;

        /* Update in-RAM state */
        if (ge->hdr.ns_index != 0u)
        {
            NVS_LOG("GC: replayed key '%s' ns=%u", ge->hdr.key, ge->hdr.ns_index);
            nvs_lookup_insert(ge->hdr.ns_index, ge->hdr.key,
                              ge->hdr.type, ge->hdr.span, dst_addr);
        }
        else
        {
            /* Namespace registry entry */
            uint8_t ns_idx = ge->hdr.value.u8;
            if (ns_idx > 0u && ns_idx <= NVS_MAX_NAMESPACES)
            {
                g_namespaces[ns_idx].in_use = 1;
                strncpy(g_namespaces[ns_idx].name, ge->hdr.key, NVS_KEY_MAX_LEN);
                g_namespaces[ns_idx].name[NVS_KEY_MAX_LEN] = '\0';
                g_namespaces[ns_idx].index = ns_idx;
                if (ns_idx > g_ns_count)
                {
                    g_ns_count = ns_idx;
                }
            }
        }
    }

    return NVS_OK;
}

/* -----------------------------------------------------------------------
 * Free-slot search
 * --------------------------------------------------------------------- */

static int nvs_find_free_slot(uint32_t page_idx, uint16_t span,
                               uint32_t *out_entry_idx)
{
    nvs_page_t *p = &g_pages[page_idx];

    if (p->state != NVS_PAGE_STATE_ACTIVE || p->free_count < span)
    {
        return NVS_ERR_NO_SPACE;
    }

    uint16_t consecutive = 0u;
    uint16_t start_idx   = 0u;

    for (uint16_t i = 0u; i < p->entry_count; i++)
    {
        uint8_t bits;
        if (nvs_bitmap_get(page_idx, i, &bits) != NVS_OK)
        {
            consecutive = 0u;
            continue;
        }
        if (bits == NVS_BITMAP_EMPTY)
        {
            if (consecutive == 0u)
            {
                start_idx = i;
            }
            if (++consecutive == span)
            {
                *out_entry_idx = start_idx;
                return NVS_OK;
            }
        }
        else
        {
            consecutive = 0u;
        }
    }
    return NVS_ERR_NO_SPACE;
}

static int nvs_advance_active_page(void)
{
    /* Mark the current active page as Full */
    if (g_active_page >= 0)
    {
        nvs_page_mark_full((uint32_t)g_active_page);
    }

    /* Find an Empty page to promote to Active */
    for (uint32_t i = 0u; i < g_num_pages; i++)
    {
        if (g_pages[i].state == NVS_PAGE_STATE_EMPTY)
        {
            int rc = nvs_page_init_empty(i);
            if (rc != NVS_OK)
            {
                return rc;
            }
            g_active_page = (int32_t)i;
            return NVS_OK;
        }
    }

    /* No empty page available — trigger garbage collection */
    return nvs_garbage_collect();
}

/* -----------------------------------------------------------------------
 * Mark an entry (and its continuation slots) as Erased in the bitmap
 * --------------------------------------------------------------------- */

static int nvs_mark_erased(uint32_t flash_addr, uint8_t span)
{
    uint32_t page_idx = nvs_flash_addr_to_page(flash_addr);
    if (page_idx == UINT32_MAX)
    {
        return NVS_ERR_NOT_FOUND;
    }

    uint32_t offset    = flash_addr - g_pages[page_idx].data_start;
    uint16_t entry_idx = (uint16_t)(offset / NVS_ENTRY_SIZE);

    for (uint8_t s = 0u; s < span; s++)
    {
        int rc = nvs_bitmap_set(page_idx, (uint16_t)(entry_idx + s),
                                NVS_BITMAP_ERASED);
        if (rc != NVS_OK)
        {
            return rc;
        }
        if (g_pages[page_idx].written_count > 0u)
        {
            g_pages[page_idx].written_count--;
        }
        g_pages[page_idx].erased_count++;
    }
    return NVS_OK;
}

/* -----------------------------------------------------------------------
 * Generic scalar set / get helpers
 * --------------------------------------------------------------------- */

/* Forward declaration */
static int nvs_write_entry(uint8_t ns_index, const char *key,
                            uint8_t type, uint8_t span,
                            const void *value_bytes, size_t value_len);

static int nvs_validate_handle(nvs_handle_t handle)
{
    if (handle == 0u || handle > NVS_MAX_HANDLES)
    {
        return NVS_ERR_HANDLE;
    }
    if (!g_handles[handle - 1u].in_use)
    {
        return NVS_ERR_HANDLE;
    }
    return NVS_OK;
}

static int nvs_set_scalar(nvs_handle_t handle, const char *key,
                           uint8_t type, const void *value, size_t vlen)
{
    if (!g_initialized)                    { return NVS_ERR_NOT_INIT;    }
    if (key == NULL || value == NULL)      { return NVS_ERR_INVALID_ARG; }
    if (strlen(key) > NVS_KEY_MAX_LEN)    { return NVS_ERR_KEY_TOO_LONG; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK) { return rc; }

    nvs_handle_rec_t *hr = &g_handles[handle - 1u];
    if (hr->mode != NVS_READWRITE) { return NVS_ERR_READ_ONLY; }

    /* Mark old entry as Erased if it exists */
    nvs_lookup_t *old = NULL;
    if (nvs_lookup_find(hr->ns_index, key, &old) == NVS_OK)
    {
        nvs_mark_erased(old->flash_addr, old->span);
        nvs_lookup_remove(hr->ns_index, key);
    }

    return nvs_write_entry(hr->ns_index, key, type, 1u, value, vlen);
}

static int nvs_get_scalar(nvs_handle_t handle, const char *key,
                           uint8_t type, void *out, size_t vlen)
{
    if (!g_initialized)                 { return NVS_ERR_NOT_INIT;    }
    if (key == NULL || out == NULL)     { return NVS_ERR_INVALID_ARG; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK) { return rc; }

    nvs_handle_rec_t *hr = &g_handles[handle - 1u];

    nvs_lookup_t *e = NULL;
    rc = nvs_lookup_find(hr->ns_index, key, &e);
    if (rc != NVS_OK)       { return rc;                }
    if (e->type != type)    { return NVS_ERR_NOT_FOUND; }

    nvs_entry_hdr_t hdr;
    if (nvs_read_entry_hdr(e->flash_addr, &hdr) != NVS_OK)
    {
        return NVS_ERR_FLASH;
    }
    if (nvs_entry_crc(&hdr) != hdr.crc32)
    {
        return NVS_ERR_CORRUPT;
    }

    memcpy(out, hdr.value.raw, vlen);
    return NVS_OK;
}

static int nvs_write_entry(uint8_t ns_index, const char *key,
                            uint8_t type, uint8_t span,
                            const void *value_bytes, size_t value_len)
{
    int rc;

retry:
    if (g_active_page < 0)
    {
        rc = nvs_advance_active_page();
        if (rc != NVS_OK) { return rc; }
    }

    uint32_t slot_idx;
    rc = nvs_find_free_slot((uint32_t)g_active_page, span, &slot_idx);
    if (rc != NVS_OK)
    {
        rc = nvs_advance_active_page();
        if (rc != NVS_OK) { return rc; }
        goto retry;
    }

    /* Build the entry header */
    nvs_entry_hdr_t hdr;
    memset(&hdr, 0xFF, sizeof(hdr));
    hdr.ns_index    = ns_index;
    hdr.type        = type;
    hdr.span        = span;
    hdr.chunk_index = 0u;
    strncpy(hdr.key, key, NVS_KEY_MAX_LEN);
    hdr.key[NVS_KEY_MAX_LEN] = '\0';
    memset(hdr.value.raw, 0xFF, sizeof(hdr.value.raw));

    if (span == 1u)
    {
        size_t copy_len = (value_len <= 8u) ? value_len : 8u;
        memcpy(hdr.value.raw, value_bytes, copy_len);
    }
    else
    {
        hdr.value.str.total_size = (uint32_t)value_len;
        hdr.value.str.reserved   = 0xFFFFFFFFu;
    }

    hdr.crc32 = nvs_entry_crc(&hdr);

    uint32_t dst_addr = nvs_page_entry_addr((uint32_t)g_active_page,
                                            (uint16_t)slot_idx);

    if (g_config.write(dst_addr, &hdr, NVS_ENTRY_SIZE) != 0)
    {
        return NVS_ERR_FLASH;
    }

    /* Write continuation slots for multi-entry values (strings/blobs) */
    if (span > 1u)
    {
        const uint8_t *src       = (const uint8_t *)value_bytes;
        uint32_t       remaining = (uint32_t)value_len;

        for (uint8_t s = 0u; s < span - 1u; s++)
        {
            uint8_t  slot_buf[NVS_ENTRY_SIZE];
            uint32_t slot_bytes = (remaining > NVS_ENTRY_SIZE)
                                  ? NVS_ENTRY_SIZE : remaining;
            memset(slot_buf, 0xFF, NVS_ENTRY_SIZE);
            memcpy(slot_buf, src, slot_bytes);

            uint32_t slot_addr = dst_addr + (uint32_t)(s + 1u) * NVS_ENTRY_SIZE;
            if (g_config.write(slot_addr, slot_buf, NVS_ENTRY_SIZE) != 0)
            {
                return NVS_ERR_FLASH;
            }
            src       += slot_bytes;
            remaining -= slot_bytes;

            nvs_bitmap_set((uint32_t)g_active_page,
                           (uint16_t)(slot_idx + 1u + s),
                           NVS_BITMAP_WRITTEN);
            g_pages[g_active_page].free_count--;
            g_pages[g_active_page].written_count++;
        }
    }

    rc = nvs_bitmap_set((uint32_t)g_active_page, (uint16_t)slot_idx,
                        NVS_BITMAP_WRITTEN);
    if (rc != NVS_OK) { return rc; }

    g_pages[g_active_page].free_count--;
    g_pages[g_active_page].written_count++;

    nvs_lookup_insert(ns_index, key, type, span, dst_addr);

    return NVS_OK;
}

/* -----------------------------------------------------------------------
 * Public API — lifecycle
 * --------------------------------------------------------------------- */

int nvs_init(const nvs_config_t *config)
{
    if (config == NULL)
    {
        return NVS_ERR_INVALID_ARG;
    }
    if (config->sector_size == 0u || config->num_sectors == 0u ||
        config->read  == NULL ||
        config->write == NULL ||
        config->erase == NULL)
    {
        return NVS_ERR_INVALID_ARG;
    }
    if (config->num_sectors > 64u)
    {
        return NVS_ERR_INVALID_ARG;
    }

    memcpy(&g_config, config, sizeof(nvs_config_t));

    g_initialized  = 0;
    g_num_pages    = config->num_sectors;
    g_active_page  = -1;
    g_ns_count     = 0;
    g_lookup_count = 0;
    g_write_seq    = 0;

    memset(g_pages,      0, sizeof(g_pages));
    memset(g_namespaces, 0, sizeof(g_namespaces));
    memset(g_lookup,     0, sizeof(g_lookup));
    memset(g_handles,    0, sizeof(g_handles));

    /* Pass 1: Read page headers and record state + sequence numbers */
    for (uint32_t i = 0u; i < g_num_pages; i++)
    {
        g_pages[i].base_addr = config->base_address + i * config->sector_size;

        nvs_page_hdr_t hdr;
        if (g_config.read(g_pages[i].base_addr, &hdr, sizeof(hdr)) == 0)
        {
            if (hdr.magic == NVS_PAGE_MAGIC &&
                nvs_page_hdr_crc(&hdr) == hdr.crc32)
            {
                g_pages[i].state  = hdr.state;
                g_pages[i].seq_no = hdr.sequence_no;
            }
            else
            {
                NVS_LOG("Page %u: invalid header (magic=0x%08X) — treating as empty",
                        i, hdr.magic);
                g_pages[i].state  = NVS_PAGE_STATE_EMPTY;
                g_pages[i].seq_no = 0u;
            }
        }
    }

    /*
     * Pass 2: Sort page indices by sequence number (ascending) so that
     * nvs_scan_page() processes them in write order and the lookup table
     * ends up with the most-recent value for each key.
     *
     * Insertion sort — O(n²) but n ≤ 64, so this is negligible.
     */
    uint32_t order[64];
    for (uint32_t i = 0u; i < g_num_pages; i++)
    {
        order[i] = i;
    }
    for (uint32_t i = 1u; i < g_num_pages; i++)
    {
        uint32_t key_val = order[i];
        uint32_t j       = i;
        while (j > 0u &&
               g_pages[order[j - 1u]].seq_no > g_pages[key_val].seq_no)
        {
            order[j] = order[j - 1u];
            j--;
        }
        order[j] = key_val;
    }

    /* Pass 3: Scan pages in sequence order */
    for (uint32_t i = 0u; i < g_num_pages; i++)
    {
        nvs_scan_page(order[i]);
    }

    /* Recover any page whose GC was interrupted (state == ERASING) */
    for (uint32_t i = 0u; i < g_num_pages; i++)
    {
        if (g_pages[i].state == NVS_PAGE_STATE_ERASING)
        {
            NVS_LOG("Page %u was mid-GC — completing erase", i);
            g_config.erase(g_pages[i].base_addr);
            g_pages[i].state       = NVS_PAGE_STATE_EMPTY;
            g_pages[i].free_count  = (uint16_t)nvs_page_entries_per_page();
            g_pages[i].entry_count = (uint16_t)nvs_page_entries_per_page();
            g_pages[i].data_start  = nvs_page_data_start(g_pages[i].base_addr);
        }
    }

    /* Select the Active page (highest sequence number among ACTIVE pages) */
    uint32_t best_seq = 0u;
    for (uint32_t i = 0u; i < g_num_pages; i++)
    {
        if (g_pages[i].state == NVS_PAGE_STATE_ACTIVE)
        {
            if (g_active_page < 0 || g_pages[i].seq_no > best_seq)
            {
                g_active_page = (int32_t)i;
                best_seq      = g_pages[i].seq_no;
            }
        }
    }

    /* No active page found — promote the first empty page */
    if (g_active_page < 0)
    {
        for (uint32_t i = 0u; i < g_num_pages; i++)
        {
            if (g_pages[i].state == NVS_PAGE_STATE_EMPTY)
            {
                int rc = nvs_page_init_empty(i);
                if (rc != NVS_OK) { return rc; }
                g_active_page = (int32_t)i;
                break;
            }
        }
    }

    /* Still no active page — run GC to reclaim space */
    if (g_active_page < 0)
    {
        int rc = nvs_garbage_collect();
        if (rc != NVS_OK) { return rc; }
    }

    g_initialized = 1;
    return NVS_OK;
}

int nvs_open(const char *name, nvs_open_mode_t mode, nvs_handle_t *out_handle)
{
    if (!g_initialized)                  { return NVS_ERR_NOT_INIT;    }
    if (name == NULL || out_handle == NULL) { return NVS_ERR_INVALID_ARG; }
    if (strlen(name) > NVS_KEY_MAX_LEN)  { return NVS_ERR_KEY_TOO_LONG; }

    /* Search for an existing namespace */
    uint8_t ns_idx = 0u;
    for (uint8_t i = 1u; i <= NVS_MAX_NAMESPACES; i++)
    {
        if (g_namespaces[i].in_use &&
            strncmp(g_namespaces[i].name, name, NVS_KEY_MAX_LEN) == 0)
        {
            ns_idx = i;
            break;
        }
    }

    if (ns_idx == 0u)
    {
        if (mode == NVS_READONLY)
        {
            return NVS_ERR_NOT_FOUND;
        }
        if (g_ns_count >= NVS_MAX_NAMESPACES)
        {
            return NVS_ERR_NS_FULL;
        }

        /* Create a new namespace */
        ns_idx    = (uint8_t)(g_ns_count + 1u);
        uint8_t v = ns_idx;
        int rc    = nvs_write_entry(0u, name, NVS_TYPE_U8, 1u, &v, sizeof(v));
        if (rc != NVS_OK) { return rc; }

        g_namespaces[ns_idx].in_use = 1;
        strncpy(g_namespaces[ns_idx].name, name, NVS_KEY_MAX_LEN);
        g_namespaces[ns_idx].name[NVS_KEY_MAX_LEN] = '\0';
        g_namespaces[ns_idx].index = ns_idx;
        g_ns_count = ns_idx;
    }

    /* Allocate a handle slot */
    for (uint32_t h = 0u; h < NVS_MAX_HANDLES; h++)
    {
        if (!g_handles[h].in_use)
        {
            g_handles[h].in_use   = 1;
            g_handles[h].mode     = mode;
            g_handles[h].ns_index = ns_idx;
            *out_handle = (nvs_handle_t)(h + 1u);
            return NVS_OK;
        }
    }
    return NVS_ERR_HANDLE;
}

int nvs_commit(nvs_handle_t handle)
{
    if (!g_initialized) { return NVS_ERR_NOT_INIT; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK)   { return rc; }

    /*
     * All writes are immediately programmed to flash; commit() is a
     * no-op in this implementation but is provided for API compatibility
     * with implementations that buffer writes.
     */
    return NVS_OK;
}

void nvs_close(nvs_handle_t handle)
{
    if (handle > 0u && handle <= NVS_MAX_HANDLES)
    {
        g_handles[handle - 1u].in_use = 0;
    }
}

/* -----------------------------------------------------------------------
 * Integer primitives — generated via X-macro
 * --------------------------------------------------------------------- */

#define NVS_IMPL_SET_GET(SUFFIX, CTYPE, TYPE_CODE)                          \
int nvs_set_##SUFFIX(nvs_handle_t h, const char *k, CTYPE v)               \
{                                                                            \
    return nvs_set_scalar(h, k, TYPE_CODE, &v, sizeof(CTYPE));             \
}                                                                            \
int nvs_get_##SUFFIX(nvs_handle_t h, const char *k, CTYPE *out)            \
{                                                                            \
    return nvs_get_scalar(h, k, TYPE_CODE, out, sizeof(CTYPE));            \
}

NVS_IMPL_SET_GET(u8,  uint8_t,  NVS_TYPE_U8)
NVS_IMPL_SET_GET(i8,  int8_t,   NVS_TYPE_I8)
NVS_IMPL_SET_GET(u16, uint16_t, NVS_TYPE_U16)
NVS_IMPL_SET_GET(i16, int16_t,  NVS_TYPE_I16)
NVS_IMPL_SET_GET(u32, uint32_t, NVS_TYPE_U32)
NVS_IMPL_SET_GET(i32, int32_t,  NVS_TYPE_I32)
NVS_IMPL_SET_GET(u64, uint64_t, NVS_TYPE_U64)
NVS_IMPL_SET_GET(i64, int64_t,  NVS_TYPE_I64)

/* -----------------------------------------------------------------------
 * String API
 * --------------------------------------------------------------------- */

int nvs_set_str(nvs_handle_t handle, const char *key, const char *value)
{
    if (!g_initialized)             { return NVS_ERR_NOT_INIT;    }
    if (key == NULL || value == NULL) { return NVS_ERR_INVALID_ARG; }
    if (strlen(key) > NVS_KEY_MAX_LEN) { return NVS_ERR_KEY_TOO_LONG; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK) { return rc; }

    nvs_handle_rec_t *hr = &g_handles[handle - 1u];
    if (hr->mode != NVS_READWRITE) { return NVS_ERR_READ_ONLY; }

    size_t   str_len    = strlen(value) + 1u;
    uint32_t cont_slots = (uint32_t)((str_len + NVS_ENTRY_SIZE - 1u)
                                     / NVS_ENTRY_SIZE);
    uint32_t total_span = 1u + cont_slots;
    if (total_span > 255u)
    {
        return NVS_ERR_VALUE_TOO_LARGE;
    }

    /* Erase old entry if present */
    nvs_lookup_t *old = NULL;
    if (nvs_lookup_find(hr->ns_index, key, &old) == NVS_OK)
    {
        nvs_mark_erased(old->flash_addr, old->span);
        nvs_lookup_remove(hr->ns_index, key);
    }

    return nvs_write_entry(hr->ns_index, key, NVS_TYPE_STR,
                           (uint8_t)total_span, value, str_len);
}

int nvs_get_str(nvs_handle_t handle, const char *key, char *buf, size_t *len)
{
    if (!g_initialized)         { return NVS_ERR_NOT_INIT;    }
    if (key == NULL || len == NULL) { return NVS_ERR_INVALID_ARG; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK) { return rc; }

    nvs_handle_rec_t *hr = &g_handles[handle - 1u];

    nvs_lookup_t *e = NULL;
    if (nvs_lookup_find(hr->ns_index, key, &e) != NVS_OK ||
        e->type != NVS_TYPE_STR)
    {
        return NVS_ERR_NOT_FOUND;
    }

    nvs_entry_hdr_t hdr;
    if (nvs_read_entry_hdr(e->flash_addr, &hdr) != NVS_OK)
    {
        return NVS_ERR_FLASH;
    }
    if (nvs_entry_crc(&hdr) != hdr.crc32)
    {
        return NVS_ERR_CORRUPT;
    }

    uint32_t total_size = hdr.value.str.total_size;

    /* Query mode: caller wants the required buffer size */
    if (buf == NULL)
    {
        *len = total_size;
        return NVS_OK;
    }
    if (*len < total_size)
    {
        return NVS_ERR_BUF_TOO_SMALL;
    }

    uint8_t *dst       = (uint8_t *)buf;
    uint32_t remaining = total_size;

    for (uint8_t s = 0u; s < hdr.span - 1u && remaining > 0u; s++)
    {
        uint32_t slot_addr = e->flash_addr + (uint32_t)(s + 1u) * NVS_ENTRY_SIZE;
        uint32_t read_len  = (remaining > NVS_ENTRY_SIZE)
                             ? NVS_ENTRY_SIZE : remaining;
        g_config.read(slot_addr, dst, read_len);
        dst       += read_len;
        remaining -= read_len;
    }
    *len = total_size;
    return NVS_OK;
}

/* -----------------------------------------------------------------------
 * Blob API
 * --------------------------------------------------------------------- */

int nvs_set_blob(nvs_handle_t handle, const char *key,
                 const void *data, size_t len)
{
    if (!g_initialized)              { return NVS_ERR_NOT_INIT;    }
    if (key == NULL || data == NULL) { return NVS_ERR_INVALID_ARG; }
    if (strlen(key) > NVS_KEY_MAX_LEN) { return NVS_ERR_KEY_TOO_LONG; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK) { return rc; }

    nvs_handle_rec_t *hr = &g_handles[handle - 1u];
    if (hr->mode != NVS_READWRITE) { return NVS_ERR_READ_ONLY; }

    uint32_t cont_slots = (uint32_t)((len + NVS_ENTRY_SIZE - 1u)
                                     / NVS_ENTRY_SIZE);
    uint32_t total_span = 1u + cont_slots;
    if (total_span > 255u)
    {
        return NVS_ERR_VALUE_TOO_LARGE;
    }

    nvs_lookup_t *old = NULL;
    if (nvs_lookup_find(hr->ns_index, key, &old) == NVS_OK)
    {
        nvs_mark_erased(old->flash_addr, old->span);
        nvs_lookup_remove(hr->ns_index, key);
    }

    return nvs_write_entry(hr->ns_index, key, NVS_TYPE_BLOB,
                           (uint8_t)total_span, data, len);
}

int nvs_get_blob(nvs_handle_t handle, const char *key,
                 void *buf, size_t *len)
{
    if (!g_initialized)          { return NVS_ERR_NOT_INIT;    }
    if (key == NULL || len == NULL) { return NVS_ERR_INVALID_ARG; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK) { return rc; }

    nvs_handle_rec_t *hr = &g_handles[handle - 1u];

    nvs_lookup_t *e = NULL;
    if (nvs_lookup_find(hr->ns_index, key, &e) != NVS_OK ||
        e->type != NVS_TYPE_BLOB)
    {
        return NVS_ERR_NOT_FOUND;
    }

    nvs_entry_hdr_t hdr;
    if (nvs_read_entry_hdr(e->flash_addr, &hdr) != NVS_OK)
    {
        return NVS_ERR_FLASH;
    }
    if (nvs_entry_crc(&hdr) != hdr.crc32)
    {
        return NVS_ERR_CORRUPT;
    }

    uint32_t total_size = hdr.value.str.total_size;

    if (buf == NULL)
    {
        *len = total_size;
        return NVS_OK;
    }
    if (*len < total_size)
    {
        return NVS_ERR_BUF_TOO_SMALL;
    }

    uint8_t *dst       = (uint8_t *)buf;
    uint32_t remaining = total_size;

    for (uint8_t s = 0u; s < hdr.span - 1u && remaining > 0u; s++)
    {
        uint32_t slot_addr = e->flash_addr + (uint32_t)(s + 1u) * NVS_ENTRY_SIZE;
        uint32_t read_len  = (remaining > NVS_ENTRY_SIZE)
                             ? NVS_ENTRY_SIZE : remaining;
        g_config.read(slot_addr, dst, read_len);
        dst       += read_len;
        remaining -= read_len;
    }
    *len = total_size;
    return NVS_OK;
}

/* -----------------------------------------------------------------------
 * Erase API
 * --------------------------------------------------------------------- */

int nvs_erase_key(nvs_handle_t handle, const char *key)
{
    if (!g_initialized)         { return NVS_ERR_NOT_INIT;    }
    if (key == NULL)            { return NVS_ERR_INVALID_ARG; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK) { return rc; }

    nvs_handle_rec_t *hr = &g_handles[handle - 1u];
    if (hr->mode != NVS_READWRITE) { return NVS_ERR_READ_ONLY; }

    nvs_lookup_t *e = NULL;
    if (nvs_lookup_find(hr->ns_index, key, &e) != NVS_OK)
    {
        return NVS_ERR_NOT_FOUND;
    }
    nvs_mark_erased(e->flash_addr, e->span);
    nvs_lookup_remove(hr->ns_index, key);
    return NVS_OK;
}

int nvs_erase_all(nvs_handle_t handle)
{
    if (!g_initialized) { return NVS_ERR_NOT_INIT; }

    int rc = nvs_validate_handle(handle);
    if (rc != NVS_OK) { return rc; }

    nvs_handle_rec_t *hr = &g_handles[handle - 1u];
    if (hr->mode != NVS_READWRITE) { return NVS_ERR_READ_ONLY; }

    uint8_t ns = hr->ns_index;
    for (uint32_t i = 0u; i < g_lookup_count; )
    {
        if (g_lookup[i].ns_index == ns)
        {
            nvs_mark_erased(g_lookup[i].flash_addr, g_lookup[i].span);
            g_lookup[i] = g_lookup[--g_lookup_count];
        }
        else
        {
            i++;
        }
    }
    return NVS_OK;
}
