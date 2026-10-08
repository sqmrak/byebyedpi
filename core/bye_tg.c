#include "bye_tg.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    int     dc;
    uint8_t address[4];
} dc_entry_t;

static const dc_entry_t DCS[] = {
    { 1,   { 149, 154, 175, 50 } },
    { 2,   { 149, 154, 167, 51 } },
    { 3,   { 149, 154, 175, 100 } },
    { 4,   { 149, 154, 167, 91 } },
    { 5,   { 149, 154, 171, 5 } },
    { BYE_TG_DC_CDN, { 91, 105, 192, 100 } }
};

typedef struct {
    uint8_t net[16];
    uint8_t bits;
    uint8_t len;
} range_t;

#define V4(a, b, c, d, bits) { { a, b, c, d }, bits, 4 }
#define V6(bits, ...) { { __VA_ARGS__ }, bits, 16 }

static const range_t RANGES[] = {
    V4(91, 105, 192, 0, 23),
    V4(91, 108, 4, 0, 22),
    V4(91, 108, 8, 0, 22),
    V4(91, 108, 12, 0, 22),
    V4(91, 108, 16, 0, 22),
    V4(91, 108, 20, 0, 22),
    V4(91, 108, 56, 0, 22),
    V4(149, 154, 160, 0, 20),
    V4(185, 76, 151, 0, 24),
    V6(48, 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3c),
    V6(48, 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3d),
    V6(48, 0x20, 0x01, 0x0b, 0x28, 0xf2, 0x3f),
    V6(48, 0x20, 0x01, 0x06, 0x7c, 0x04, 0xe8),
    V6(32, 0x2a, 0x0a, 0xf2, 0x80)
};

int bye_tg_dc_known(int dc) {
    for (size_t i = 0; i < sizeof DCS / sizeof DCS[0]; ++i)
        if (DCS[i].dc == dc) return 1;
    return 0;
}

int bye_tg_dc_address(int dc, uint8_t out[4]) {
    for (size_t i = 0; i < sizeof DCS / sizeof DCS[0]; ++i) {
        if (DCS[i].dc == dc) {
            memcpy(out, DCS[i].address, 4);
            return 0;
        }
    }
    return -1;
}

int bye_tg_ws_host(int dc, int is_media, unsigned variant, char *out, size_t cap) {
    if (variant >= BYE_TG_WS_VARIANTS || !out || !cap || !bye_tg_dc_known(dc)) return -1;
    int gateway = dc == BYE_TG_DC_CDN ? 2 : dc;
    /* the media gateway is the "-1" host, and each kind falls back to the other */
    int suffix = (variant == 0) == (is_media != 0);
    int n = snprintf(out, cap, suffix ? "kws%d-1.web.telegram.org" : "kws%d.web.telegram.org",
                     gateway);
    return n > 0 && (size_t)n < cap ? 0 : -1;
}

size_t bye_tg_gateways(int dc, int is_media, const bye_tg_ws_addresses_t *resolved,
                       bye_tg_gateway_t *out, size_t cap) {
    if (!out) return 0;
    size_t clear = cap < BYE_TG_GATEWAYS_MAX ? cap : BYE_TG_GATEWAYS_MAX;
    memset(out, 0, sizeof *out * clear);
    if (cap < BYE_TG_GATEWAYS_MAX || !bye_tg_dc_known(dc)) return 0;
    int gateway_dc = dc == BYE_TG_DC_CDN ? 2 : dc;
    size_t count = 0;
    for (unsigned pass = 0; pass < 2; ++pass) {
        for (unsigned variant = 0; variant < BYE_TG_WS_VARIANTS; ++variant) {
            bye_tg_gateway_t entry;
            memset(&entry, 0, sizeof entry);
            if (bye_tg_ws_host(dc, is_media, variant, entry.host, sizeof entry.host) != 0)
                continue;
            if (pass == 0) {
                unsigned media = (variant == 0) == (is_media != 0);
                if (!resolved || !resolved->dc[gateway_dc - 1][media].valid) continue;
                memcpy(entry.address, resolved->dc[gateway_dc - 1][media].address, 4);
            } else if (bye_tg_dc_address(dc, entry.address) != 0) {
                continue;
            }
            size_t i;
            for (i = 0; i < count; ++i)
                if (!strcmp(out[i].host, entry.host) &&
                    !memcmp(out[i].address, entry.address, 4)) break;
            if (i == count) out[count++] = entry;
        }
    }
    return count;
}

size_t bye_tg_gateway_next(const bye_tg_gateway_t *gateways, size_t count,
                           size_t current, int tcp_failed) {
    if (!gateways || count > BYE_TG_GATEWAYS_MAX || current >= count) return count;
    size_t next = current + 1;
    while (tcp_failed && next < count &&
           !memcmp(gateways[current].address, gateways[next].address, 4)) ++next;
    return next;
}

static int in_range(const range_t *range, const uint8_t *addr) {
    size_t whole = range->bits / 8;
    unsigned rest = range->bits % 8;
    if (memcmp(range->net, addr, whole) != 0) return 0;
    if (!rest) return 1;
    uint8_t mask = (uint8_t)(0xFF << (8 - rest));
    return (range->net[whole] & mask) == (addr[whole] & mask);
}

int bye_tg_is_address(const uint8_t *addr, size_t addr_len) {
    if (!addr || (addr_len != 4 && addr_len != 16)) return 0;
    for (size_t i = 0; i < sizeof RANGES / sizeof RANGES[0]; ++i)
        if (RANGES[i].len == addr_len && in_range(&RANGES[i], addr)) return 1;
    return 0;
}
