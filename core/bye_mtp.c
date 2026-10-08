#include "bye_mtp.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_LEN 32
#define IV_LEN 16
#define HDR_MAX 4

struct bye_mtp {
    EVP_CIPHER_CTX *client_dec; /* the client's bytes to plain */
    EVP_CIPHER_CTX *client_enc; /* plain to the client */
    EVP_CIPHER_CTX *dc_enc;     /* plain to the datacenter */
    EVP_CIPHER_CTX *dc_dec;     /* the datacenter's bytes to plain */

    uint32_t proto;
    int      pass;          /* the splitter gave up: every read is a message */
    uint8_t  hdr[HDR_MAX];  /* plain header bytes of the packet being read */
    size_t   hdr_len;
    size_t   total;         /* length of that packet with its header, 0 if unknown */
    size_t   got;           /* bytes of it seen so far */
    uint8_t *held;          /* encrypted bytes of an incomplete packet */
    size_t   held_len;
    size_t   held_cap;
};

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static int valid_proto(uint32_t tag) {
    return tag == BYE_MTP_TAG_ABRIDGED || tag == BYE_MTP_TAG_INTERMEDIATE ||
           tag == BYE_MTP_TAG_PADDED;
}

static int is_http(const uint8_t *p) {
    return memcmp(p, "POST", 4) == 0 || memcmp(p, "GET ", 4) == 0 ||
           memcmp(p, "HEAD", 4) == 0 || memcmp(p, "OPTI", 4) == 0;
}

static int derive_key(const uint8_t *prekey, const uint8_t *secret, size_t secret_len,
                      uint8_t key[KEY_LEN]) {
    if (secret_len == 0) {
        memcpy(key, prekey, KEY_LEN);
        return 0;
    }
    uint8_t material[KEY_LEN + BYE_MTP_SECRET_MAX];
    unsigned int out_len = 0;
    memcpy(material, prekey, KEY_LEN);
    memcpy(material + KEY_LEN, secret, secret_len);
    return EVP_Digest(material, KEY_LEN + secret_len, key, &out_len, EVP_sha256(), NULL) == 1 &&
           out_len == KEY_LEN ? 0 : -1;
}

static EVP_CIPHER_CTX *ctr_new(const uint8_t key[KEY_LEN], const uint8_t iv[IV_LEN]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return NULL;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int ctr_apply(EVP_CIPHER_CTX *ctx, uint8_t *data, size_t len) {
    while (len > 0) {
        int step = len > (size_t)INT_MAX / 2 ? INT_MAX / 2 : (int)len;
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx, data, &out_len, data, step) != 1 || out_len != step)
            return -1;
        data += step;
        len -= (size_t)step;
    }
    return 0;
}

static void reverse48(const uint8_t *in, uint8_t *out) {
    for (size_t i = 0; i < 48; ++i) out[i] = in[47 - i];
}

/* the first bytes of the relay init are read by filters and by the datacenter's
   own protocol detection, so they must not look like another protocol */
static int relay_init_ok(const uint8_t *p) {
    if (p[0] == 0xEF) return 0;
    if (memcmp(p, "HEAD", 4) == 0 || memcmp(p, "POST", 4) == 0 || memcmp(p, "GET ", 4) == 0)
        return 0;
    if (le32(p) == BYE_MTP_TAG_INTERMEDIATE || le32(p) == BYE_MTP_TAG_PADDED) return 0;
    if (p[0] == 0x16 && p[1] == 0x03 && p[2] == 0x01 && p[3] == 0x02) return 0;
    if (p[4] == 0 && p[5] == 0 && p[6] == 0 && p[7] == 0) return 0;
    return 1;
}

void bye_mtp_close(bye_mtp_t *mtp) {
    if (!mtp) return;
    EVP_CIPHER_CTX_free(mtp->client_dec);
    EVP_CIPHER_CTX_free(mtp->client_enc);
    EVP_CIPHER_CTX_free(mtp->dc_enc);
    EVP_CIPHER_CTX_free(mtp->dc_dec);
    free(mtp->held);
    free(mtp);
}

bye_mtp_status_t bye_mtp_open(bye_mtp_t **out, const uint8_t *secret, size_t secret_len,
                              const uint8_t client_init[BYE_MTP_INIT_LEN],
                              bye_mtp_route_t *route,
                              uint8_t relay_init[BYE_MTP_INIT_LEN]) {
    if (out) *out = NULL;
    if (!out || !client_init || !route || !relay_init || secret_len > BYE_MTP_SECRET_MAX ||
        (secret_len && !secret))
        return BYE_MTP_ERR_ARG;
    memset(route, 0, sizeof *route);
    if (is_http(client_init)) return BYE_MTP_ERR_HTTP;

    bye_mtp_t *mtp = calloc(1, sizeof *mtp);
    if (!mtp) return BYE_MTP_ERR_MEMORY;
    bye_mtp_status_t status = BYE_MTP_ERR_CRYPTO;

    uint8_t key[KEY_LEN];
    uint8_t rev[48];

    if (derive_key(client_init + 8, secret, secret_len, key) != 0) goto fail;
    mtp->client_dec = ctr_new(key, client_init + 40);
    if (!mtp->client_dec) goto fail;

    uint8_t plain[BYE_MTP_INIT_LEN];
    memcpy(plain, client_init, sizeof plain);
    if (ctr_apply(mtp->client_dec, plain, sizeof plain) != 0) goto fail;

    uint32_t proto = le32(plain + 56);
    if (!valid_proto(proto)) {
        status = BYE_MTP_ERR_INIT;
        goto fail;
    }
    int dc_raw = (int16_t)((uint16_t)plain[60] | ((uint16_t)plain[61] << 8));
    mtp->proto = proto;
    route->proto = proto;
    route->is_media = dc_raw < 0;
    route->dc = dc_raw < 0 ? -dc_raw : dc_raw;

    reverse48(client_init + 8, rev);
    if (derive_key(rev, secret, secret_len, key) != 0) goto fail;
    mtp->client_enc = ctr_new(key, rev + 32);
    if (!mtp->client_enc) goto fail;

    do {
        if (RAND_bytes(relay_init, BYE_MTP_INIT_LEN) != 1) goto fail;
    } while (!relay_init_ok(relay_init));

    reverse48(relay_init + 8, rev);
    mtp->dc_dec = ctr_new(rev, rev + 32);
    mtp->dc_enc = ctr_new(relay_init + 8, relay_init + 40);
    if (!mtp->dc_dec || !mtp->dc_enc) goto fail;

    /* the tail of the init holds the tag and the datacenter. it is sent as
       plain bytes xor the key stream, so the datacenter reads them back */
    uint8_t tail[8];
    int16_t dc_value = (int16_t)(route->is_media ? -route->dc : route->dc);
    tail[0] = (uint8_t)proto;
    tail[1] = (uint8_t)(proto >> 8);
    tail[2] = (uint8_t)(proto >> 16);
    tail[3] = (uint8_t)(proto >> 24);
    tail[4] = (uint8_t)(uint16_t)dc_value;
    tail[5] = (uint8_t)((uint16_t)dc_value >> 8);
    if (RAND_bytes(tail + 6, 2) != 1) goto fail;

    uint8_t encrypted[BYE_MTP_INIT_LEN];
    memcpy(encrypted, relay_init, sizeof encrypted);
    if (ctr_apply(mtp->dc_enc, encrypted, sizeof encrypted) != 0) goto fail;
    for (size_t i = 0; i < 8; ++i)
        relay_init[56 + i] = tail[i] ^ (uint8_t)(encrypted[56 + i] ^ relay_init[56 + i]);

    *out = mtp;
    return BYE_MTP_OK;
fail:
    bye_mtp_close(mtp);
    memset(relay_init, 0, BYE_MTP_INIT_LEN);
    return status;
}

bye_mtp_status_t bye_mtp_down(bye_mtp_t *mtp, uint8_t *data, size_t len) {
    if (!mtp || (!data && len)) return BYE_MTP_ERR_ARG;
    if (ctr_apply(mtp->dc_dec, data, len) != 0 || ctr_apply(mtp->client_enc, data, len) != 0)
        return BYE_MTP_ERR_CRYPTO;
    return BYE_MTP_OK;
}

static int hold(bye_mtp_t *mtp, const uint8_t *data, size_t len) {
    if (len > BYE_MTP_PACKET_MAX + HDR_MAX - mtp->held_len) return -1;
    size_t need = mtp->held_len + len;
    if (need > mtp->held_cap) {
        size_t cap = mtp->held_cap ? mtp->held_cap : 4096;
        while (cap < need) cap *= 2;
        if (cap > BYE_MTP_PACKET_MAX + HDR_MAX) cap = BYE_MTP_PACKET_MAX + HDR_MAX;
        uint8_t *grown = realloc(mtp->held, cap);
        if (!grown) return -1;
        mtp->held = grown;
        mtp->held_cap = cap;
    }
    memcpy(mtp->held + mtp->held_len, data, len);
    mtp->held_len += len;
    return 0;
}

static void reset_packet(bye_mtp_t *mtp) {
    mtp->hdr_len = 0;
    mtp->total = 0;
    mtp->got = 0;
    mtp->held_len = 0;
    /* an upload leaves a megabyte behind otherwise */
    if (mtp->held_cap > 64 * 1024) {
        free(mtp->held);
        mtp->held = NULL;
        mtp->held_cap = 0;
    }
}

/* how many header bytes the packet needs before its length is known */
static size_t header_need(const bye_mtp_t *mtp) {
    if (mtp->proto == BYE_MTP_TAG_ABRIDGED)
        return (mtp->hdr[0] & 0x7F) == 0x7F ? 4 : 1;
    return 4;
}

/* 0 for a packet with no payload, which no client sends: the stream is not
   what the splitter expects, so it stops cutting */
static size_t packet_length(const bye_mtp_t *mtp) {
    size_t header, payload;
    if (mtp->proto == BYE_MTP_TAG_ABRIDGED) {
        uint32_t first = mtp->hdr[0] & 0x7F;
        if (first == 0x7F) {
            header = 4;
            payload = ((size_t)mtp->hdr[1] | ((size_t)mtp->hdr[2] << 8) |
                       ((size_t)mtp->hdr[3] << 16)) * 4;
        } else {
            header = 1;
            payload = (size_t)first * 4;
        }
    } else {
        header = 4;
        payload = le32(mtp->hdr) & 0x7FFFFFFFu;
    }
    if (payload == 0) return 0;
    if (payload > BYE_MTP_PACKET_MAX) return (size_t)-1;
    return header + payload;
}

bye_mtp_status_t bye_mtp_up(bye_mtp_t *mtp, uint8_t *data, size_t len,
                            bye_mtp_emit_fn emit, void *ctx) {
    if (!mtp || (!data && len)) return BYE_MTP_ERR_ARG;
    if (len == 0) return BYE_MTP_OK;
    if (ctr_apply(mtp->client_dec, data, len) != 0) return BYE_MTP_ERR_CRYPTO;

    /* data holds plain bytes now. the length of each packet is read from them,
       and each packet is encrypted for the datacenter just before it goes out */
    size_t seg = 0, pos = 0;
    while (pos < len && emit && !mtp->pass) {
        if (mtp->total == 0) {
            mtp->hdr[mtp->hdr_len++] = data[pos++];
            if (mtp->hdr_len < header_need(mtp)) continue;
            size_t total = packet_length(mtp);
            if (total == (size_t)-1) return BYE_MTP_ERR_PACKET;
            if (total == 0) {
                mtp->pass = 1;
                break;
            }
            mtp->total = total;
            mtp->got = mtp->hdr_len;
            if (mtp->got < mtp->total) continue;
        } else {
            size_t take = mtp->total - mtp->got;
            if (take > len - pos) take = len - pos;
            pos += take;
            mtp->got += take;
            if (mtp->got < mtp->total) continue;
        }

        if (ctr_apply(mtp->dc_enc, data + seg, pos - seg) != 0) return BYE_MTP_ERR_CRYPTO;
        int refused;
        if (mtp->held_len) {
            if (hold(mtp, data + seg, pos - seg) != 0) return BYE_MTP_ERR_PACKET;
            refused = emit(ctx, mtp->held, mtp->held_len);
        } else {
            refused = emit(ctx, data + seg, pos - seg);
        }
        if (refused) return BYE_MTP_ERR_EMIT;
        seg = pos;
        reset_packet(mtp);
    }

    if (ctr_apply(mtp->dc_enc, data + seg, len - seg) != 0) return BYE_MTP_ERR_CRYPTO;
    if (seg == len) return BYE_MTP_OK;
    if (!emit) return BYE_MTP_OK;
    if (mtp->pass) {
        /* what was held and the rest of this read go out as one message */
        if (mtp->held_len && hold(mtp, data + seg, len - seg) != 0) return BYE_MTP_ERR_PACKET;
        const uint8_t *msg = mtp->held_len ? mtp->held : data + seg;
        size_t msg_len = mtp->held_len ? mtp->held_len : len - seg;
        mtp->held_len = 0;
        return emit(ctx, msg, msg_len) ? BYE_MTP_ERR_EMIT : BYE_MTP_OK;
    }
    return hold(mtp, data + seg, len - seg) == 0 ? BYE_MTP_OK : BYE_MTP_ERR_PACKET;
}

bye_mtp_status_t bye_mtp_up_flush(bye_mtp_t *mtp, bye_mtp_emit_fn emit, void *ctx) {
    if (!mtp || !emit) return BYE_MTP_ERR_ARG;
    if (mtp->held_len == 0) return BYE_MTP_OK;
    int refused = emit(ctx, mtp->held, mtp->held_len);
    reset_packet(mtp);
    return refused ? BYE_MTP_ERR_EMIT : BYE_MTP_OK;
}
