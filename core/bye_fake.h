#ifndef BYE_FAKE_H
#define BYE_FAKE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* what a fake packet of ciadpi (-f) needs outside the kernel's tcp: xnu has no
   way to swap the bytes of a send that is already queued, so the fake leaves as
   a raw ipv4 packet with the sequence number of the real bytes that follow it.
   a low ttl keeps it from the server, the filter on the path still reads it.

   the sequence numbers of a socket cannot be read back on ios 5 to 16, so the
   daemon watches the syn and syn-ack of every connection it makes with bpf and
   keeps them in a bye_fake_track_t */

#define BYE_FAKE_TTL_DEFAULT 8
#define BYE_FAKE_SNI_MAX 64
#define BYE_FAKE_SNI_DEFAULT "www.iana.org"
#define BYE_FAKE_HOST_DEFAULT "www.w3.org"
#define BYE_FAKE_DATA_MAX 1500
/* one segment: a fake longer than this is cut, the real bytes still go out whole */
#define BYE_FAKE_PAYLOAD_MAX 1400
#define BYE_FAKE_BLOB_MAX 2048
#define BYE_FAKE_PACKET_MAX (20 + 20 + 20 + BYE_FAKE_PAYLOAD_MAX)

#define BYE_FAKE_MOD_RAND  1u /* -Q r: a new random, session id and key */
#define BYE_FAKE_MOD_ORIG  2u /* -Q o: the app's own hello with the name replaced */
#define BYE_FAKE_MOD_MIMIC 4u /* -Q m: the length of the app's hello */
#define BYE_FAKE_MOD_DUPSID 8u /* -Q d: the app's session id */

typedef struct {
    uint8_t        src[4], dst[4];
    uint16_t       sport, dport; /* host order */
    uint32_t       seq, ack;     /* host order */
    uint8_t        ttl;
    uint16_t       id;
    int            md5sig;       /* a tcp md5 option, which no server accepts without a key */
    const uint8_t *payload;
    size_t         len;
} bye_fake_packet_t;

/* ipv4 and tcp headers, checksums done, flags psh and ack. darwin takes the
   length and the fragment field of a raw packet in host order, which is what
   host_order asks for. returns the size, or 0 when out_cap or len is too small
   or too large */
size_t bye_fake_packet_build(const bye_fake_packet_t *packet, int host_order, uint8_t *out,
                             size_t out_cap);

/* the link types bpf reports */
#define BYE_LINK_NULL     0u
#define BYE_LINK_ETHERNET 1u
#define BYE_LINK_RAW      12u

typedef struct {
    uint8_t  src[4], dst[4];
    uint16_t sport, dport; /* host order */
    uint32_t seq;          /* host order */
    uint8_t  flags;        /* the tcp flags byte */
} bye_fake_syn_t;

/* 1 for an ipv4 tcp segment with syn set that fits the frame, 0 for anything else */
int bye_fake_syn_parse(unsigned link, const uint8_t *frame, size_t len, bye_fake_syn_t *out);

typedef struct {
    uint16_t code;
    uint8_t  jt, jf;
    uint32_t k;
} bye_bpf_insn_t;

#define BYE_BPF_FILTER_MAX 16

/* a filter that keeps ipv4 tcp syn and syn-ack, not fragments. returns the
   number of instructions, 0 for a link type it does not know */
size_t bye_fake_bpf_filter(unsigned link, bye_bpf_insn_t *out, size_t cap);

/* syn and syn-ack of the connections the daemon made, newest over oldest */
#define BYE_FAKE_TRACK_MAX 256

typedef struct {
    uint8_t  local[4], remote[4];
    uint16_t lport, rport;
    uint32_t isn;     /* ours */
    uint32_t sisn;    /* the server's, valid when have_sisn */
    int      have_sisn;
    int      used;
} bye_fake_entry_t;

typedef struct {
    bye_fake_entry_t entry[BYE_FAKE_TRACK_MAX];
    size_t           next;
} bye_fake_track_t;

void bye_fake_track_init(bye_fake_track_t *track);
/* a syn starts an entry, a syn-ack completes the entry of the syn it answers */
void bye_fake_track_note(bye_fake_track_t *track, const bye_fake_syn_t *syn);
/* 1 and both numbers when the connection is known and the server answered */
int bye_fake_track_find(const bye_fake_track_t *track, const uint8_t local[4], uint16_t lport,
                        const uint8_t remote[4], uint16_t rport, uint32_t *isn, uint32_t *sisn);

/* a tls hello of 517 bytes in the shape of a browser's, with the name `sni`
   (the default when NULL). with BYE_FAKE_MOD_ORIG and a hello in `real` the
   app's own bytes carry the name instead, and BYE_FAKE_MOD_MIMIC pads the
   result to the length of `real`. returns the size, 0 when cap is too small */
size_t bye_fake_tls(uint8_t *out, size_t cap, const char *sni, uint32_t mods,
                    const uint8_t *real, size_t real_len, uint32_t seed);

/* a plain request for `host` (the default when NULL) */
size_t bye_fake_http(uint8_t *out, size_t cap, const char *host);

#ifdef __cplusplus
}
#endif

#endif
