#ifndef BYE_DESYNC_H
#define BYE_DESYNC_H

#include <stddef.h>
#include <stdint.h>

#include "bye_sniff.h"

#ifdef __cplusplus
extern "C" {
#endif

/* how the first bytes of a connection are cut before they reach the network.
   a filter that matches the server name in one packet misses it when the name
   is split over segments or over tls records.

   positions are written against the bytes the app sent:
     N         N bytes from the start
     name      where the server name starts (sni, or the http host value)
     name+N    N bytes after that, name-N before it
     mid       the middle of the name
     end       the end of the name

   a spec is clauses separated by ';':
     split=P[,P...]   cut the stream into segments before each position
     tlsrec=P         cut the tls record in two records at P (tls only)
     oob=P            send one urgent byte after position P

   a plan is only built for the first payload of a flow.

   a strategy list is specs separated by '|', at most four. `none` is a spec
   that changes nothing. the daemon tries them in turn when a flow gets no
   answer, see bye_tcp.h */

#define BYE_DESYNC_SPLIT_MAX 4
#define BYE_DESYNC_OPS_MAX 64
#define BYE_DESYNC_TLSREC_GROWTH 5
#define BYE_DESYNC_OOB_BYTE 0x61

typedef enum {
    BYE_POS_ABS = 0,
    BYE_POS_NAME,
    BYE_POS_MID,
    BYE_POS_END
} bye_pos_kind_t;

typedef struct {
    bye_pos_kind_t kind;
    int32_t        delta;
} bye_pos_t;

/* the options of ciadpi (byedpi), see bye_ciadpi.h. a position is
   offset[:repeats[:skip]][+flags] as it is written there */
#define BYE_OFFSET_END   1u
#define BYE_OFFSET_MID   2u
#define BYE_OFFSET_RAND  4u
#define BYE_OFFSET_SNI   8u   /* from the start of the tls server name */
#define BYE_OFFSET_HOST  16u  /* from the start of the name, tls or http */
#define BYE_OFFSET_START 32u

typedef struct {
    int32_t  offset;
    uint32_t flags;   /* BYE_OFFSET_* */
    uint32_t repeats; /* 0 and 1 are one cut */
    int32_t  skip;    /* added to the offset for each repeat after the first */
} bye_offset_t;

typedef enum {
    BYE_PART_SPLIT = 0,
    BYE_PART_DISORDER, /* the part leaves with ttl 1, so the kernel has to send it again */
    BYE_PART_OOB,      /* the part ends with an urgent byte that replaces the next one */
    BYE_PART_DISOOB    /* both */
} bye_part_mode_t;

typedef struct {
    uint8_t      mode;
    bye_offset_t pos;
} bye_part_t;

#define BYE_PARTS_MAX 32
#define BYE_TLSREC_MAX 8
#define BYE_HTTP_HMIX  1u  /* "Host" becomes "hOsT" */
#define BYE_HTTP_DMIX  2u  /* every second letter of the name is a capital */
#define BYE_HTTP_SPACE 4u  /* the space after "Host:" becomes tabs behind the name */
#define BYE_PROTO_TLS  1u
#define BYE_PROTO_HTTP 2u
#define BYE_TRIGGER_TORST    1u /* a timeout, a reset or a close before any answer */
#define BYE_TRIGGER_REDIRECT 2u /* an http redirect to another domain */
#define BYE_TRIGGER_TLSERR   4u /* an answer to a hello that is not a handshake record */
/* the most the plan adds to the app's bytes: a record header per tlsrec cut
   and the byte behind the last urgent part */
#define BYE_DESYNC_GROWTH_MAX (BYE_DESYNC_TLSREC_GROWTH * BYE_TLSREC_MAX + 1)

typedef struct {
    /* the specs of this program: split, tlsrec and oob, cuts sorted by where
       they land. unused when cli is set */
    bye_pos_t split[BYE_DESYNC_SPLIT_MAX];
    size_t    split_count;
    int       has_tlsrec;
    bye_pos_t tlsrec;
    int       has_oob;
    bye_pos_t oob;

    /* one group of ciadpi options, used instead of the fields above */
    int          cli;
    bye_part_t   parts[BYE_PARTS_MAX];
    size_t       part_count;
    bye_offset_t tlsrec_parts[BYE_TLSREC_MAX];
    size_t       tlsrec_count;
    uint8_t      oob_char;
    int          oob_char_set; /* without it the urgent byte is 'a' */
    uint32_t     mod_http;     /* BYE_HTTP_* */
    uint8_t      tlsminor;     /* 0 leaves the version alone */
    uint32_t     proto;        /* BYE_PROTO_*, 0 for any */
    uint32_t     trigger;      /* BYE_TRIGGER_*: the failures that send a flow here */
} bye_desync_t;

#define BYE_OP_TTL1 1u /* the segment leaves with ttl 1 */
#define BYE_OP_OOB  2u /* the byte behind the segment is replaced by the urgent byte
                          and goes with it in one MSG_OOB send */

typedef struct {
    size_t   off; /* into the plan's output buffer */
    size_t   len;
    int      oob_after; /* send one urgent byte once this segment is out */
    uint32_t flags;     /* BYE_OP_*, set by the options of ciadpi only */
} bye_op_t;

typedef struct {
    bye_op_t ops[BYE_DESYNC_OPS_MAX];
    size_t   count;
    size_t   total; /* bytes in the output buffer, with one more writable */
    int      applied; /* the name was found and the bytes were changed or cut */
    int      has_name; /* the app's bytes hold a server name at name_off */
    int      tls;      /* the name is a tls sni, not an http host */
    size_t   name_off;
    size_t   name_len;
    uint8_t  oob_char; /* the byte of a BYE_OP_OOB segment */
} bye_plan_t;

typedef enum {
    BYE_DESYNC_OK        =  0,
    BYE_DESYNC_NEED_MORE =  1, /* the first payload is not complete yet */
    BYE_DESYNC_ERR_ARG   = -1,
    BYE_DESYNC_ERR_SPEC  = -2,
    BYE_DESYNC_ERR_SPACE = -3  /* out is too small, see bye_desync_build */
} bye_desync_status_t;

#define BYE_STRATEGIES_MAX 8
#define BYE_STRATEGY_SPEC_MAX 96
/* one original ByeDPI command line inside a list, as long as the whole config value may be */
#define BYE_STRATEGY_LINE_MAX 1024
#define BYE_NOTES_MAX 640

typedef struct {
    bye_desync_t item[BYE_STRATEGIES_MAX];
    size_t       count;
    uint32_t     timeout_ms; /* -T: the wait for an answer, 0 for the default */
    uint8_t      def_ttl;    /* -g: the ttl a socket gets back after a ttl 1 part, 0 for the one it had */
    /* what the options asked for that this system does not do, one line each */
    char         notes[BYE_NOTES_MAX];
} bye_strategies_t;

/* filters can require different split positions, and some servers reject modified packets
   auto tries the built-in strategies in order and remembers a passing one to avoid repeated waits */
extern const char BYE_STRATEGIES_DEFAULT[];
extern const char BYE_STRATEGIES_AUTO_LIST[];

/* the default for a blocked tls site: a tls record cut inside the name and the
   stream cut after the first byte and inside the name */
extern const char BYE_DESYNC_DEFAULT_SPEC[];

bye_desync_status_t bye_desync_parse(const char *spec, bye_desync_t *out,
                                     char *error, size_t error_cap);

/* a list of one to BYE_STRATEGIES_MAX specs. an empty item is an error, so a
   stray '|' is not read as a strategy that changes nothing. an item that starts
   with '-' is the command line of ciadpi, see bye_ciadpi.h: its groups join the
   list one by one and its notes, -T and -g carry over */
bye_desync_status_t bye_strategies_parse(const char *list, bye_strategies_t *out,
                                         char *error, size_t error_cap);

/* the next step of a failed flow. step j uses item[(start + j) % count], the
   flow began at step 0 and is on `attempt`. `kind` is one BYE_TRIGGER_* value.
   returns the first step above `attempt` that takes this failure, or 0 when
   none does. a strategy of the spec syntax takes every failure, a group of
   ciadpi options only those its -A flags name */
size_t bye_strategies_after(const bye_strategies_t *list, size_t start, size_t attempt,
                            uint32_t kind);

/* builds the plan for the first payload. a payload with no name, or another
   protocol, gets a single segment holding the bytes unchanged. the bytes the
   plan sends, with the urgent bytes left out, are the app's bytes with at most
   one record header inserted. out_cap must be in_len + BYE_DESYNC_GROWTH_MAX */
bye_desync_status_t bye_desync_build(const bye_desync_t *desync, const uint8_t *in,
                                     size_t in_len, uint8_t *out, size_t out_cap,
                                     bye_plan_t *plan);

#ifdef __cplusplus
}
#endif

#endif
