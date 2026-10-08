/* transparent capture on real packet bytes: a syn to an arbitrary address
   becomes a flow with its original tuple, the stack's answer goes back from
   that address, and flows that share a port never mix. checksums are checked
   by an independent implementation here, not by the module under test */

#include "tun_nat.h"
#include "packet_fixture.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void ok(const char *name, int condition) {
    if (condition) return;
    ++failures;
    fprintf(stderr, "FAIL %s\n", name);
}

static const uint8_t APP4[4]   = { 198, 18, 0, 1 };
static const uint8_t LOCAL4[4] = { 198, 18, 0, 2 };
static const uint8_t SYNTH4[4] = { 198, 18, 0, 3 };
static const uint8_t DEST4A[4] = { 203, 0, 113, 7 };
static const uint8_t DEST4B[4] = { 203, 0, 113, 8 };

static const uint8_t APP6[16]   = { 0xfd, 0, 0x5e, 0x4b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static const uint8_t LOCAL6[16] = { 0xfd, 0, 0x5e, 0x4b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
static const uint8_t SYNTH6[16] = { 0xfd, 0, 0x5e, 0x4b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 };
static const uint8_t DEST6[16]  = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 };

#define LISTEN_PORT 7

static tun_nat_config_t config_for(size_t limit) {
    tun_nat_config_t c;
    memset(&c, 0, sizeof c);
    memcpy(c.local4, LOCAL4, 4);
    memcpy(c.synthetic4, SYNTH4, 4);
    memcpy(c.local6, LOCAL6, 16);
    memcpy(c.synthetic6, SYNTH6, 16);
    c.have_ipv4 = 1;
    c.have_ipv6 = 1;
    c.listen_port = LISTEN_PORT;
    c.limit = limit;
    return c;
}

int main(void) {
    static tun_nat_t nat;
    tun_nat_config_t config = config_for(4);
    ok("init", tun_nat_init(&nat, &config) == TUN_NAT_OK);

    uint8_t p[256], held[256];
    size_t len, held_len, slot;
    tun_nat_drop_t why;

    /* a syn to an arbitrary address opens a pending flow with the original
       tuple and is held, not passed */
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_SYN, 1000, 0, 0);
    ok("syn opens a new flow",
       tun_nat_inbound(&nat, p, len, 10, &slot, &why) == TUN_NAT_NEW);
    const tun_nat_entry_t *e = tun_nat_entry(&nat, slot);
    ok("the entry keeps the app address as source",
       e && e->key.address_len == 4 && memcmp(e->key.source, APP4, 4) == 0);
    ok("the entry keeps the original destination",
       e && memcmp(e->key.destination, DEST4A, 4) == 0);
    ok("the entry keeps both original ports",
       e && e->key.source_port == 50001 && e->key.destination_port == 443);
    ok("the flow waits for a decision", e && e->state == TUN_NAT_PENDING);

    /* the app repeats its syn while the owner decides */
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_SYN, 1000, 0, 0);
    ok("a repeated syn is held again",
       tun_nat_inbound(&nat, p, len, 20, NULL, &why) == TUN_NAT_HELD);
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_ACK, 1001, 1, 0);
    ok("a segment before the decision is dropped",
       tun_nat_inbound(&nat, p, len, 20, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_PENDING);

    /* accepted: the held syn comes back addressed to the stack's listener,
       from the synthetic peer and this slot's port */
    size_t slot_a = slot;
    ok("accept", tun_nat_accept(&nat, slot_a, held, sizeof held, &held_len) == TUN_NAT_OK);
    ok("the syn is now from the synthetic peer", memcmp(held + 12, SYNTH4, 4) == 0);
    ok("the syn is now to the stack", memcmp(held + 16, LOCAL4, 4) == 0);
    ok("the source port is the slot's port",
       pkt_rd16(held + 20) == tun_nat_synthetic_port(slot_a));
    ok("the destination port is the listener", pkt_rd16(held + 22) == LISTEN_PORT);
    ok("the sequence number is untouched", pkt_rd32(held + 24) == 1000);
    ok("the translated syn has a valid ip header", pkt_ip4_valid(held));
    ok("the translated syn has a valid tcp checksum", pkt_l4_valid(held, held_len));

    /* the stack's syn-ack goes back to the app from the original destination */
    len = pkt_tcp4(p, LOCAL4, LISTEN_PORT, SYNTH4, tun_nat_synthetic_port(slot_a),
               PKT_SYN | PKT_ACK, 7000, 1001, 0);
    ok("the syn-ack is let out",
       tun_nat_outbound(&nat, p, len, 30, NULL, &why) == TUN_NAT_PASS);
    ok("the syn-ack comes from the original destination",
       memcmp(p + 12, DEST4A, 4) == 0 && pkt_rd16(p + 20) == 443);
    ok("the syn-ack goes to the app", memcmp(p + 16, APP4, 4) == 0 && pkt_rd16(p + 22) == 50001);
    ok("the syn-ack checksums are valid", pkt_ip4_valid(p) && pkt_l4_valid(p, len));

    /* and the app's ack reaches the stack's side of the same connection */
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_ACK, 1001, 7001, 5);
    ok("the ack goes in", tun_nat_inbound(&nat, p, len, 40, &slot, &why) == TUN_NAT_PASS);
    ok("the ack lands on the same flow", slot == slot_a);
    ok("the ack is translated with valid checksums",
       memcmp(p + 12, SYNTH4, 4) == 0 && pkt_l4_valid(p, len) && pkt_ip4_valid(p));

    /* two connections to different addresses on the same port, even from the
       same source port, stay two flows */
    len = pkt_tcp4(p, APP4, 50001, DEST4B, 443, PKT_SYN, 2000, 0, 0);
    ok("a second destination on the same port is a new flow",
       tun_nat_inbound(&nat, p, len, 50, &slot, &why) == TUN_NAT_NEW && slot != slot_a);
    size_t slot_b = slot;
    tun_nat_accept(&nat, slot_b, held, sizeof held, &held_len);
    ok("the flows get different synthetic ports",
       pkt_rd16(held + 20) != tun_nat_synthetic_port(slot_a));

    len = pkt_tcp4(p, LOCAL4, LISTEN_PORT, SYNTH4, tun_nat_synthetic_port(slot_b),
               PKT_SYN | PKT_ACK, 9000, 2001, 0);
    tun_nat_outbound(&nat, p, len, 60, NULL, &why);
    ok("the second flow answers from its own destination",
       memcmp(p + 12, DEST4B, 4) == 0);
    len = pkt_tcp4(p, LOCAL4, LISTEN_PORT, SYNTH4, tun_nat_synthetic_port(slot_a),
               PKT_ACK, 7001, 1006, 0);
    tun_nat_outbound(&nat, p, len, 60, NULL, &why);
    ok("the first flow still answers from its own destination",
       memcmp(p + 12, DEST4A, 4) == 0);

    /* a bad checksum on a syn never costs a table entry */
    len = pkt_tcp4(p, APP4, 50002, DEST4A, 80, PKT_SYN, 5, 0, 0);
    p[20 + 16] ^= 0x5a;
    ok("a syn with a bad checksum is dropped",
       tun_nat_inbound(&nat, p, len, 70, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_CHECKSUM);

    /* a mid stream segment with a bad checksum stays bad after translation,
       so the stack still refuses it */
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_ACK, 1006, 7001, 3);
    p[20 + 20] ^= 0xff; /* corrupt the payload, not the checksum */
    ok("a corrupted segment is still passed to the stack",
       tun_nat_inbound(&nat, p, len, 80, NULL, &why) == TUN_NAT_PASS);
    ok("its checksum is still wrong after translation", !pkt_l4_valid(p, len));

    /* a corrupted ipv4 header is never recomputed into a valid one */
    len = pkt_tcp4(p, APP4, 50001, DEST4A, 443, PKT_ACK, 1006, 7001, 0);
    p[8] = 1; /* ttl changed without fixing the header checksum */
    ok("a bad ip header checksum is dropped",
       tun_nat_inbound(&nat, p, len, 80, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_CHECKSUM);

    /* fragments */
    len = pkt_tcp4(p, APP4, 50003, DEST4A, 443, PKT_SYN, 1, 0, 0);
    pkt_wr16(p + 6, 0x2000);
    pkt_wr16(p + 10, 0);
    pkt_wr16(p + 10, pkt_finish(pkt_add(p, 20, 0)));
    ok("a first fragment is dropped",
       tun_nat_inbound(&nat, p, len, 90, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_FRAGMENT);
    pkt_wr16(p + 6, 0x0010);
    pkt_wr16(p + 10, 0);
    pkt_wr16(p + 10, pkt_finish(pkt_add(p, 20, 0)));
    ok("a later fragment is dropped",
       tun_nat_inbound(&nat, p, len, 90, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_FRAGMENT);
    len = pkt_tcp4(p, APP4, 50003, DEST4A, 443, PKT_SYN, 1, 0, 0);
    pkt_wr16(p + 6, 0x4000); /* don't fragment on its own is fine */
    pkt_wr16(p + 10, 0);
    pkt_wr16(p + 10, pkt_finish(pkt_add(p, 20, 0)));
    ok("don't fragment alone is not a fragment",
       tun_nat_inbound(&nat, p, len, 90, &slot, &why) == TUN_NAT_NEW);
    size_t slot_df = slot;

    /* the table has a hard limit; the fifth flow is refused and counted */
    len = pkt_tcp4(p, APP4, 50004, DEST4A, 443, PKT_SYN, 1, 0, 0);
    ok("the fourth flow fits", tun_nat_inbound(&nat, p, len, 100, &slot, &why) == TUN_NAT_NEW);
    size_t slot_four = slot;
    len = pkt_tcp4(p, APP4, 50005, DEST4A, 443, PKT_SYN, 1, 0, 0);
    ok("the fifth flow is refused",
       tun_nat_inbound(&nat, p, len, 100, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_TABLE_FULL);
    ok("the refusal is counted", nat.dropped[TUN_NAT_DROP_TABLE_FULL] == 1);

    /* a refused flow gets a reset from the original destination */
    size_t reset_len;
    ok("reject", tun_nat_reject(&nat, slot_four, p, sizeof p, &reset_len) == TUN_NAT_OK);
    ok("the reset comes from the destination the app asked for",
       memcmp(p + 12, DEST4A, 4) == 0 && pkt_rd16(p + 20) == 443 && pkt_rd16(p + 22) == 50004);
    ok("the reset acknowledges the syn", pkt_rd32(p + 28) == 2 && p[33] == (PKT_RST | PKT_ACK));
    ok("the reset has valid checksums", pkt_ip4_valid(p) && pkt_l4_valid(p, reset_len));
    ok("a rejected flow frees its slot", tun_nat_entry(&nat, slot_four)->state == TUN_NAT_FREE);

    /* a stale flow id never reaches the entry that reused its slot */
    uint64_t old_id = tun_nat_flow_id(&nat, slot_df);
    size_t found;
    ok("a live id resolves", tun_nat_slot_for_id(&nat, old_id, &found) && found == slot_df);
    size_t expired_slots[4];
    ok("a pending flow expires", tun_nat_expire_pending(&nat, 100000, 10000,
                                                         expired_slots, 4) == 1 &&
       expired_slots[0] == slot_df);
    ok("an expired id no longer resolves", !tun_nat_slot_for_id(&nat, old_id, NULL));
    len = pkt_tcp4(p, APP4, 50006, DEST4A, 443, PKT_SYN, 1, 0, 0);
    tun_nat_inbound(&nat, p, len, 100001, &slot, &why);
    ok("the old id does not resolve to the slot's new flow",
       !tun_nat_slot_for_id(&nat, old_id, NULL) &&
       tun_nat_flow_id(&nat, slot) != old_id);

    /* segments with no flow and addresses the tunnel keeps for itself */
    len = pkt_tcp4(p, APP4, 51000, DEST4A, 443, PKT_ACK, 5, 5, 0);
    ok("a segment for an unknown tuple is dropped",
       tun_nat_inbound(&nat, p, len, 1, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_NO_FLOW);
    len = pkt_tcp4(p, APP4, 51000, LOCAL4, LISTEN_PORT, PKT_SYN, 5, 0, 0);
    ok("an app may not reach the listener directly",
       tun_nat_inbound(&nat, p, len, 1, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_RESERVED);
    len = pkt_tcp4(p, APP4, 51000, SYNTH4, 443, PKT_SYN, 5, 0, 0);
    ok("the synthetic peer is not a destination",
       tun_nat_inbound(&nat, p, len, 1, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_RESERVED);
    len = pkt_tcp4(p, APP4, 51000, DEST4A, 443, PKT_SYN, 5, 0, 0);
    p[9] = 17;
    pkt_wr16(p + 10, 0);
    pkt_wr16(p + 10, pkt_finish(pkt_add(p, 20, 0)));
    ok("udp is not captured yet and says so",
       tun_nat_inbound(&nat, p, len, 1, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_PROTOCOL);

    /* malformed */
    len = pkt_tcp4(p, APP4, 51001, DEST4A, 443, PKT_SYN, 5, 0, 0);
    ok("a packet shorter than its ip length is dropped",
       tun_nat_inbound(&nat, p, len - 4, 1, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_MALFORMED);
    len = pkt_tcp4(p, APP4, 51001, DEST4A, 443, PKT_SYN, 5, 0, 0);
    p[20 + 12] = 0xf0; /* data offset of 60 in a 20 byte segment */
    ok("a tcp header longer than the segment is dropped",
       tun_nat_inbound(&nat, p, len, 1, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_MALFORMED);

    /* the stack sending to a synthetic port nobody owns */
    len = pkt_tcp4(p, LOCAL4, LISTEN_PORT, SYNTH4, TUN_NAT_PORT_BASE + 3, PKT_ACK, 1, 1, 0);
    ok("an answer for an unknown slot is dropped",
       tun_nat_outbound(&nat, p, len, 1, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_NO_FLOW);

    /* draining: a reconnect from the same tuple gets a fresh entry, and its
       segments reach the fresh one, not the draining one */
    static tun_nat_t drain;
    config = config_for(4);
    tun_nat_init(&drain, &config);
    len = pkt_tcp4(p, APP4, 52000, DEST4A, 443, PKT_SYN, 1, 0, 0);
    tun_nat_inbound(&drain, p, len, 1, &slot, &why);
    size_t old_slot = slot;
    tun_nat_accept(&drain, old_slot, held, sizeof held, &held_len);
    tun_nat_close(&drain, old_slot);
    ok("a closed flow drains", tun_nat_entry(&drain, old_slot)->state == TUN_NAT_DRAINING);
    len = pkt_tcp4(p, APP4, 52000, DEST4A, 443, PKT_SYN, 900, 0, 0);
    ok("a reconnect from the same tuple is a new flow",
       tun_nat_inbound(&drain, p, len, 2, &slot, &why) == TUN_NAT_NEW && slot != old_slot);
    size_t new_slot = slot;
    tun_nat_accept(&drain, new_slot, held, sizeof held, &held_len);
    len = pkt_tcp4(p, APP4, 52000, DEST4A, 443, PKT_ACK, 901, 1, 0);
    tun_nat_inbound(&drain, p, len, 3, &slot, &why);
    ok("its segments reach the new flow, not the draining one", slot == new_slot);
    tun_nat_release(&drain, old_slot);
    ok("a released slot is free", tun_nat_entry(&drain, old_slot)->state == TUN_NAT_FREE);

    /* tcp fast open data on the syn is not held: only the headers are */
    static tun_nat_t tfo;
    config = config_for(4);
    tun_nat_init(&tfo, &config);
    len = pkt_tcp4(p, APP4, 53000, DEST4A, 443, PKT_SYN, 100, 0, 150);
    ok("a syn carrying data opens a flow",
       tun_nat_inbound(&tfo, p, len, 1, &slot, &why) == TUN_NAT_NEW);
    ok("accept", tun_nat_accept(&tfo, slot, held, sizeof held, &held_len) == TUN_NAT_OK);
    ok("only the headers of the syn were kept", held_len == 40 && pkt_rd16(held + 2) == 40);
    ok("the trimmed syn is valid", pkt_ip4_valid(held) && pkt_l4_valid(held, held_len));

    /* ipv6: the same capture, with and without destination options */
    static tun_nat_t six;
    config = config_for(4);
    tun_nat_init(&six, &config);
    len = pkt_tcp6(p, APP6, 60000, DEST6, 443, PKT_SYN, 77, 0, 0, 0, 0);
    ok("a v6 syn opens a flow", tun_nat_inbound(&six, p, len, 1, &slot, &why) == TUN_NAT_NEW);
    e = tun_nat_entry(&six, slot);
    ok("the v6 entry keeps the original tuple",
       e->key.address_len == 16 && memcmp(e->key.destination, DEST6, 16) == 0 &&
       memcmp(e->key.source, APP6, 16) == 0 && e->key.destination_port == 443);
    size_t six_slot = slot;
    tun_nat_accept(&six, six_slot, held, sizeof held, &held_len);
    ok("the v6 syn is addressed to the stack",
       memcmp(held + 8, SYNTH6, 16) == 0 && memcmp(held + 24, LOCAL6, 16) == 0);
    ok("the v6 syn checksum is valid", pkt_l4_valid(held, held_len));

    len = pkt_tcp6(p, LOCAL6, LISTEN_PORT, SYNTH6, tun_nat_synthetic_port(six_slot),
               PKT_SYN | PKT_ACK, 5, 78, 0, 0, 0);
    ok("the v6 syn-ack is let out", tun_nat_outbound(&six, p, len, 2, NULL, &why) == TUN_NAT_PASS);
    ok("the v6 syn-ack comes from the original destination",
       memcmp(p + 8, DEST6, 16) == 0 && pkt_rd16(p + 40) == 443 && memcmp(p + 24, APP6, 16) == 0);
    ok("the v6 syn-ack checksum is valid", pkt_l4_valid(p, len));

    len = pkt_tcp6(p, APP6, 60001, DEST6, 443, PKT_SYN, 1, 0, 0, 2, 60);
    ok("a v6 syn behind destination options is captured",
       tun_nat_inbound(&six, p, len, 3, &slot, &why) == TUN_NAT_NEW &&
       tun_nat_entry(&six, slot)->key.source_port == 60001);
    tun_nat_accept(&six, slot, held, sizeof held, &held_len);
    ok("its translation keeps a valid checksum", pkt_l4_valid(held, held_len));

    len = pkt_tcp6(p, APP6, 60002, DEST6, 443, PKT_SYN, 1, 0, 0, 1, 43);
    ok("a v6 routing header is refused, it changes the real destination",
       tun_nat_inbound(&six, p, len, 3, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_EXTENSION);
    len = pkt_tcp6(p, APP6, 60002, DEST6, 443, PKT_SYN, 1, 0, 0, 1, 44);
    ok("a v6 fragment header is refused as a fragment",
       tun_nat_inbound(&six, p, len, 3, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_FRAGMENT);
    len = pkt_tcp6(p, APP6, 60002, DEST6, 443, PKT_SYN, 1, 0, 0, 9, 60);
    ok("an overlong v6 header chain is refused",
       tun_nat_inbound(&six, p, len, 3, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_EXTENSION);
    len = pkt_tcp6(p, APP6, 60002, DEST6, 443, PKT_SYN, 1, 0, 0, 0, 0);
    pkt_wr16(p + 4, (uint16_t)(len - 40 + 8));
    ok("a v6 payload length that lies is refused",
       tun_nat_inbound(&six, p, len, 3, NULL, &why) == TUN_NAT_DROP &&
       why == TUN_NAT_DROP_MALFORMED);

    static const uint8_t datagram[] = { 'd', 'n', 's' };
    tun_flow_key_t udp_key;
    const uint8_t *udp_payload = NULL;
    size_t udp_payload_len = 0;
    len = pkt_udp4(p, APP4, 53000, DEST4A, 53, datagram, sizeof datagram);
    ok("ipv4 udp keeps its original tuple and datagram",
       tun_nat_udp_inbound(&nat, p, len, &udp_key, &udp_payload,
                           &udp_payload_len, &why) == TUN_NAT_UDP_PACKET &&
       udp_key.protocol == TUN_FLOW_UDP && udp_key.source_port == 53000 &&
       udp_key.destination_port == 53 && udp_payload_len == sizeof datagram &&
       memcmp(udp_payload, datagram, sizeof datagram) == 0);
    ok("ipv4 udp reply uses original addresses and checksum",
       tun_nat_udp_reply(&udp_key, datagram, sizeof datagram, held,
                         sizeof held, &held_len) == TUN_NAT_OK &&
       memcmp(pkt_src(held), DEST4A, 4) == 0 &&
       memcmp(pkt_dst(held), APP4, 4) == 0 &&
       pkt_rd16(held + 20) == 53 && pkt_rd16(held + 22) == 53000 &&
       pkt_ip4_valid(held) && pkt_l4_valid(held, held_len));
    ok("short udp reply buffer is refused",
       tun_nat_udp_reply(&udp_key, datagram, sizeof datagram, held,
                         8, &held_len) == TUN_NAT_ERR_SPACE && held_len == 0);

    len = pkt_udp4(p, APP4, 53000, DEST4A, 53, datagram, sizeof datagram);
    pkt_wr16(p + 20 + 4, 9);
    ok("udp length mismatch is refused",
       tun_nat_udp_inbound(&nat, p, len, &udp_key, &udp_payload,
                           &udp_payload_len, &why) == TUN_NAT_UDP_DROP &&
       why == TUN_NAT_DROP_MALFORMED);
    len = pkt_udp4(p, APP4, 53000, DEST4A, 53, datagram, sizeof datagram);
    p[20 + 8] ^= 1;
    ok("corrupt udp payload is refused",
       tun_nat_udp_inbound(&nat, p, len, &udp_key, &udp_payload,
                           &udp_payload_len, &why) == TUN_NAT_UDP_DROP &&
       why == TUN_NAT_DROP_CHECKSUM);
    len = pkt_udp4(p, APP4, 53000, DEST4A, 53, datagram, sizeof datagram);
    pkt_wr16(p + 20 + 6, 0);
    ok("ipv4 udp zero checksum is accepted",
       tun_nat_udp_inbound(&nat, p, len, &udp_key, &udp_payload,
                           &udp_payload_len, &why) == TUN_NAT_UDP_PACKET);

    len = pkt_udp6(p, APP6, 53000, DEST6, 53, datagram, sizeof datagram);
    ok("ipv6 udp keeps its original tuple",
       tun_nat_udp_inbound(&six, p, len, &udp_key, &udp_payload,
                           &udp_payload_len, &why) == TUN_NAT_UDP_PACKET &&
       udp_key.address_len == 16 && memcmp(udp_key.destination, DEST6, 16) == 0);
    ok("ipv6 udp reply has a valid checksum",
       tun_nat_udp_reply(&udp_key, datagram, sizeof datagram, held,
                         sizeof held, &held_len) == TUN_NAT_OK &&
       memcmp(pkt_src(held), DEST6, 16) == 0 &&
       memcmp(pkt_dst(held), APP6, 16) == 0 && pkt_l4_valid(held, held_len));
    len = pkt_udp6(p, APP6, 53000, DEST6, 53, datagram, sizeof datagram);
    pkt_wr16(p + 40 + 6, 0);
    ok("ipv6 udp zero checksum is refused",
       tun_nat_udp_inbound(&six, p, len, &udp_key, &udp_payload,
                           &udp_payload_len, &why) == TUN_NAT_UDP_DROP &&
       why == TUN_NAT_DROP_CHECKSUM);

    /* a refused datagram gets icmp port unreachable from its destination */
    len = pkt_udp4(p, APP4, 41001, DEST4A, 443, datagram, sizeof datagram);
    ok("ipv4 quic tuple captured",
       tun_nat_udp_inbound(&nat, p, len, &udp_key, &udp_payload,
                           &udp_payload_len, &why) == TUN_NAT_UDP_PACKET);
    ok("ipv4 refusal is icmp port unreachable quoting the datagram",
       tun_nat_udp_unreachable(&udp_key, sizeof datagram, held, sizeof held,
                               &held_len) == TUN_NAT_OK &&
       held_len == 56 && held[9] == 1 && held[20] == 3 && held[21] == 3 &&
       memcmp(pkt_src(held), DEST4A, 4) == 0 && memcmp(pkt_dst(held), APP4, 4) == 0 &&
       pkt_ip4_valid(held) && pkt_l4_valid(held, held_len) &&
       pkt_ip4_valid(held + 28) && held[28 + 9] == 17 &&
       memcmp(held + 28 + 12, APP4, 4) == 0 && memcmp(held + 28 + 16, DEST4A, 4) == 0 &&
       pkt_rd16(held + 28 + 2) == 28 + sizeof datagram &&
       pkt_rd16(held + 48) == 41001 && pkt_rd16(held + 50) == 443 &&
       pkt_rd16(held + 52) == 8 + sizeof datagram);
    ok("short icmp refusal buffer is refused",
       tun_nat_udp_unreachable(&udp_key, sizeof datagram, held, 55,
                               &held_len) == TUN_NAT_ERR_SPACE && held_len == 0);
    len = pkt_udp6(p, APP6, 41001, DEST6, 443, datagram, sizeof datagram);
    ok("ipv6 quic tuple captured",
       tun_nat_udp_inbound(&six, p, len, &udp_key, &udp_payload,
                           &udp_payload_len, &why) == TUN_NAT_UDP_PACKET);
    ok("ipv6 refusal is icmpv6 port unreachable with a valid checksum",
       tun_nat_udp_unreachable(&udp_key, sizeof datagram, held, sizeof held,
                               &held_len) == TUN_NAT_OK &&
       held_len == 96 && held[6] == 58 && held[40] == 1 && held[41] == 4 &&
       memcmp(pkt_src(held), DEST6, 16) == 0 && memcmp(pkt_dst(held), APP6, 16) == 0 &&
       pkt_l4_valid(held, held_len) &&
       memcmp(held + 48 + 8, APP6, 16) == 0 && memcmp(held + 48 + 24, DEST6, 16) == 0 &&
       held[48 + 6] == 17 && pkt_rd16(held + 48 + 4) == 8 + sizeof datagram &&
       pkt_rd16(held + 88) == 41001 && pkt_rd16(held + 90) == 443);
    udp_key.protocol = TUN_FLOW_TCP;
    ok("icmp refusal of a tcp tuple is refused",
       tun_nat_udp_unreachable(&udp_key, 0, held, sizeof held, &held_len) == TUN_NAT_ERR_ARG);

    /* configuration that would make the translation ambiguous is refused */
    static tun_nat_t bad;
    tun_nat_config_t wrong = config_for(4);
    wrong.listen_port = (uint16_t)TUN_NAT_PORT_BASE;
    ok("a listener inside the synthetic port range is refused",
       tun_nat_init(&bad, &wrong) == TUN_NAT_ERR_ARG);
    wrong = config_for(4);
    memcpy(wrong.synthetic4, LOCAL4, 4);
    ok("a synthetic peer equal to the stack address is refused",
       tun_nat_init(&bad, &wrong) == TUN_NAT_ERR_ARG);
    wrong = config_for(TUN_NAT_TCP_MAX + 1);
    ok("a limit above the compile cap is refused", tun_nat_init(&bad, &wrong) == TUN_NAT_ERR_ARG);

    ok("every drop reason has words",
       strlen(tun_nat_drop_text(TUN_NAT_DROP_FRAGMENT)) > 10 &&
       strlen(tun_nat_drop_text(TUN_NAT_DROP_TABLE_FULL)) > 10);

    /* the tunnel loop sleeps until the oldest held syn expires, not on a beat */
    static tun_nat_t held_nat;
    tun_nat_config_t held_config = config_for(4);
    ok("held init", tun_nat_init(&held_nat, &held_config) == TUN_NAT_OK);
    ok("nothing held waits forever",
       tun_nat_pending_wait_ms(&held_nat, 1000, 10000) == UINT64_MAX);
    len = pkt_tcp4(p, APP4, 52001, DEST4A, 443, PKT_SYN, 1, 0, 0);
    ok("held syn", tun_nat_inbound(&held_nat, p, len, 1000, NULL, &why) == TUN_NAT_NEW);
    len = pkt_tcp4(p, APP4, 52002, DEST4A, 443, PKT_SYN, 1, 0, 0);
    ok("later held syn", tun_nat_inbound(&held_nat, p, len, 4000, NULL, &why) == TUN_NAT_NEW);
    ok("a fresh hold waits its whole budget",
       tun_nat_pending_wait_ms(&held_nat, 1000, 10000) == 10000);
    ok("the oldest hold sets the wait",
       tun_nat_pending_wait_ms(&held_nat, 7000, 10000) == 4000);
    ok("an overdue hold wants service now",
       tun_nat_pending_wait_ms(&held_nat, 12000, 10000) == 0);
    ok("a clock that went backwards waits the whole budget",
       tun_nat_pending_wait_ms(&held_nat, 500, 10000) == 10000);
    ok("the overdue hold expires",
       tun_nat_expire_pending(&held_nat, 12000, 10000, NULL, 0) == 1);
    ok("the next hold sets the wait after it",
       tun_nat_pending_wait_ms(&held_nat, 12000, 10000) == 2000);

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("all tun_nat checks passed");
    return 0;
}
