#ifndef SENKO_LWIPOPTS_H
#define SENKO_LWIPOPTS_H

/* senko's lwip configuration. it lives outside daemon/third_party/lwip so the
   vendored tree stays an unmodified copy of STABLE-2_2_1_RELEASE.

   the shape of this port: no operating system, one thread owning the whole
   stack, and packets handed in and out by the utun device. nothing here may
   allocate from libc at runtime, because an ios 5 device has to survive a
   long session inside a fixed budget */

/* no os: no threads, no semaphores, no mailboxes inside lwip. the packet loop
   calls into the stack and sys_check_timeouts() itself */
#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0

/* raw callback api only. the sequential apis exist to be called from other
   threads, which this port does not have */
#define LWIP_NETCONN                    0
#define LWIP_SOCKET                     0
#define LWIP_NETIF_API                  0

/* every allocation comes from lwip's own static pools, so the footprint is
   known at build time and a busy moment cannot grow the heap */
#define MEM_LIBC_MALLOC                 0
#define MEMP_MEM_MALLOC                 0
#define MEM_USE_POOLS                   0

/* pools hold structs with pointers in them, so the alignment has to match the
   slice: four bytes on armv7, eight on arm64. getting this wrong gives
   misaligned pbufs, which is undefined behaviour even where the cpu tolerates
   the access */
#if defined(__LP64__) || defined(_LP64) || defined(__aarch64__) || defined(__x86_64__)
#define MEM_ALIGNMENT                   8
/* ipv6 reassembly keeps a pointer inside each fragment header. eight bytes
   hold it on armv7 but not on arm64, where lwip asserts in its reassembly
   timer about a second after start unless the header is copied aside */
#define IPV6_FRAG_COPYHEADER            1
#else
#define MEM_ALIGNMENT                   4
#endif

/* protocols the tunnel carries */
#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define LWIP_TCP                        1
#define LWIP_UDP                        1
#define LWIP_RAW                        1
#define LWIP_ICMP                       1
#define LWIP_ICMP6                      1

/* checksums stay on: packets arriving from the device are not trusted, and
   the ones leaving have to be correct for the physical path */
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                1
#define CHECKSUM_GEN_ICMP               1
#define CHECKSUM_GEN_ICMP6              1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1
#define CHECKSUM_CHECK_TCP              1
#define CHECKSUM_CHECK_ICMP             1
#define CHECKSUM_CHECK_ICMP6            1

/* the tunnel interface is point to point and carries bare ip, so there is no
   link layer to resolve, no addresses to discover and no lease to renew */
#define LWIP_ARP                        0
#define LWIP_ETHERNET                   0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_IPV6_DHCP6                 0
#define LWIP_IPV6_AUTOCONFIG            0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT   0
#define LWIP_IPV6_MLD                   0
#define LWIP_IGMP                       0
#define PPP_SUPPORT                     0
#define LWIP_SNMP                       0
#define LWIP_ALTCP                      0

/* senko resolves names itself, through the selected server or through the
   physical interface, with its own policy and cache. lwip's resolver would be
   a second one with neither */
#define LWIP_DNS                        0

/* senko never listens on the stack: flows arrive as packets, not as accepts
   on a bound port */
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_NETIF_LINK_CALLBACK        0
#define LWIP_NETIF_HOSTNAME             0
#define LWIP_SO_RCVBUF                  0

/* tcp shape. the window is what one flow may hold in flight, and it is paid
   for out of the pbuf pool below */
#define TCP_MSS                         1360
/* four segments make bulk downloads wait for an app ack after about 5 kb
   the larger send ceiling still shares the same fixed heap and segment pools */
#define TCP_SND_BUF                     (16 * TCP_MSS)
#define TCP_WND                         (4 * TCP_MSS)
#define TCP_SND_QUEUELEN                ((4 * TCP_SND_BUF) / TCP_MSS)
#define TCP_QUEUE_OOSEQ                 1

/* every connection inside the stack runs between an app and lwip over the
   utun device, which is memory in the same machine, not a network that can
   delay a duplicate for a minute. two seconds of msl leaves time-wait at four,
   long enough to answer a repeated fin, and it frees the capture slot, which
   stays taken until lwip lets go of the connection, in four seconds instead
   of two minutes */
#define TCP_MSL                         2000UL
#define LWIP_TCP_SACK_OUT               1
#define LWIP_WND_SCALE                  1
#define TCP_RCV_SCALE                   1

/* two memory profiles. the small one is what an armv7 device gets, and the
   flow ceilings match the ones the flow table enforces in core/tun_flow.h,
   so neither side can admit a flow the other has no room for */
#if defined(SENKO_LWIP_PROFILE_LARGE)
#define MEMP_NUM_TCP_PCB                64
#define MEMP_NUM_UDP_PCB                128
#define MEM_SIZE                        (512 * 1024)
#define PBUF_POOL_SIZE                  96
#define MEMP_NUM_TCP_SEG                192
#define MEMP_NUM_REASSDATA              16
#else
#define MEMP_NUM_TCP_PCB                32
#define MEMP_NUM_UDP_PCB                64
#define MEM_SIZE                        (192 * 1024)
#define PBUF_POOL_SIZE                  48
#define MEMP_NUM_TCP_SEG                96
#define MEMP_NUM_REASSDATA              8
#endif

#define MEMP_NUM_TCP_PCB_LISTEN         2
#define MEMP_NUM_RAW_PCB                2
#define MEMP_NUM_NETBUF                 0
#define MEMP_NUM_NETCONN                0
#define MEMP_NUM_SYS_TIMEOUT            8
#define PBUF_POOL_BUFSIZE               1536
#define IP_REASS_MAX_PBUFS              (PBUF_POOL_SIZE / 4)
#define LWIP_NETIF_TX_SINGLE_PBUF       1

/* one interface: the tunnel */
#define LWIP_SINGLE_NETIF               1
#define LWIP_HAVE_LOOPIF                0
#define LWIP_NETIF_LOOPBACK             0

/* counters are cheap and are what diagnostics reports; the printing helpers
   and the assert-heavy debug output are not compiled in */
#define LWIP_STATS                      1
#define LWIP_STATS_DISPLAY              0
#define LWIP_DEBUG                      0

#endif
