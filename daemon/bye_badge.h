#ifndef BYE_BADGE_H
#define BYE_BADGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* tells the springboard hook whether the tunnel runs, and which interface it
   leaves by. the hook shows the vpn badge and keeps the wifi glyph. a host
   build writes nothing */
void bye_badge_on(const char *physical_ifname);
void bye_badge_off(void);

#ifdef __cplusplus
}
#endif

#endif
