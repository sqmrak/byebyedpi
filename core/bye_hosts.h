#ifndef BYE_HOSTS_H
#define BYE_HOSTS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* a list of domain names: one per line, "#" starts a comment, an optional
   leading "*." or "." is ignored. a name matches itself and every name under
   it, so "example.org" covers "cdn.example.org". a line that is not a plain
   domain name rejects the whole file, so a bad list is never half applied */

#define BYE_HOSTS_FILE_MAX (1024u * 1024u)
#define BYE_HOSTS_NAMES_MAX 16384u
#define BYE_HOSTS_NAME_MAX 253u
#define BYE_HOSTS_ERROR_MAX 96

typedef struct bye_hosts bye_hosts_t;

/* 1 when text is one plain domain name, as a line of a list may be written */
int bye_hosts_name_ok(const char *text, size_t len);

/* NULL with the reason in error */
bye_hosts_t *bye_hosts_parse(const char *text, size_t len, char *error, size_t error_cap);
void bye_hosts_free(bye_hosts_t *hosts);
size_t bye_hosts_count(const bye_hosts_t *hosts);

/* 1 when name, or a parent of it, is in the list. case does not matter and a
   trailing dot is ignored. a name that is empty or too long never matches */
int bye_hosts_match(const bye_hosts_t *hosts, const char *name, size_t len);

#ifdef __cplusplus
}
#endif

#endif
