#include "bye_hosts.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *name; /* inside the arena, which is never moved */
    uint16_t    len;
} entry_t;

struct bye_hosts {
    char    *arena;
    entry_t *entries;
    size_t   count;
};

static void fail(char *error, size_t cap, size_t line, const char *why) {
    if (error && cap) snprintf(error, cap, "line %zu: %s", line, why);
}

static char lower(char c) {
    return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c;
}

/* labels of letters, digits, dashes and underscores, none starting or ending
   with a dash. a name with no dot is allowed: an intranet name is a domain too */
int bye_hosts_name_ok(const char *name, size_t len) {
    size_t label = 0;
    if (len == 0 || len > BYE_HOSTS_NAME_MAX) return 0;
    for (size_t i = 0; i < len; ++i) {
        char c = name[i];
        if (c == '.') {
            if (label == 0 || label > 63 || name[i - 1] == '-') return 0;
            label = 0;
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
            ++label;
        } else if (c == '-' && label > 0) {
            ++label;
        } else {
            return 0;
        }
    }
    return label > 0 && label <= 63 && name[len - 1] != '-';
}

static int compare(const void *a, const void *b) {
    const entry_t *x = a, *y = b;
    size_t common = x->len < y->len ? x->len : y->len;
    int order = memcmp(x->name, y->name, common);
    if (order) return order;
    return (int)x->len - (int)y->len;
}

bye_hosts_t *bye_hosts_parse(const char *text, size_t len, char *error, size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!text && len) {
        fail(error, error_cap, 0, "no text");
        return NULL;
    }
    if (len > BYE_HOSTS_FILE_MAX) {
        fail(error, error_cap, 0, "the list is too large");
        return NULL;
    }
    bye_hosts_t *hosts = calloc(1, sizeof *hosts);
    if (!hosts) {
        fail(error, error_cap, 0, "not enough memory");
        return NULL;
    }
    /* the names cannot take more room than the text they came from */
    hosts->arena = malloc(len + 1);
    size_t max_entries = len / 2 + 1;
    if (max_entries > BYE_HOSTS_NAMES_MAX) max_entries = BYE_HOSTS_NAMES_MAX;
    hosts->entries = malloc(max_entries * sizeof *hosts->entries);
    if (!hosts->arena || !hosts->entries) {
        fail(error, error_cap, 0, "not enough memory");
        bye_hosts_free(hosts);
        return NULL;
    }

    size_t used = 0, line_no = 0, pos = 0;
    while (pos < len) {
        const char *line = text + pos;
        const char *nl = memchr(line, '\n', len - pos);
        size_t line_len = nl ? (size_t)(nl - line) : len - pos;
        pos += nl ? line_len + 1 : line_len;
        ++line_no;

        const char *hash = memchr(line, '#', line_len);
        if (hash) line_len = (size_t)(hash - line);
        while (line_len && (line[line_len - 1] == '\r' || line[line_len - 1] == ' ' ||
                            line[line_len - 1] == '\t')) --line_len;
        while (line_len && (*line == ' ' || *line == '\t')) {
            ++line;
            --line_len;
        }
        if (line_len == 0) continue;
        if (line_len >= 2 && line[0] == '*' && line[1] == '.') {
            line += 2;
            line_len -= 2;
        } else if (line[0] == '.') {
            ++line;
            --line_len;
        }
        while (line_len && line[line_len - 1] == '.') --line_len;

        char name[BYE_HOSTS_NAME_MAX + 1];
        if (line_len > BYE_HOSTS_NAME_MAX) {
            fail(error, error_cap, line_no, "not a domain name");
            bye_hosts_free(hosts);
            return NULL;
        }
        for (size_t i = 0; i < line_len; ++i) name[i] = lower(line[i]);
        if (!bye_hosts_name_ok(name, line_len)) {
            fail(error, error_cap, line_no, "not a domain name");
            bye_hosts_free(hosts);
            return NULL;
        }
        if (hosts->count == BYE_HOSTS_NAMES_MAX) {
            fail(error, error_cap, line_no, "too many names");
            bye_hosts_free(hosts);
            return NULL;
        }
        memcpy(hosts->arena + used, name, line_len);
        hosts->entries[hosts->count].name = hosts->arena + used;
        hosts->entries[hosts->count].len = (uint16_t)line_len;
        used += line_len;
        ++hosts->count;
    }
    qsort(hosts->entries, hosts->count, sizeof *hosts->entries, compare);
    return hosts;
}

void bye_hosts_free(bye_hosts_t *hosts) {
    if (!hosts) return;
    free(hosts->arena);
    free(hosts->entries);
    free(hosts);
}

size_t bye_hosts_count(const bye_hosts_t *hosts) {
    return hosts ? hosts->count : 0;
}

static int has_exact(const bye_hosts_t *hosts, const char *name, size_t len) {
    size_t low = 0, high = hosts->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        const entry_t *e = &hosts->entries[mid];
        size_t common = e->len < len ? e->len : len;
        int order = memcmp(e->name, name, common);
        if (order == 0) order = (int)e->len - (int)len;
        if (order == 0) return 1;
        if (order < 0) low = mid + 1;
        else high = mid;
    }
    return 0;
}

int bye_hosts_match(const bye_hosts_t *hosts, const char *name, size_t len) {
    if (!hosts || !name) return 0;
    while (len && name[len - 1] == '.') --len;
    if (len == 0 || len > BYE_HOSTS_NAME_MAX) return 0;
    char low[BYE_HOSTS_NAME_MAX];
    for (size_t i = 0; i < len; ++i) low[i] = lower(name[i]);
    for (size_t at = 0; at < len; ++at) {
        if (at == 0 || low[at - 1] == '.')
            if (has_exact(hosts, low + at, len - at)) return 1;
    }
    return 0;
}
