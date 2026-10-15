#include "bye_config.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* recognize the old default list so existing files can adopt the current default */
static const char OLD_DEFAULT_LIST[] =
    "tlsrec=name+1;split=1,name+1|tlsrec=mid;split=1,mid|split=1,name+1;oob=1|none";

void bye_config_defaults(bye_config_t *config) {
    if (!config) return;
    memset(config, 0, sizeof *config);
    config->telegram = 1;
    config->block_quic = 1;
    config->hosts_only = 1;
    config->pool = 1;
    config->version = BYE_CONFIG_VERSION;
    snprintf(config->relay, sizeof config->relay, "%s", BYE_CONFIG_RELAY_DEFAULT);
    config->proxy_port = BYE_CONFIG_PROXY_PORT_DEFAULT;
    snprintf(config->desync_spec, sizeof config->desync_spec, "%s", BYE_STRATEGIES_DEFAULT);
    (void)bye_strategies_parse(config->desync_spec, &config->desync_strategies, NULL, 0);
}

int bye_config_migrate(bye_config_t *config) {
    if (!config || config->version >= BYE_CONFIG_VERSION) return 0;
    /* every older build saved its own defaults and choices, and a youtube list picked
       there stopped the videos on a newer build, so one reset replaces them all */
    bye_config_defaults(config);
    return 1;
}

static void fail(char *error, size_t cap, size_t line, const char *why) {
    if (error && cap) snprintf(error, cap, "line %zu: %s", line, why);
}

static int parse_bool(const char *value, const char *yes, const char *no, int *out) {
    if (strcmp(value, yes) == 0) {
        *out = 1;
        return 0;
    }
    if (strcmp(value, no) == 0) {
        *out = 0;
        return 0;
    }
    return -1;
}

static int copy_text(char *dst, size_t cap, const char *src) {
    size_t len = strlen(src);
    if (len >= cap) return -1;
    memcpy(dst, src, len + 1);
    return 0;
}

/* relay names enter tls and http requests, so accept only domain characters */
static int relay_domain_ok(const char *name) {
    size_t len = strlen(name);
    int dots = 0, label = 0;
    if (len < 3 || len >= BYE_CONFIG_RELAY_NAME_MAX) return 0;
    for (size_t i = 0; i < len; ++i) {
        char ch = name[i];
        if (ch == '.') {
            if (!label) return 0;
            label = 0;
            ++dots;
        } else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                   (ch == '-' && label)) {
            ++label;
        } else {
            return 0;
        }
    }
    return dots >= 1 && label > 0 && name[len - 1] != '-';
}

/* restrict names to the hosts directory so the app cannot make the root daemon read other files */
static int hosts_name_ok(const char *name) {
    size_t len = strlen(name);
    if (len == 0 || len >= BYE_CONFIG_HOSTS_NAME_MAX || name[0] == '.') return 0;
    for (size_t i = 0; i < len; ++i) {
        char ch = name[i];
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
              ch == '.' || ch == '_' || ch == '-')) return 0;
    }
    return 1;
}

static int apply(bye_config_t *config, const char *key, const char *value, char *why,
                 size_t why_cap) {
    /* older files keep the desync key; rejecting it would discard their other settings */
    if (strcmp(key, "desync") == 0) {
        int ignored = 0;
        if (parse_bool(value, "on", "off", &ignored) != 0) {
            snprintf(why, why_cap, "desync is on or off");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "telegram") == 0 || strcmp(key, "autostart") == 0 || strcmp(key, "proxy") == 0) {
        int *target = key[0] == 't' ? &config->telegram
                    : key[0] == 'p' ? &config->proxy : &config->autostart;
        if (parse_bool(value, "on", "off", target) != 0) {
            snprintf(why, why_cap, "%s is on or off", key);
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "quic") == 0) {
        int block = 0;
        if (parse_bool(value, "block", "pass", &block) != 0) {
            snprintf(why, why_cap, "quic is block or pass");
            return -1;
        }
        config->block_quic = block;
        return 0;
    }
    if (strcmp(key, "desync.spec") == 0) {
        char detail[120];
        char single[BYE_CONFIG_SPEC_MAX];
        bye_strategies_t list;
        if (strlen(value) >= sizeof config->desync_spec) {
            snprintf(why, why_cap, "desync.spec is too long");
            return -1;
        }
        const char *bar = strchr(value, '|');
        if (bar) {
            const char *first = strcmp(value, OLD_DEFAULT_LIST) == 0 ? BYE_STRATEGIES_DEFAULT : value;
            size_t n = first == value ? (size_t)(bar - value) : strlen(first);
            while (n && first[n - 1] == ' ') --n;
            while (n && *first == ' ') {
                ++first;
                --n;
            }
            memcpy(single, first, n);
            single[n] = '\0';
            value = single;
            config->spec_reduced = 1;
        }
        if (bye_strategies_parse(value, &list, detail, sizeof detail) != BYE_DESYNC_OK) {
            snprintf(why, why_cap, "desync.spec: %s", detail);
            return -1;
        }
        memcpy(config->desync_spec, value, strlen(value) + 1);
        config->desync_strategies = list;
        return 0;
    }
    if (strcmp(key, "proxy.port") == 0) {
        char *end = NULL;
        long port = strtol(value, &end, 10);
        if (!*value || *end || port < 1 || port > 65535) {
            snprintf(why, why_cap, "proxy.port is 1 to 65535");
            return -1;
        }
        config->proxy_port = (int)port;
        return 0;
    }
    if (strcmp(key, "proxy.secret") == 0) {
        if (strcmp(value, "auto") == 0) {
            config->proxy_secret[0] = '\0';
            return 0;
        }
        if (strlen(value) != BYE_CONFIG_SECRET_LEN) goto bad_secret;
        for (size_t i = 0; i < BYE_CONFIG_SECRET_LEN; ++i) {
            char ch = value[i];
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) goto bad_secret;
        }
        memcpy(config->proxy_secret, value, BYE_CONFIG_SECRET_LEN + 1);
        return 0;
    bad_secret:
        snprintf(why, why_cap, "proxy.secret is 32 lowercase hex digits or auto");
        return -1;
    }
    if (strcmp(key, "hosts") == 0) {
        if (strcmp(value, "none") == 0) {
            config->hosts[0] = '\0';
            return 0;
        }
        if (!hosts_name_ok(value)) {
            snprintf(why, why_cap, "hosts is a file name or none");
            return -1;
        }
        return copy_text(config->hosts, sizeof config->hosts, value);
    }
    if (strcmp(key, "hosts.mode") == 0) {
        if (parse_bool(value, "only", "except", &config->hosts_only) != 0) {
            snprintf(why, why_cap, "hosts.mode is only or except");
            return -1;
        }
        return 0;
    }
    if (strcmp(key, "telegram.pool") == 0) {
        if (strlen(value) != 1 || value[0] < '0' || value[0] > '0' + BYE_CONFIG_POOL_MAX) {
            snprintf(why, why_cap, "telegram.pool is 0 to %d", BYE_CONFIG_POOL_MAX);
            return -1;
        }
        config->pool = value[0] - '0';
        return 0;
    }
    if (strcmp(key, "version") == 0) {
        if (value[0] < '1' || value[0] > '0' + BYE_CONFIG_VERSION || value[1] != '\0') {
            snprintf(why, why_cap, "version is 1 to %d", BYE_CONFIG_VERSION);
            return -1;
        }
        config->version = value[0] - '0';
        return 0;
    }
    if (strcmp(key, "relay") == 0) {
        if (strcmp(value, "none") == 0) {
            config->relay[0] = '\0';
            return 0;
        }
        char list[BYE_CONFIG_RELAY_MAX];
        size_t used = 0;
        int count = 0;
        const char *p = value;
        list[0] = '\0';
        while (*p) {
            const char *comma = strchr(p, ',');
            size_t n = comma ? (size_t)(comma - p) : strlen(p);
            char name[BYE_CONFIG_RELAY_NAME_MAX + 1];
            while (n && *p == ' ') { ++p; --n; }
            while (n && p[n - 1] == ' ') --n;
            if (n == 0 || n >= sizeof name || count == BYE_CONFIG_RELAYS) goto bad_relay;
            memcpy(name, p, n);
            name[n] = '\0';
            if (!relay_domain_ok(name) || used + n + 2 > sizeof list) goto bad_relay;
            used += (size_t)snprintf(list + used, sizeof list - used, "%s%s", count ? "," : "", name);
            ++count;
            if (!comma) break;
            p = comma + 1;
            if (!*p) goto bad_relay;
        }
        if (!count) goto bad_relay;
        return copy_text(config->relay, sizeof config->relay, list);
    bad_relay:
        snprintf(why, why_cap, "relay is up to %d domain names or none", BYE_CONFIG_RELAYS);
        return -1;
    }
    if (strcmp(key, "dns") == 0) {
        struct in_addr address;
        if (strcmp(value, "system") == 0) {
            config->dns[0] = '\0';
            return 0;
        }
        if (strlen(value) >= sizeof config->dns || inet_pton(AF_INET, value, &address) != 1) {
            snprintf(why, why_cap, "dns is an ipv4 address or system");
            return -1;
        }
        return copy_text(config->dns, sizeof config->dns, value);
    }
    snprintf(why, why_cap, "unknown key");
    return -1;
}

bye_config_status_t bye_config_parse(const char *text, size_t len, bye_config_t *config,
                                     char *error, size_t error_cap) {
    if (error && error_cap) error[0] = '\0';
    if (!text || !config) return BYE_CONFIG_ERR_ARG;
    if (len > BYE_CONFIG_FILE_MAX) {
        fail(error, error_cap, 0, "the file is too large");
        return BYE_CONFIG_ERR_PARSE;
    }

    bye_config_t next = *config;
    next.spec_reduced = 0;
    size_t line_no = 0;
    size_t pos = 0;
    while (pos < len) {
        const char *line = text + pos;
        const char *nl = memchr(line, '\n', len - pos);
        size_t line_len = nl ? (size_t)(nl - line) : len - pos;
        pos += nl ? line_len + 1 : line_len;
        ++line_no;

        while (line_len && (line[line_len - 1] == '\r' || line[line_len - 1] == ' ' ||
                            line[line_len - 1] == '\t')) --line_len;
        while (line_len && (*line == ' ' || *line == '\t')) {
            ++line;
            --line_len;
        }
        if (line_len == 0 || *line == '#') continue;

        const char *eq = memchr(line, '=', line_len);
        if (!eq) {
            fail(error, error_cap, line_no, "expected key = value");
            return BYE_CONFIG_ERR_PARSE;
        }
        const char *key_end = eq;
        while (key_end > line && (key_end[-1] == ' ' || key_end[-1] == '\t')) --key_end;
        const char *value = eq + 1;
        const char *line_end = line + line_len;
        while (value < line_end && (*value == ' ' || *value == '\t')) ++value;

        char key[32], val[BYE_CONFIG_SPEC_MAX + 8];
        size_t key_len = (size_t)(key_end - line);
        size_t val_len = (size_t)(line_end - value);
        if (key_len == 0 || key_len >= sizeof key || val_len >= sizeof val) {
            fail(error, error_cap, line_no, "key or value too long");
            return BYE_CONFIG_ERR_PARSE;
        }
        memcpy(key, line, key_len);
        key[key_len] = '\0';
        memcpy(val, value, val_len);
        val[val_len] = '\0';

        char why[144];
        if (apply(&next, key, val, why, sizeof why) != 0) {
            fail(error, error_cap, line_no, why);
            return BYE_CONFIG_ERR_PARSE;
        }
    }
    *config = next;
    return BYE_CONFIG_OK;
}

int bye_config_render(const bye_config_t *config, char *out, size_t cap) {
    if (!config || !out || !cap) return -1;
    int n = snprintf(out, cap,
                     "version = %d\n"
                     "desync.spec = %s\n"
                     "hosts = %s\n"
                     "hosts.mode = %s\n"
                     "telegram = %s\n"
                     "telegram.pool = %d\n"
                     "quic = %s\n"
                     "dns = %s\n"
                     "relay = %s\n"
                     "autostart = %s\n"
                     "proxy = %s\n"
                     "proxy.port = %d\n"
                     "proxy.secret = %s\n",
                     config->version, config->desync_spec,
                     config->hosts[0] ? config->hosts : "none",
                     config->hosts_only ? "only" : "except",
                     config->telegram ? "on" : "off", config->pool,
                     config->block_quic ? "block" : "pass",
                     config->dns[0] ? config->dns : "system",
                     config->relay[0] ? config->relay : "none",
                     config->autostart ? "on" : "off",
                     config->proxy ? "on" : "off", config->proxy_port,
                     config->proxy_secret[0] ? config->proxy_secret : "auto");
    return n > 0 && (size_t)n < cap ? 0 : -1;
}
