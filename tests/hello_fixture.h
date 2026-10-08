#ifndef BYE_HELLO_FIXTURE_H
#define BYE_HELLO_FIXTURE_H

/* move sni past a tcp packet with a real tls padding extension */
static size_t padded_hello(uint8_t *out, size_t cap, size_t padding) {
    if (!out || padding > 16384 - (sizeof hello_openssl - 5) - 4 ||
        cap < sizeof hello_openssl + padding + 4) return 0;
    bye_sniff_t name;
    CHECK(bye_sniff_tls(hello_openssl, hello_openssl_len, &name) == BYE_SNIFF_OK);
    size_t ext = name.name_off - 9;
    size_t pos = 9 + 2 + 32;
    pos += 1 + hello_openssl[pos];
    pos += 2 + (((size_t)hello_openssl[pos] << 8) | hello_openssl[pos + 1]);
    pos += 1 + hello_openssl[pos];
    memcpy(out, hello_openssl, ext);
    out[ext] = 0;
    out[ext + 1] = 21;
    out[ext + 2] = (uint8_t)(padding >> 8);
    out[ext + 3] = (uint8_t)padding;
    memset(out + ext + 4, 0, padding);
    memcpy(out + ext + 4 + padding, hello_openssl + ext, hello_openssl_len - ext);
    size_t added = padding + 4;
    size_t len = hello_openssl_len + added;
    out[3] = (uint8_t)((len - 5) >> 8);
    out[4] = (uint8_t)(len - 5);
    out[6] = (uint8_t)((len - 9) >> 16);
    out[7] = (uint8_t)((len - 9) >> 8);
    out[8] = (uint8_t)(len - 9);
    size_t exts = ((size_t)out[pos] << 8) | out[pos + 1];
    exts += added;
    out[pos] = (uint8_t)(exts >> 8);
    out[pos + 1] = (uint8_t)exts;
    CHECK(bye_sniff_tls(out, len, &name) == BYE_SNIFF_OK);
    return len;
}

static inline size_t named_hello(uint8_t *out, size_t cap, const char *host) {
    bye_sniff_t name;
    CHECK(bye_sniff_tls(hello_openssl, hello_openssl_len, &name) == BYE_SNIFF_OK);
    size_t n = strlen(host);
    if (!n || n > 255 || cap < hello_openssl_len - name.name_len + n) return 0;
    size_t len = hello_openssl_len - name.name_len + n;
    memcpy(out, hello_openssl, name.name_off);
    memcpy(out + name.name_off, host, n);
    memcpy(out + name.name_off + n, hello_openssl + name.name_off + name.name_len,
           hello_openssl_len - name.name_off - name.name_len);
    out[3] = (uint8_t)((len - 5) >> 8);
    out[4] = (uint8_t)(len - 5);
    out[6] = (uint8_t)((len - 9) >> 16);
    out[7] = (uint8_t)((len - 9) >> 8);
    out[8] = (uint8_t)(len - 9);
    const size_t fields[] = {name.name_off - 7, name.name_off - 5, name.name_off - 2};
    for (size_t i = 0; i < sizeof fields / sizeof fields[0]; ++i) {
        size_t pos = fields[i];
        size_t value = (((size_t)out[pos] << 8) | out[pos + 1]) - name.name_len + n;
        out[pos] = (uint8_t)(value >> 8);
    out[pos + 1] = (uint8_t)value;
    }
    size_t pos = 9 + 2 + 32;
    pos += 1 + hello_openssl[pos];
    pos += 2 + (((size_t)hello_openssl[pos] << 8) | hello_openssl[pos + 1]);
    pos += 1 + hello_openssl[pos];
    size_t exts = (((size_t)out[pos] << 8) | out[pos + 1]) - name.name_len + n;
    out[pos] = (uint8_t)(exts >> 8);
    out[pos + 1] = (uint8_t)exts;
    CHECK(bye_sniff_tls(out, len, &name) == BYE_SNIFF_OK && name.name_len == n);
    return len;
}

#endif
