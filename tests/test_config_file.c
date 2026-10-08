#define main daemon_main_entry
#include "../daemon/main.c"
#undef main

#include "check.h"

static void write_config(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) return;
    CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    CHECK(close(fd) == 0);
}

int main(void) {
    char dir[] = "/tmp/bye-config-file-XXXXXX";
    char *created = mkdtemp(dir);
    CHECK(created != NULL);
    if (!created) return failed;
    daemon_t daemon;
    memset(&daemon, 0, sizeof daemon);
    int n = snprintf(daemon.config_path, sizeof daemon.config_path, "%s/config", dir);
    CHECK(n > 0 && (size_t)n < sizeof daemon.config_path);
    load_config(&daemon);
    CHECK(!daemon.config_error[0] && daemon.config.version == BYE_CONFIG_VERSION);
    CHECK(!strcmp(daemon.config.dns, "1.1.1.1"));

    char error[BYE_CONFIG_ERROR_MAX];
    const char system[] = "dns = system\n";
    CHECK(bye_config_parse(system, sizeof system - 1, &daemon.config, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(save_config(&daemon) == 0);
    load_config(&daemon);
    CHECK(!daemon.config_error[0] && !daemon.config.dns[0]);

    write_config(daemon.config_path,
                 "version = 3\ndns = system\ndesync.spec = tlsrec=mid;split=1,mid\n"
                 "hosts = youtube.sites\nproxy.secret = 000102030405060708090a0b0c0d0e0f\n");
    load_config(&daemon);
    CHECK(!daemon.config_error[0] && daemon.config.version == BYE_CONFIG_VERSION);
    CHECK(!strcmp(daemon.config.dns, "1.1.1.1"));
    CHECK(!strcmp(daemon.config.desync_spec, BYE_CONFIG_SPEC_V2_DEFAULT));
    CHECK(!strcmp(daemon.config.hosts, "youtube.sites"));
    CHECK(!strcmp(daemon.config.proxy_secret, "000102030405060708090a0b0c0d0e0f"));
    char text[BYE_CONFIG_FILE_MAX + 2];
    size_t len = 0;
    CHECK(read_file(daemon.config_path, text, sizeof text - 1, &len) == 0);
    text[len] = '\0';
    CHECK(strstr(text, "version = 4\n") && strstr(text, "dns = 1.1.1.1\n"));
    load_config(&daemon);
    CHECK(!daemon.config_error[0] && !strcmp(daemon.config.dns, "1.1.1.1"));

    CHECK(bye_config_parse(system, sizeof system - 1, &daemon.config, error, sizeof error) == BYE_CONFIG_OK);
    CHECK(save_config(&daemon) == 0);
    load_config(&daemon);
    CHECK(!daemon.config_error[0] && !daemon.config.dns[0]);

    write_config(daemon.config_path, "dns = system\n");
    load_config(&daemon);
    CHECK(!daemon.config_error[0] && !strcmp(daemon.config.dns, "1.1.1.1"));
    CHECK(daemon.config.version == BYE_CONFIG_VERSION);
    CHECK(unlink(daemon.config_path) == 0);
    CHECK(rmdir(dir) == 0);
    if (!failed) puts("test_config_file ok");
    return failed;
}
