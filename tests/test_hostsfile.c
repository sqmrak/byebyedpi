#define _DEFAULT_SOURCE

#include "bye_hostsfile.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"

static char dir[] = "/tmp/bye-hostsfile-XXXXXX";

static void put(const char *name, const char *text, size_t len) {
    char path[160];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *file = fopen(path, "wb");
    CHECK(file != NULL);
    if (!file) return;
    CHECK(fwrite(text, 1, len, file) == len);
    fclose(file);
}

int main(void) {
    CHECK(mkdtemp(dir) != NULL);
    char reason[200];
    bye_hosts_t *hosts;

    put("list.txt", "# list\nyoutube.com\ndiscord.com\n", strlen("# list\nyoutube.com\ndiscord.com\n"));
    hosts = bye_hostsfile_load(dir, "list.txt", reason, sizeof reason);
    CHECK(hosts != NULL && bye_hosts_count(hosts) == 2 && reason[0] == '\0');
    CHECK(bye_hosts_match(hosts, "www.youtube.com", 15));
    bye_hosts_free(hosts);

    put("empty", "", 0);
    hosts = bye_hostsfile_load(dir, "empty", reason, sizeof reason);
    CHECK(hosts != NULL && bye_hosts_count(hosts) == 0);
    bye_hosts_free(hosts);

    /* a missing file, a broken one, one too large */
    CHECK(bye_hostsfile_load(dir, "absent.txt", reason, sizeof reason) == NULL);
    CHECK(strstr(reason, "cannot read the hosts list absent.txt") != NULL);
    put("bad.txt", "a.org\nbad name\n", strlen("a.org\nbad name\n"));
    CHECK(bye_hostsfile_load(dir, "bad.txt", reason, sizeof reason) == NULL);
    CHECK(strcmp(reason, "hosts list bad.txt, line 2: not a domain name") == 0);
    char *big = malloc(BYE_HOSTS_FILE_MAX + 100);
    memset(big, '#', BYE_HOSTS_FILE_MAX + 100);
    put("big.txt", big, BYE_HOSTS_FILE_MAX + 100);
    free(big);
    CHECK(bye_hostsfile_load(dir, "big.txt", reason, sizeof reason) == NULL);
    CHECK(strstr(reason, "larger than") != NULL);

    /* the directory is the app's: none of these may be followed or opened */
    char path[200], target[200];
    snprintf(path, sizeof path, "%s/link.txt", dir);
    snprintf(target, sizeof target, "%s/list.txt", dir);
    CHECK(symlink(target, path) == 0);
    CHECK(bye_hostsfile_load(dir, "link.txt", reason, sizeof reason) == NULL);
    CHECK(strstr(reason, "cannot read") != NULL);
    snprintf(path, sizeof path, "%s/pipe.txt", dir);
    CHECK(mkfifo(path, 0600) == 0);
    CHECK(bye_hostsfile_load(dir, "pipe.txt", reason, sizeof reason) == NULL);
    CHECK(strstr(reason, "not a plain file") != NULL);
    snprintf(path, sizeof path, "%s/sub.txt", dir);
    CHECK(mkdir(path, 0700) == 0);
    CHECK(bye_hostsfile_load(dir, "sub.txt", reason, sizeof reason) == NULL);
    CHECK(strstr(reason, "cannot read") != NULL || strstr(reason, "not a plain file") != NULL);

    /* names that are not plain file names never reach the disk */
    static const char *const names[] = { "../x", "a/b", "/etc/passwd", ".hidden", "", "a b", "x\n" };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; ++i) {
        CHECK(bye_hostsfile_load(dir, names[i], reason, sizeof reason) == NULL);
        CHECK(strstr(reason, "not a plain file name") != NULL);
    }
    CHECK(bye_hostsfile_load(NULL, "list.txt", reason, sizeof reason) == NULL);
    CHECK(bye_hostsfile_load(dir, NULL, reason, sizeof reason) == NULL);
    CHECK(bye_hostsfile_load(dir, "list.txt", NULL, 0) == NULL);

    char deep[600];
    memset(deep, 'd', sizeof deep - 1);
    deep[sizeof deep - 1] = '\0';
    CHECK(bye_hostsfile_load(deep, "list.txt", reason, sizeof reason) == NULL);
    CHECK(strstr(reason, "too long") != NULL);

    char cmd[200];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd) != 0) fprintf(stderr, "cleanup failed\n");
    if (!failed) puts("test_hostsfile ok");
    return failed;
}
