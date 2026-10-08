#define _DEFAULT_SOURCE

#include "bye_client.h"
#include "bye_paths.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* talks to byedpid: reads the token the daemon wrote, sends it, sends one
   command and prints the answer. the exit code is 0 for an OK answer */

#define ANSWER_MAX 8192
#define TIMEOUT_MS 20000

static void usage(void) {
    fprintf(stderr,
            "usage: byebyectl [--ctl PATH] COMMAND\n"
            "  status | start | stop | restart | config | reload | set KEY VALUE | version\n"
            "  probe NAME... | probe | probe stop    which strategies get a tls hello through\n");
}

/* a started probe runs for a minute or more: ask for its report until it ends
   and print the last one. 0 when it ended on its own */
static int follow_probe(bye_client_t *client, char *answer, size_t cap) {
    char error[BYE_CLIENT_ERROR_MAX];
    for (;;) {
        sleep(2);
        if (bye_client_call(client, "probe", answer, cap, error, sizeof error) < 0) {
            fprintf(stderr, "byebyectl: %s\n", error);
            return 1;
        }
        const char *state = strstr(answer, "state=");
        const char *progress = strstr(answer, "progress=");
        if (progress) {
            int len = (int)strcspn(progress, "\n");
            fprintf(stderr, "byebyectl: %.*s\n", len, progress);
        }
        if (!state || strncmp(state, "state=running", 13) != 0) return 0;
    }
}

int main(int argc, char **argv) {
    const char *socket_path = BYE_CTL_SOCKET;
    int first = 1;
    if (argc >= 3 && strcmp(argv[1], "--ctl") == 0) {
        socket_path = argv[2];
        first = 3;
    }
    if (first >= argc) {
        usage();
        return 2;
    }
    char command[BYE_CLIENT_LINE_MAX + 1] = "";
    for (int i = first; i < argc; ++i) {
        size_t used = strlen(command);
        if (used + strlen(argv[i]) + 2 >= sizeof command) {
            fprintf(stderr, "byebyectl: the command is too long\n");
            return 2;
        }
        snprintf(command + used, sizeof command - used, "%s%s", i > first ? " " : "", argv[i]);
    }

    char error[BYE_CLIENT_ERROR_MAX];
    bye_client_t client;
    /* version is the one command the daemon answers before the token */
    if (bye_client_open(&client, socket_path, strcmp(command, "version") != 0, TIMEOUT_MS, error,
                        sizeof error) != 0) {
        fprintf(stderr, "byebyectl: %s\n", error);
        return 1;
    }
    char answer[ANSWER_MAX];
    if (bye_client_call(&client, command, answer, sizeof answer, error, sizeof error) < 0) {
        fprintf(stderr, "byebyectl: %s\n", error);
        bye_client_close(&client);
        return 1;
    }
    int ok = strncmp(answer, "OK", 2) == 0;
    if (strncmp(command, "probe ", 6) == 0 && strcmp(command, "probe stop") != 0 && ok) {
        fprintf(stderr, "byebyectl: probing, this takes a minute or more\n");
        if (follow_probe(&client, answer, sizeof answer) != 0) {
            bye_client_close(&client);
            return 1;
        }
        ok = strncmp(answer, "OK", 2) == 0;
    }
    bye_client_close(&client);
    fputs(answer, stdout);
    return ok ? 0 : 1;
}
