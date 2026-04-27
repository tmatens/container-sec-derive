/*
 * csd synthetic cap-exerciser.
 *
 * Long-running process that periodically invokes syscalls which fire
 * cap_capable() checks for a known set of capabilities, all from a
 * stable non-runc comm ("exerciser"). The container running this
 * binary is csd's pipeline regression fixture: postgres + caddy
 * showed empty observed cap sets in Step 30 because their workloads
 * trigger no capable() calls after `ig` attaches. This binary makes
 * sure that when caps *are* exercised post-attach from a userspace
 * process, csd records them.
 *
 * Cycle (one per second):
 *   chown(target, 1, 1)        -> CAP_CHOWN
 *   chown(target, 0, 0)        -> CAP_CHOWN
 *   chmod(target, 04755)       -> CAP_FSETID (suid bit on root-owned)
 *   chmod(target, 0644)
 *   bind(:80) loopback         -> CAP_NET_BIND_SERVICE
 *   fork() + child setgid(65534) -> CAP_SETGID
 *           child setuid(65534) -> CAP_SETUID
 *
 * Build: gcc -static -O2 -o /exerciser exerciser.c
 * The static link + scratch base image keeps comm = "exerciser".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

static const char *TARGET = "/csd-exerciser-target";

static void exercise_chown(void) {
    int fd = open(TARGET, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        if (write(fd, "x", 1) < 0) perror("write");
        close(fd);
    } else {
        perror("open target");
        return;
    }
    if (chown(TARGET, 1, 1) < 0) perror("chown 1:1");
    if (chown(TARGET, 0, 0) < 0) perror("chown 0:0");
}

static void exercise_chmod(void) {
    if (chmod(TARGET, 04755) < 0) perror("chmod 04755");
    if (chmod(TARGET, 0644) < 0) perror("chmod 0644");
}

static void exercise_bind(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(80);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) perror("bind :80");
    close(s);
}

static void exercise_setuid(void) {
    pid_t p = fork();
    if (p == 0) {
        if (setgid(65534) < 0) perror("setgid 65534");
        if (setuid(65534) < 0) perror("setuid 65534");
        _exit(0);
    } else if (p > 0) {
        waitpid(p, NULL, 0);
    } else {
        perror("fork");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    fprintf(stdout, "csd-exerciser starting\n");
    int cycle = 0;
    for (;;) {
        exercise_chown();
        exercise_chmod();
        exercise_bind();
        exercise_setuid();
        if (cycle % 5 == 0) {
            fprintf(stdout, "cycle=%d\n", cycle);
        }
        cycle++;
        sleep(1);
    }
}
