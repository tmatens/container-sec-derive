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
 *   chown(target, 1, -1)       -> CAP_CHOWN  (uid-only: one check per call)
 *   chown(target, 0, -1)       -> CAP_CHOWN
 *   chmod(target, 04755)       -> CAP_FSETID (suid bit on root-owned)
 *   chmod(target, 0644)
 *   bind(:80) loopback         -> CAP_NET_BIND_SERVICE
 *   fork() + child setgid(65534) -> CAP_SETGID
 *           child setuid(65534) -> CAP_SETUID
 *
 * Build: gcc -static -O2 -o /exerciser exerciser.c
 * The static link + scratch base image keeps comm = "exerciser".
 *
 * Counting mode (env ITERS>0): used by scripts/kretprobe_missrate.sh.
 * After an optional WARMUP_MS sleep (so csd can attach its BPF before any
 * counted op fires), run exactly ITERS cycles with no inter-cycle sleep,
 * tally the cap-invoking syscalls that SUCCEEDED, print a machine-readable
 * "TALLY ..." line, and exit. A successful syscall means the kernel
 * invoked capable() for that cap and it was held -> exactly one
 * capable=true event, giving the harness an exact ground-truth count.
 * ITERS unset/0 keeps the legacy infinite 1 Hz loop the smoke fixture uses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

/* Non-default /dev node the v0.3 device smoke maps in via
 * `docker run --device /dev/null:/dev/csd-exerciser-dev`. Opening it fires a
 * trace_open on a /dev path the device observer must record — a hardware-free,
 * deterministic device gate. A no-op (ENOENT) when the harness did not map it,
 * so the cap/fs/miss-rate smokes that don't map it are unaffected. */
static const char *DEVICE_TARGET = "/dev/csd-exerciser-dev";

/* Open the mapped device node, if present. Legacy-loop only (never counting
 * mode), so the kretprobe miss-rate tally stays exactly 1 syscall : 1 cap
 * event. Opening a /dev/null-backed node needs no capability, so it perturbs
 * no cap observation either. */
static void exercise_device(void) {
    int fd = open(DEVICE_TARGET, O_RDONLY);
    if (fd >= 0) close(fd);
}

/* A mode-0000 file baked into the image. Read as root it needs a DAC override:
 * mode 0000 has no read bit for anyone, so DAC denies the read regardless of
 * ownership, and the kernel checks CAP_DAC_OVERRIDE -> a cap_capable(DAC_OVERRIDE,
 * syscall=openat) event. (Mode is the discriminator, not ownership — a root-owned
 * 0600 file would be readable by root with no cap check.) This drives the
 * adversarial "does csd narrow soundly"
 * test (#349 scenario 5): DAC_READ_SEARCH *would* also satisfy this read, but the
 * openat syscall alone cannot prove the access is read-only (it could have been a
 * write), so csd must NOT narrow DAC_OVERRIDE -> DAC_READ_SEARCH. Legacy-loop only
 * (never counting mode), so it can't perturb the miss-rate 1:1 tally; and gated on
 * CSD_EXERCISE_DAC so ONLY the scenario-5 smoke fires it — every other smoke that
 * shares this image is byte-identical (no new DAC_OVERRIDE events). */
static const char *DAC_FOREIGN_TARGET = "/csd-exerciser-foreign";
static void exercise_read_foreign(void) {
    int fd = open(DAC_FOREIGN_TARGET, O_RDONLY);
    if (fd >= 0) { char b; if (read(fd, &b, 1) < 0) { /* ignore */ } close(fd); }
}

/* Each exercise_* returns the count of cap-invoking syscalls that
 * SUCCEEDED this call (one capable=true event per success). Legacy mode
 * ignores the returns; counting mode accumulates them. */

static int exercise_chown(void) {
    int n = 0;
    int fd = open(TARGET, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        if (write(fd, "x", 1) < 0) perror("write");
        close(fd);
    } else {
        perror("open target");
        return 0;
    }
    /* Change only the uid (gid = -1 = "no change"). chown() with both
     * ATTR_UID and ATTR_GID fires CAP_CHOWN twice (once per field), which
     * breaks the 1 syscall -> 1 cap-event mapping the miss-rate harness
     * relies on; uid-only keeps it exactly 1:1. CAP_CHOWN still fires. */
    if (chown(TARGET, 1, (gid_t)-1) == 0) n++; else perror("chown uid=1");
    if (chown(TARGET, 0, (gid_t)-1) == 0) n++; else perror("chown uid=0");
    return n;
}

static void exercise_chmod(void) {
    if (chmod(TARGET, 04755) < 0) perror("chmod 04755");
    if (chmod(TARGET, 0644) < 0) perror("chmod 0644");
}

static int exercise_bind(void) {
    int ok = 0;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 0; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(80);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) == 0) ok = 1; else perror("bind :80");
    close(s);
    return ok;
}

/* Returns 1 if the child held both CAP_SETGID and CAP_SETUID (both
 * setgid/setuid succeeded). The child must fork because setuid(65534)
 * permanently drops privilege. */
static int exercise_setuid(void) {
    pid_t p = fork();
    if (p == 0) {
        int ok = 1;
        if (setgid(65534) != 0) { perror("setgid 65534"); ok = 0; }
        if (setuid(65534) != 0) { perror("setuid 65534"); ok = 0; }
        _exit(ok ? 0 : 1);
    } else if (p > 0) {
        int st = 0;
        waitpid(p, &st, 0);
        return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 1 : 0;
    }
    perror("fork");
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    fprintf(stdout, "csd-exerciser starting\n");

    const char *iters_env = getenv("ITERS");
    unsigned long long iters = iters_env ? strtoull(iters_env, NULL, 10) : 0ULL;
    if (iters > 0ULL) {
        const char *warm_env = getenv("WARMUP_MS");
        unsigned long warm_ms = warm_env ? strtoul(warm_env, NULL, 10) : 0UL;
        if (warm_ms > 0UL) {
            fprintf(stdout, "warmup_ms=%lu\n", warm_ms);
            struct timespec ts = { .tv_sec = (time_t)(warm_ms / 1000UL),
                                   .tv_nsec = (long)(warm_ms % 1000UL) * 1000000L };
            nanosleep(&ts, NULL);
        }
        /* CYCLE_US throttles the loop so the cap-event rate stays under the
         * BPF ringbuf drain rate. Without it a tight loop overflows the
         * ringbuf (csd exits 21, drop rate >=10%) and the deficit would
         * reflect ringbuf drops, not kretprobe misses. */
        const char *cyc_env = getenv("CYCLE_US");
        unsigned long cycle_us = cyc_env ? strtoul(cyc_env, NULL, 10) : 0UL;
        struct timespec cyc_ts = { .tv_sec = (time_t)(cycle_us / 1000000UL),
                                   .tv_nsec = (long)(cycle_us % 1000000UL) * 1000L };
        unsigned long long c_chown = 0, c_bind = 0, c_setgid = 0, c_setuid = 0;
        fprintf(stdout, "counting iters=%llu cycle_us=%lu\n", iters, cycle_us);
        for (unsigned long long i = 0; i < iters; i++) {
            c_chown += (unsigned)exercise_chown();
            exercise_chmod();
            c_bind += (unsigned)exercise_bind();
            int s = exercise_setuid();
            c_setgid += (unsigned)s;
            c_setuid += (unsigned)s;
            if (cycle_us > 0UL) nanosleep(&cyc_ts, NULL);
        }
        fprintf(stdout,
                "TALLY chown=%llu bind=%llu setgid=%llu setuid=%llu iters=%llu\n",
                c_chown, c_bind, c_setgid, c_setuid, iters);
        return 0;
    }

    int cycle = 0;
    for (;;) {
        exercise_chown();
        exercise_chmod();
        exercise_bind();
        exercise_setuid();
        exercise_device();
        if (getenv("CSD_EXERCISE_DAC")) exercise_read_foreign();
        if (cycle % 5 == 0) {
            fprintf(stdout, "cycle=%d\n", cycle);
        }
        cycle++;
        sleep(1);
    }
}
