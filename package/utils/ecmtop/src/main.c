#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef __linux__
#include <sys/sysmacros.h>
#endif
#include <time.h>
#include <signal.h>
#include <termios.h>
#include <ctype.h>
#include <math.h>
#include <poll.h>
#include <arpa/inet.h>

/*
 * 极致内存安全与精准度设计原则：
 * 1. 零动态堆内存分配：主循环内 0 次 malloc / free，全静态预分配，无内存碎片与泄漏。
 * 2. 高精度单调时钟：采用 clock_gettime(CLOCK_MONOTONIC) 微秒级测算真实 delta_t，杜绝速率翻倍与漂移。
 * 3. 完整 IPv6 双栈与 MAC 聚合支持：
 *    - 自动嗅探 /proc/net/if_inet6 学习 LAN IPv6 委派前缀，精准判定公网 IPv6 的局域网流向；
 *    - 优先按网卡 MAC 物理地址聚合客户端，彻底杜绝 IPv6 临时隐私地址导致单设备分裂；
 *    - 自动关联 /proc/net/arp IPv4 地址；
 *    - 支持 [v] 按键在 100 列紧凑视图与 124 列完整 IPv6 宽屏视图间无缝切换。
 * 4. 边界严格受控：全量 snprintf/strncpy 截断防护，行缓冲定宽防溢出。
 */

#define MAX_CONNS 4096
#define MAX_CLIENTS 256
#define MAX_LAN_PREFIXES 8
#define MAX_ARP_ENTRIES 256

#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_DIM     "\033[2m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"
#define CURSOR_HOME   "\033[H"
#define CLEAR_SCREEN  "\033[H\033[2J"
#define HIDE_CURSOR   "\033[?25l"
#define SHOW_CURSOR   "\033[?25h"

typedef enum {
    SORT_DOWN = 0,
    SORT_UP,
    SORT_TOTAL_DOWN,
    SORT_CONNS,
    SORT_MAX
} sort_mode_t;

struct conn_info {
    uint64_t serial;
    uint64_t from_bytes;
    uint64_t to_bytes;
    int is_routed;
    char sip[64];
    char dip[64];
    char smac[18];
    char dmac[18];
};

struct client_stat {
    char mac[18];
    char display_ip[48];  /* 紧凑显示 IP */
    char full_ip[48];     /* 完整 IP (IPv4 或 IPv6) */
    char ipv4[16];        /* 关联的 IPv4 */
    char ipv6[48];        /* 关联的最新 IPv6 */
    double down_speed;    /* bytes/s */
    double up_speed;      /* bytes/s */
    uint64_t total_down;  /* 累计字节数 */
    uint64_t total_up;
    int active_conns;
};

struct wan_stat {
    double down_speed;
    double up_speed;
    uint64_t total_down;
    uint64_t total_up;
    int active_flows;
};

/* 静态内存池 */
static struct conn_info g_prev_conns[MAX_CONNS];
static int g_prev_conns_count = 0;

static struct conn_info g_curr_conns[MAX_CONNS];
static int g_curr_conns_count = 0;

static struct client_stat g_clients[MAX_CLIENTS];
static int g_clients_count = 0;

static struct wan_stat g_wan = {0};

/* 客户端持久累计流量字典 */
struct client_total {
    char key[48];         /* 主键：有效 MAC 优先，无 MAC 则用 IP */
    char mac[18];
    char ipv4[16];
    char ipv6[48];
    uint64_t total_down;
    uint64_t total_up;
    bool in_use;
};
static struct client_total g_client_totals[MAX_CLIENTS] = {0};

/* 本地 LAN IPv6 委派前缀池 (首 64 位 = 8 字节) */
struct lan_v6_prefix {
    uint8_t prefix[8];
    bool valid;
};
static struct lan_v6_prefix g_lan_v6_prefixes[MAX_LAN_PREFIXES];
static int g_lan_v6_prefixes_count = 0;

/* 本地 ARP 映射缓存 (MAC -> IPv4) */
struct arp_entry {
    char mac[18];
    char ip[16];
};
static struct arp_entry g_arp_table[MAX_ARP_ENTRIES];
static int g_arp_count = 0;

static volatile bool g_running = true;
static bool g_paused = false;
static bool g_wide_view = false; /* false: 100列紧凑视图; true: 124列宽屏IPv6视图 */
static sort_mode_t g_sort_mode = SORT_DOWN;
static struct termios g_orig_termios;
static bool g_termios_saved = false;

/* 信号处理 */
static void sig_handler(int sig) {
    (void)sig;
    g_running = false;
}

/* 终端属性控制 */
static void restore_terminal(void) {
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_orig_termios);
    }
    printf(SHOW_CURSOR "\n");
    fflush(stdout);
}

static void setup_terminal(void) {
    if (!isatty(STDIN_FILENO)) return;
    if (tcgetattr(STDIN_FILENO, &g_orig_termios) == 0) {
        g_termios_saved = true;
        atexit(restore_terminal);

        struct termios raw = g_orig_termios;
        raw.c_lflag &= ~(ECHO | ICANON);
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0; /* 纯非阻塞读取，依靠 poll 控制精确延时 */
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    }
    printf(HIDE_CURSOR CLEAR_SCREEN);
    fflush(stdout);
}

/* 自动创建字符设备 */
static int ensure_device(const char *dev_path) {
    struct stat st;
    if (stat(dev_path, &st) == 0) return 0;

    FILE *f = fopen("/sys/kernel/debug/ecm/ecm_state/state_dev_major", "r");
    if (!f) return -1;

    int major_num = 0;
    if (fscanf(f, "%d", &major_num) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);

#ifdef makedev
    dev_t dev = makedev(major_num, 0);
#else
    dev_t dev = ((major_num & 0xfff) << 8) | (0 & 0xff);
#endif
    if (mknod(dev_path, S_IFCHR | 0600, dev) != 0) {
        return -1;
    }
    return 0;
}

/* 读取 /proc/net/arp 刷新本地 MAC -> IPv4 映射 */
static void refresh_arp_cache(void) {
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return;

    g_arp_count = 0;
    char line[256];
    /* 跳过表头 */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return;
    }

    while (fgets(line, sizeof(line), f) && g_arp_count < MAX_ARP_ENTRIES) {
        char ip[64], hw_type[32], flags[32], mac[32], mask[32], dev[32];
        if (sscanf(line, "%63s %31s %31s %31s %31s %31s", ip, hw_type, flags, mac, mask, dev) == 6) {
            if (strlen(mac) == 17 && strcmp(mac, "00:00:00:00:00:00") != 0) {
                strncpy(g_arp_table[g_arp_count].mac, mac, sizeof(g_arp_table[0].mac) - 1);
                strncpy(g_arp_table[g_arp_count].ip, ip, sizeof(g_arp_table[0].ip) - 1);
                g_arp_count++;
            }
        }
    }
    fclose(f);
}

/* 根据 MAC 查找对应已知的 IPv4 */
static const char *find_ipv4_by_mac(const char *mac) {
    if (!mac || strlen(mac) != 17) return NULL;
    for (int i = 0; i < g_arp_count; i++) {
        if (strcasecmp(g_arp_table[i].mac, mac) == 0) {
            return g_arp_table[i].ip;
        }
    }
    return NULL;
}

/* 嗅探 /proc/net/if_inet6 获取 br-lan / lan 接口的 IPv6 委派前缀 */
static void refresh_lan_v6_prefixes(void) {
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (!f) return;

    g_lan_v6_prefixes_count = 0;
    char line[256];

    while (fgets(line, sizeof(line), f) && g_lan_v6_prefixes_count < MAX_LAN_PREFIXES) {
        char addr_hex[33], dev[64];
        unsigned int if_idx, prefix_len, scope, flags;
        if (sscanf(line, "%32s %x %x %x %x %63s", addr_hex, &if_idx, &prefix_len, &scope, &flags, dev) == 6) {
            /* 关注内网桥接或局域网接口 (如 br-lan, lan, eth) */
            if (strstr(dev, "lan") != NULL || strncmp(dev, "br-", 3) == 0) {
                /* 排除链路本地 fe80 */
                if (strncasecmp(addr_hex, "fe80", 4) == 0) continue;
                /* 解析前 16 个 16 进制字符即 8 字节前缀 */
                struct lan_v6_prefix *p = &g_lan_v6_prefixes[g_lan_v6_prefixes_count];
                for (int b = 0; b < 8; b++) {
                    char byte_str[3] = {addr_hex[b * 2], addr_hex[b * 2 + 1], '\0'};
                    p->prefix[b] = (uint8_t)strtoul(byte_str, NULL, 16);
                }
                p->valid = true;
                g_lan_v6_prefixes_count++;
            }
        }
    }
    fclose(f);
}

/* 判断是否为局域网 IP (IPv4 私网网段或 IPv6 ULA/本地链路/LAN 前缀匹配) */
static bool is_lan_ip(const char *ip) {
    if (!ip || !*ip) return false;

    /* 1. IPv4 私网判定 */
    if (strchr(ip, '.') != NULL) {
        if (strncmp(ip, "192.168.", 8) == 0) return true;
        if (strncmp(ip, "10.", 3) == 0) return true;
        if (strncmp(ip, "127.", 4) == 0) return true;
        if (strncmp(ip, "172.", 4) == 0) {
            int sec = atoi(ip + 4);
            if (sec >= 16 && sec <= 31) return true;
        }
        return false;
    }

    /* 2. IPv6 判定 */
    if (strncasecmp(ip, "fe80:", 5) == 0) return true;  /* Link-Local */
    if (strncasecmp(ip, "fc", 2) == 0 || strncasecmp(ip, "fd", 2) == 0) return true; /* ULA */

    /* 3. 与从 /proc/net/if_inet6 学习到的 LAN 前缀比较 */
    struct in6_addr in6;
    if (inet_pton(AF_INET6, ip, &in6) == 1) {
        for (int i = 0; i < g_lan_v6_prefixes_count; i++) {
            if (g_lan_v6_prefixes[i].valid &&
                memcmp(in6.s6_addr, g_lan_v6_prefixes[i].prefix, 8) == 0) {
                return true;
            }
        }
    }

    return false;
}

/* 紧凑化格式化 IPv6：保持在 16 字符内，如 240e:..4ebd:0af5 */
static void format_ip_compact(const char *in_ip, char *out, size_t out_len) {
    if (!in_ip || !*in_ip) {
        snprintf(out, out_len, "%-16s", "N/A");
        return;
    }
    /* IPv4 直接整洁输出 */
    if (strchr(in_ip, '.') != NULL) {
        snprintf(out, out_len, "%-16s", in_ip);
        return;
    }

    /* IPv6: 长度过长则前段与后段折叠 */
    size_t len = strlen(in_ip);
    if (len <= 16) {
        snprintf(out, out_len, "%-16s", in_ip);
    } else {
        /* 前 5 字符 (如 240e:) + ".." + 后 9 字符 (如 4ebd:0af5) 共 16 字符 */
        char prefix[6] = {0};
        strncpy(prefix, in_ip, 5);
        const char *suffix = in_ip + (len - 9);
        snprintf(out, out_len, "%s..%s", prefix, suffix);
    }
}

/* 格式化字节数：严格定宽 11 字符右对齐 */
static void format_bytes(uint64_t b, char *out, size_t out_len) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    double val = (double)b;
    int idx = 0;
    while (val >= 1024.0 && idx < 4) {
        val /= 1024.0;
        idx++;
    }
    char tmp[32];
    if (idx == 0) {
        snprintf(tmp, sizeof(tmp), "%" PRIu64 " B", b);
    } else {
        snprintf(tmp, sizeof(tmp), "%.2f %s", val, units[idx]);
    }
    snprintf(out, out_len, "%11s", tmp);
}

/* 格式化流速：严格定宽 12 字符右对齐 */
static void format_speed(double speed, char *out, size_t out_len) {
    char tmp[32];
    if (speed < 1024.0) {
        snprintf(tmp, sizeof(tmp), "%.1f B/s", speed);
    } else if (speed < 1024.0 * 1024.0) {
        snprintf(tmp, sizeof(tmp), "%.1f KB/s", speed / 1024.0);
    } else if (speed < 1024.0 * 1024.0 * 1024.0) {
        snprintf(tmp, sizeof(tmp), "%.2f MB/s", speed / (1024.0 * 1024.0));
    } else {
        snprintf(tmp, sizeof(tmp), "%.2f GB/s", speed / (1024.0 * 1024.0 * 1024.0));
    }
    snprintf(out, out_len, "%12s", tmp);
}

/* 格式化比特率：严格定宽 12 字符右对齐 */
static void format_bitrate(double speed, char *out, size_t out_len) {
    double bps = speed * 8.0;
    char tmp[32];
    if (bps < 1000.0) {
        snprintf(tmp, sizeof(tmp), "%.0f bps", bps);
    } else if (bps < 1000.0 * 1000.0) {
        snprintf(tmp, sizeof(tmp), "%.1f Kbps", bps / 1000.0);
    } else if (bps < 1000.0 * 1000.0 * 1000.0) {
        snprintf(tmp, sizeof(tmp), "%.2f Mbps", bps / (1000.0 * 1000.0));
    } else {
        snprintf(tmp, sizeof(tmp), "%.2f Gbps", bps / (1000.0 * 1000.0 * 1000.0));
    }
    snprintf(out, out_len, "%12s", tmp);
}

/* 绘制进度条 */
static void render_progress_bar(double ratio, int width, const char *fill_color, char *out, size_t out_len) {
    if (ratio < 0.0) ratio = 0.0;
    if (ratio > 1.0) ratio = 1.0;
    int filled = (int)round(ratio * width);
    if (filled > width) filled = width;
    int empty = width - filled;

    char bar_fill[64] = {0};
    char bar_empty[64] = {0};
    if (filled > 0 && filled < (int)sizeof(bar_fill)) memset(bar_fill, '#', filled);
    if (empty > 0 && empty < (int)sizeof(bar_empty)) memset(bar_empty, '.', empty);

    snprintf(out, out_len, "%s%s%s%s", fill_color, bar_fill, COLOR_DIM, bar_empty);
}

/* 查找上一周期该连接的索引 (基于 serial) */
static int find_prev_conn(uint64_t serial) {
    for (int i = 0; i < g_prev_conns_count; i++) {
        if (g_prev_conns[i].serial == serial) return i;
    }
    return -1;
}

/* 查找或创建客户端累计记录（以 MAC 为主键，无有效 MAC 则以 IP 兜底） */
static struct client_total *get_client_total(const char *key, const char *mac, const char *ip) {
    if (!key || !*key) return NULL;

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_client_totals[i].in_use && strcasecmp(g_client_totals[i].key, key) == 0) {
            if (mac && strlen(mac) == 17 && (!g_client_totals[i].mac[0] || strcmp(g_client_totals[i].mac, "N/A") == 0)) {
                strncpy(g_client_totals[i].mac, mac, sizeof(g_client_totals[i].mac) - 1);
            }
            if (ip && *ip) {
                if (strchr(ip, '.') != NULL) {
                    strncpy(g_client_totals[i].ipv4, ip, sizeof(g_client_totals[i].ipv4) - 1);
                } else {
                    strncpy(g_client_totals[i].ipv6, ip, sizeof(g_client_totals[i].ipv6) - 1);
                }
            }
            return &g_client_totals[i];
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_client_totals[i].in_use) {
            g_client_totals[i].in_use = true;
            strncpy(g_client_totals[i].key, key, sizeof(g_client_totals[i].key) - 1);
            strncpy(g_client_totals[i].mac, (mac && strlen(mac) == 17) ? mac : "N/A", sizeof(g_client_totals[i].mac) - 1);
            if (ip && *ip) {
                if (strchr(ip, '.') != NULL) {
                    strncpy(g_client_totals[i].ipv4, ip, sizeof(g_client_totals[i].ipv4) - 1);
                } else {
                    strncpy(g_client_totals[i].ipv6, ip, sizeof(g_client_totals[i].ipv6) - 1);
                }
            }
            g_client_totals[i].total_down = 0;
            g_client_totals[i].total_up = 0;
            return &g_client_totals[i];
        }
    }
    return NULL;
}

/* 流式读取 /dev/ecm_state 并解析 */
static int read_ecm_state(const char *dev_path) {
    FILE *f = fopen(dev_path, "r");
    if (!f) return -1;

    g_curr_conns_count = 0;
    char line[1024];

    uint64_t cur_serial = 0;
    struct conn_info *entry = NULL;

    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "conns.conn.", 11) != 0) continue;

        char *eq = strchr(line + 11, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = line + 11;
        char *val = eq + 1;
        char *nl = strchr(val, '\n');
        if (nl) *nl = '\0';

        char *dot = strchr(key, '.');
        if (!dot) continue;
        *dot = '\0';
        char *serial_str = key;
        char *field = dot + 1;

        uint64_t s = strtoull(serial_str, NULL, 10);
        if (s == 0) continue;

        if (s != cur_serial) {
            if (g_curr_conns_count >= MAX_CONNS) break;
            cur_serial = s;
            entry = &g_curr_conns[g_curr_conns_count++];
            memset(entry, 0, sizeof(*entry));
            entry->serial = s;
        }

        if (!entry) continue;

        if (strcmp(field, "sip_address") == 0) {
            strncpy(entry->sip, val, sizeof(entry->sip) - 1);
        } else if (strcmp(field, "snode_address") == 0) {
            strncpy(entry->smac, val, sizeof(entry->smac) - 1);
        } else if (strcmp(field, "dip_address") == 0) {
            strncpy(entry->dip, val, sizeof(entry->dip) - 1);
        } else if (strcmp(field, "dnode_address") == 0) {
            strncpy(entry->dmac, val, sizeof(entry->dmac) - 1);
        } else if (strcmp(field, "is_routed") == 0) {
            entry->is_routed = atoi(val);
        } else if (strcmp(field, "adv_stats.from_data_total") == 0) {
            entry->from_bytes = strtoull(val, NULL, 10);
        } else if (strcmp(field, "adv_stats.to_data_total") == 0) {
            entry->to_bytes = strtoull(val, NULL, 10);
        }
    }

    fclose(f);
    return 0;
}

/* 客户端比较函数 (qsort) */
static int client_cmp(const void *a, const void *b) {
    const struct client_stat *ca = (const struct client_stat *)a;
    const struct client_stat *cb = (const struct client_stat *)b;
    switch (g_sort_mode) {
        case SORT_UP:
            return (cb->up_speed > ca->up_speed) - (cb->up_speed < ca->up_speed);
        case SORT_TOTAL_DOWN:
            return (cb->total_down > ca->total_down) - (cb->total_down < ca->total_down);
        case SORT_CONNS:
            return cb->active_conns - ca->active_conns;
        case SORT_DOWN:
        default:
            return (cb->down_speed > ca->down_speed) - (cb->down_speed < ca->down_speed);
    }
}

/* 核心差分采样计算 */
static void collect_stats(double actual_interval) {
    if (actual_interval <= 0.0) actual_interval = 1.0;

    refresh_arp_cache();
    refresh_lan_v6_prefixes();

    g_clients_count = 0;
    uint64_t wan_delta_down = 0;
    uint64_t wan_delta_up = 0;
    int active_flows = 0;

    for (int i = 0; i < g_curr_conns_count; i++) {
        struct conn_info *cur = &g_curr_conns[i];
        if (cur->is_routed != 1) continue;
        active_flows++;

        const char *c_ip = cur->sip;
        const char *c_mac = cur->smac;
        uint64_t flow_down = 0, flow_up = 0;

        int p_idx = find_prev_conn(cur->serial);

        /* 精准判断 LAN 客户端与 WAN 远端 */
        bool sip_is_lan = is_lan_ip(cur->sip);
        bool dip_is_lan = is_lan_ip(cur->dip);

        if (sip_is_lan && !dip_is_lan) {
            /* 内网客户端主动发起到外网的连接: to_bytes 为下载，from_bytes 为上传 */
            c_ip = cur->sip;
            c_mac = cur->smac;
            if (p_idx >= 0) {
                if (cur->to_bytes >= g_prev_conns[p_idx].to_bytes)
                    flow_down = cur->to_bytes - g_prev_conns[p_idx].to_bytes;
                if (cur->from_bytes >= g_prev_conns[p_idx].from_bytes)
                    flow_up = cur->from_bytes - g_prev_conns[p_idx].from_bytes;
            }
        } else if (dip_is_lan && !sip_is_lan) {
            /* 外网发起到内网客户端的连接: from_bytes 为下载，to_bytes 为上传 */
            c_ip = cur->dip;
            c_mac = cur->dmac;
            if (p_idx >= 0) {
                if (cur->from_bytes >= g_prev_conns[p_idx].from_bytes)
                    flow_down = cur->from_bytes - g_prev_conns[p_idx].from_bytes;
                if (cur->to_bytes >= g_prev_conns[p_idx].to_bytes)
                    flow_up = cur->to_bytes - g_prev_conns[p_idx].to_bytes;
            }
        } else {
            /* 默认假设 sip 为客户端 */
            c_ip = cur->sip;
            c_mac = cur->smac;
            if (p_idx >= 0) {
                if (cur->to_bytes >= g_prev_conns[p_idx].to_bytes)
                    flow_down = cur->to_bytes - g_prev_conns[p_idx].to_bytes;
                if (cur->from_bytes >= g_prev_conns[p_idx].from_bytes)
                    flow_up = cur->from_bytes - g_prev_conns[p_idx].from_bytes;
            }
        }

        wan_delta_down += flow_down;
        wan_delta_up += flow_up;

        /* 聚合主键：有效 MAC 优先（物理聚合），否则以 IP 聚合 */
        char client_key[64];
        if (c_mac && strlen(c_mac) == 17 && strcmp(c_mac, "00:00:00:00:00:00") != 0) {
            strncpy(client_key, c_mac, sizeof(client_key) - 1);
        } else {
            strncpy(client_key, c_ip, sizeof(client_key) - 1);
        }

        /* 查找当前周期的客户端统计条目 */
        int found = -1;
        for (int c = 0; c < g_clients_count; c++) {
            if (c_mac && strlen(c_mac) == 17 && strcasecmp(g_clients[c].mac, c_mac) == 0) {
                found = c;
                break;
            } else if (strcmp(g_clients[c].full_ip, c_ip) == 0) {
                found = c;
                break;
            }
        }

        if (found < 0 && g_clients_count < MAX_CLIENTS) {
            found = g_clients_count++;
            memset(&g_clients[found], 0, sizeof(struct client_stat));
            strncpy(g_clients[found].mac, (c_mac && strlen(c_mac) == 17) ? c_mac : "N/A", sizeof(g_clients[found].mac) - 1);
            strncpy(g_clients[found].full_ip, c_ip, sizeof(g_clients[found].full_ip) - 1);

            /* 探测并绑定 IPv4 */
            const char *arp_v4 = find_ipv4_by_mac(c_mac);
            if (arp_v4) {
                strncpy(g_clients[found].ipv4, arp_v4, sizeof(g_clients[found].ipv4) - 1);
            } else if (strchr(c_ip, '.') != NULL) {
                strncpy(g_clients[found].ipv4, c_ip, sizeof(g_clients[found].ipv4) - 1);
            }

            /* 探测并绑定 IPv6 */
            if (strchr(c_ip, ':') != NULL) {
                strncpy(g_clients[found].ipv6, c_ip, sizeof(g_clients[found].ipv6) - 1);
            }
        }

        if (found >= 0) {
            struct client_stat *cs = &g_clients[found];
            cs->down_speed += (double)flow_down / actual_interval;
            cs->up_speed += (double)flow_up / actual_interval;
            cs->active_conns++;

            /* 动态补充 IP 信息 */
            if (strchr(c_ip, '.') != NULL && !cs->ipv4[0]) {
                strncpy(cs->ipv4, c_ip, sizeof(cs->ipv4) - 1);
            } else if (strchr(c_ip, ':') != NULL && !cs->ipv6[0]) {
                strncpy(cs->ipv6, c_ip, sizeof(cs->ipv6) - 1);
            }

            /* 决定展示 IP：优先 IPv4（易读），纯 IPv6 设备展示 IPv6 */
            const char *primary_ip = cs->ipv4[0] ? cs->ipv4 : (cs->ipv6[0] ? cs->ipv6 : cs->full_ip);
            strncpy(cs->full_ip, primary_ip, sizeof(cs->full_ip) - 1);
            format_ip_compact(primary_ip, cs->display_ip, sizeof(cs->display_ip));

            struct client_total *tot = get_client_total(client_key, c_mac, c_ip);
            if (tot) {
                tot->total_down += flow_down;
                tot->total_up += flow_up;
                cs->total_down = tot->total_down;
                cs->total_up = tot->total_up;
            }
        }
    }

    /* 精确计算瞬时速率 */
    g_wan.down_speed = (double)wan_delta_down / actual_interval;
    g_wan.up_speed = (double)wan_delta_up / actual_interval;
    g_wan.total_down += wan_delta_down;
    g_wan.total_up += wan_delta_up;
    g_wan.active_flows = active_flows;

    /* 客户端排序 */
    qsort(g_clients, g_clients_count, sizeof(struct client_stat), client_cmp);

    /* 保存当前快照作为下一次差分基线 */
    memcpy(g_prev_conns, g_curr_conns, sizeof(struct conn_info) * g_curr_conns_count);
    g_prev_conns_count = g_curr_conns_count;
}

/* 渲染 TUI 界面 */
static void render_tui(double interval, int limit) {
    const char *sort_labels[] = {"Down Speed [DESC]", "Up Speed [DESC]", "Total Down [DESC]", "Active Conns [DESC]"};
    char down_spd[16], down_bit[16], up_spd[16], up_bit[16];
    char rx_tot[16], tx_tot[16];
    char bar_down[128], bar_up[128];

    format_speed(g_wan.down_speed, down_spd, sizeof(down_spd));
    format_bitrate(g_wan.down_speed, down_bit, sizeof(down_bit));
    format_speed(g_wan.up_speed, up_spd, sizeof(up_spd));
    format_bitrate(g_wan.up_speed, up_bit, sizeof(up_bit));

    format_bytes(g_wan.total_down, rx_tot, sizeof(rx_tot));
    format_bytes(g_wan.total_up, tx_tot, sizeof(tx_tot));

    double down_ratio = ((g_wan.down_speed * 8.0) / 1000000.0) / 1000.0; /* 1000Mbps 基准 */
    double up_ratio = ((g_wan.up_speed * 8.0) / 1000000.0) / 100.0;     /* 100Mbps 基准 */

    render_progress_bar(down_ratio, 30, COLOR_GREEN, bar_down, sizeof(bar_down));
    render_progress_bar(up_ratio, 30, COLOR_CYAN, bar_up, sizeof(bar_up));

    printf(CURSOR_HOME);

    if (!g_wide_view) {
        /* 100 列黄金紧凑模式 */
        printf("%s====================================================================================================%s\n", COLOR_CYAN, COLOR_RESET);
        printf(" %sLibWrt NSS Hardware Traffic Monitor (ecmtop)%s                                  [Interval: %.1fs]%s%s\n",
               COLOR_BOLD COLOR_WHITE, COLOR_RESET, interval, g_paused ? " " COLOR_YELLOW "[PAUSED]" COLOR_RESET : "", COLOR_RESET);
        printf("%s====================================================================================================%s\n\n", COLOR_CYAN, COLOR_RESET);

        printf(" %sWAN Status (NSS Hardware Offloaded)%s\n", COLOR_BOLD COLOR_YELLOW, COLOR_RESET);
        printf("   %sRX (Down):%s  %s  (%s)   [%s%s]  %5.1f%%\n",
               COLOR_BOLD COLOR_GREEN, COLOR_RESET, down_spd, down_bit, bar_down, COLOR_RESET, (down_ratio > 1.0 ? 1.0 : down_ratio) * 100.0);
        printf("   %sTX (Up):  %s  %s  (%s)   [%s%s]  %5.1f%%\n\n",
               COLOR_BOLD COLOR_CYAN, COLOR_RESET, up_spd, up_bit, bar_up, COLOR_RESET, (up_ratio > 1.0 ? 1.0 : up_ratio) * 100.0);

        printf("   Total RX: %s   |   Total TX: %s   |   NSS Active Flows: %-5d\n",
               rx_tot, tx_tot, g_wan.active_flows);
        printf("%s----------------------------------------------------------------------------------------------------%s\n", COLOR_CYAN, COLOR_RESET);

        printf(" %sClient Real-Time Traffic Ranking%s (Sorted by: %s%s%s)\n\n",
               COLOR_BOLD COLOR_WHITE, COLOR_RESET, COLOR_YELLOW, sort_labels[g_sort_mode], COLOR_RESET);

        printf("   %s%-3s  %-16s  %-17s  %12s  %12s  %11s  %7s  %6s%s\n",
               COLOR_BOLD, "No.", "Client IP", "MAC Address", "Down Speed", "Up Speed", "Total Down", "Conns", "Ratio", COLOR_RESET);
        printf("   ---  ----------------  -----------------  ------------  ------------  -----------  -------  ------\n");

        int count = g_clients_count < limit ? g_clients_count : limit;
        for (int i = 0; i < count; i++) {
            struct client_stat *cs = &g_clients[i];
            char c_down[16], c_up[16], c_tot[16];
            format_speed(cs->down_speed, c_down, sizeof(c_down));
            format_speed(cs->up_speed, c_up, sizeof(c_up));
            format_bytes(cs->total_down, c_tot, sizeof(c_tot));

            double ratio = 0.0;
            if (g_wan.down_speed > 0.0) {
                ratio = (cs->down_speed / g_wan.down_speed) * 100.0;
            }
            if (ratio > 100.0) ratio = 100.0;

            printf("   %02d   %-16s  %-17s  %s%s%s  %s%s%s  %s  %7d  %5.1f%%\n",
                   i + 1, cs->display_ip, cs->mac,
                   COLOR_GREEN, c_down, COLOR_RESET,
                   COLOR_CYAN, c_up, COLOR_RESET,
                   c_tot, cs->active_conns, ratio);
        }

        for (int i = count; i < limit; i++) {
            printf("%100s\n", "");
        }

        printf("%s----------------------------------------------------------------------------------------------------%s\n", COLOR_CYAN, COLOR_RESET);
        printf("   %s[q]%s Quit | %s[s]%s Sort | %s[v]%s View:Compact | %s[r]%s Reset | %s[Space]%s Pause\n",
               COLOR_BOLD COLOR_RED, COLOR_RESET,
               COLOR_BOLD COLOR_YELLOW, COLOR_RESET,
               COLOR_BOLD COLOR_CYAN, COLOR_RESET,
               COLOR_BOLD COLOR_MAGENTA, COLOR_RESET,
               COLOR_BOLD COLOR_GREEN, COLOR_RESET);
        printf("%s====================================================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    } else {
        /* 124 列宽屏 IPv6 完整模式 */
        printf("%s============================================================================================================================%s\n", COLOR_CYAN, COLOR_RESET);
        printf(" %sLibWrt NSS Hardware Traffic Monitor (ecmtop)%s [IPv6 Wide View]                         [Interval: %.1fs]%s%s\n",
               COLOR_BOLD COLOR_WHITE, COLOR_RESET, interval, g_paused ? " " COLOR_YELLOW "[PAUSED]" COLOR_RESET : "", COLOR_RESET);
        printf("%s============================================================================================================================%s\n\n", COLOR_CYAN, COLOR_RESET);

        printf(" %sWAN Status (NSS Hardware Offloaded)%s\n", COLOR_BOLD COLOR_YELLOW, COLOR_RESET);
        printf("   %sRX (Down):%s  %s  (%s)   [%s%s]  %5.1f%%\n",
               COLOR_BOLD COLOR_GREEN, COLOR_RESET, down_spd, down_bit, bar_down, COLOR_RESET, (down_ratio > 1.0 ? 1.0 : down_ratio) * 100.0);
        printf("   %sTX (Up):  %s  %s  (%s)   [%s%s]  %5.1f%%\n\n",
               COLOR_BOLD COLOR_CYAN, COLOR_RESET, up_spd, up_bit, bar_up, COLOR_RESET, (up_ratio > 1.0 ? 1.0 : up_ratio) * 100.0);

        printf("   Total RX: %s   |   Total TX: %s   |   NSS Active Flows: %-5d\n",
               rx_tot, tx_tot, g_wan.active_flows);
        printf("%s----------------------------------------------------------------------------------------------------------------------------%s\n", COLOR_CYAN, COLOR_RESET);

        printf(" %sClient Real-Time Traffic Ranking%s (Sorted by: %s%s%s)\n\n",
               COLOR_BOLD COLOR_WHITE, COLOR_RESET, COLOR_YELLOW, sort_labels[g_sort_mode], COLOR_RESET);

        printf("   %s%-3s  %-39s  %-17s  %12s  %12s  %11s  %7s  %6s%s\n",
               COLOR_BOLD, "No.", "Client Full IP (IPv4 / IPv6)", "MAC Address", "Down Speed", "Up Speed", "Total Down", "Conns", "Ratio", COLOR_RESET);
        printf("   ---  ---------------------------------------  -----------------  ------------  ------------  -----------  -------  ------\n");

        int count = g_clients_count < limit ? g_clients_count : limit;
        for (int i = 0; i < count; i++) {
            struct client_stat *cs = &g_clients[i];
            char c_down[16], c_up[16], c_tot[16];
            format_speed(cs->down_speed, c_down, sizeof(c_down));
            format_speed(cs->up_speed, c_up, sizeof(c_up));
            format_bytes(cs->total_down, c_tot, sizeof(c_tot));

            double ratio = 0.0;
            if (g_wan.down_speed > 0.0) {
                ratio = (cs->down_speed / g_wan.down_speed) * 100.0;
            }
            if (ratio > 100.0) ratio = 100.0;

            printf("   %02d   %-39s  %-17s  %s%s%s  %s%s%s  %s  %7d  %5.1f%%\n",
                   i + 1, cs->full_ip, cs->mac,
                   COLOR_GREEN, c_down, COLOR_RESET,
                   COLOR_CYAN, c_up, COLOR_RESET,
                   c_tot, cs->active_conns, ratio);
        }

        for (int i = count; i < limit; i++) {
            printf("%124s\n", "");
        }

        printf("%s----------------------------------------------------------------------------------------------------------------------------%s\n", COLOR_CYAN, COLOR_RESET);
        printf("   %s[q]%s Quit | %s[s]%s Sort | %s[v]%s View:Wide | %s[r]%s Reset | %s[Space]%s Pause\n",
               COLOR_BOLD COLOR_RED, COLOR_RESET,
               COLOR_BOLD COLOR_YELLOW, COLOR_RESET,
               COLOR_BOLD COLOR_CYAN, COLOR_RESET,
               COLOR_BOLD COLOR_MAGENTA, COLOR_RESET,
               COLOR_BOLD COLOR_GREEN, COLOR_RESET);
        printf("%s============================================================================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    }
    fflush(stdout);
}

/* 一次性纯文本输出 */
static void print_once(int limit) {
    char down_spd[16], down_bit[16], up_spd[16], up_bit[16];
    char rx_tot[16], tx_tot[16];

    format_speed(g_wan.down_speed, down_spd, sizeof(down_spd));
    format_bitrate(g_wan.down_speed, down_bit, sizeof(down_bit));
    format_speed(g_wan.up_speed, up_spd, sizeof(up_spd));
    format_bitrate(g_wan.up_speed, up_bit, sizeof(up_bit));

    format_bytes(g_wan.total_down, rx_tot, sizeof(rx_tot));
    format_bytes(g_wan.total_up, tx_tot, sizeof(tx_tot));

    printf("=== WAN Status ===\n");
    printf("Down Speed: %s (%s) | Total RX: %s\n", down_spd, down_bit, rx_tot);
    printf("Up Speed:   %s (%s) | Total TX: %s\n", up_spd, up_bit, tx_tot);
    printf("Active Flows: %d\n\n", g_wan.active_flows);

    printf("=== Client Traffic Ranking ===\n");
    printf("No.  Client IP                                MAC Address        Down Speed    Up Speed  Total Down    Conns\n");
    printf("------------------------------------------------------------------------------------------------------------\n");

    int count = g_clients_count < limit ? g_clients_count : limit;
    for (int i = 0; i < count; i++) {
        struct client_stat *cs = &g_clients[i];
        char c_down[16], c_up[16], c_tot[16];
        format_speed(cs->down_speed, c_down, sizeof(c_down));
        format_speed(cs->up_speed, c_up, sizeof(c_up));
        format_bytes(cs->total_down, c_tot, sizeof(c_tot));

        printf("%02d   %-39s  %-17s  %s  %s  %s  %7d\n",
               i + 1, cs->full_ip, cs->mac, c_down, c_up, c_tot, cs->active_conns);
    }
}

/* 一次性 JSON 输出 */
static void print_json(double interval) {
    printf("{\n");
    printf("  \"interval\": %.2f,\n", interval);
    printf("  \"wan\": {\n");
    printf("    \"down_speed\": %.2f,\n", g_wan.down_speed);
    printf("    \"up_speed\": %.2f,\n", g_wan.up_speed);
    printf("    \"total_down\": %" PRIu64 ",\n", g_wan.total_down);
    printf("    \"total_up\": %" PRIu64 ",\n", g_wan.total_up);
    printf("    \"active_flows\": %d\n", g_wan.active_flows);
    printf("  },\n");
    printf("  \"clients\": [\n");

    for (int i = 0; i < g_clients_count; i++) {
        struct client_stat *cs = &g_clients[i];
        printf("    {\n");
        printf("      \"ip\": \"%s\",\n", cs->full_ip);
        printf("      \"mac\": \"%s\",\n", cs->mac);
        printf("      \"down_speed\": %.2f,\n", cs->down_speed);
        printf("      \"up_speed\": %.2f,\n", cs->up_speed);
        printf("      \"total_down\": %" PRIu64 ",\n", cs->total_down);
        printf("      \"total_up\": %" PRIu64 ",\n", cs->total_up);
        printf("      \"active_conns\": %d\n", cs->active_conns);
        printf("    }%s\n", (i == g_clients_count - 1) ? "" : ",");
    }

    printf("  ]\n");
    printf("}\n");
}

int main(int argc, char *argv[]) {
    double interval = 1.0;
    int limit = 10;
    bool json_mode = false;
    bool once_mode = false;
    const char *dev_path = "/dev/ecm_state";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interval = atof(argv[++i]);
            if (interval <= 0.1) interval = 0.1;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            limit = atoi(argv[++i]);
            if (limit <= 0) limit = 10;
        } else if (strcmp(argv[i], "-json") == 0) {
            json_mode = true;
        } else if (strcmp(argv[i], "-once") == 0) {
            once_mode = true;
        } else if (strcmp(argv[i], "-dev") == 0 && i + 1 < argc) {
            dev_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: ecmtop [-i interval] [-n clients] [-once] [-json] [-dev path]\n");
            return 0;
        }
    }

    if (ensure_device(dev_path) != 0) {
        fprintf(stderr, "Error: cannot access or create %s (is kmod-qca-nss-ecm loaded?)\n", dev_path);
        return 1;
    }

    /* 首次打桩采样建立基准 */
    if (read_ecm_state(dev_path) != 0) {
        fprintf(stderr, "Error reading %s\n", dev_path);
        return 1;
    }
    collect_stats(interval);

    /* 一次性输出模式 */
    if (json_mode || once_mode) {
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        usleep((useconds_t)(interval * 1000000.0));
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double actual_int = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        if (actual_int <= 0.0) actual_int = interval;

        if (read_ecm_state(dev_path) != 0) {
            fprintf(stderr, "Error reading %s\n", dev_path);
            return 1;
        }
        collect_stats(actual_int);
        if (json_mode) {
            print_json(actual_int);
        } else {
            print_once(limit);
        }
        return 0;
    }

    /* 交互式 TUI 模式 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    setup_terminal();

    render_tui(interval, limit);

    struct timespec ts_last;
    clock_gettime(CLOCK_MONOTONIC, &ts_last);

    while (g_running) {
        /* 使用 poll 进行精确超时监听按键，杜绝时钟漂移 */
        struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN, .revents = 0 };
        int poll_ret = poll(&pfd, 1, 100); /* 最多等待 100ms */

        if (poll_ret > 0 && (pfd.revents & POLLIN)) {
            char ch = 0;
            if (read(STDIN_FILENO, &ch, 1) > 0) {
                if (ch == 'q' || ch == 'Q' || ch == 3) {
                    break;
                } else if (ch == 's' || ch == 'S') {
                    g_sort_mode = (sort_mode_t)((g_sort_mode + 1) % SORT_MAX);
                    render_tui(interval, limit);
                } else if (ch == 'v' || ch == 'V') {
                    g_wide_view = !g_wide_view;
                    printf(CLEAR_SCREEN);
                    render_tui(interval, limit);
                } else if (ch == 'r' || ch == 'R') {
                    memset(g_client_totals, 0, sizeof(g_client_totals));
                    g_wan.total_down = 0;
                    g_wan.total_up = 0;
                    render_tui(interval, limit);
                } else if (ch == ' ') {
                    g_paused = !g_paused;
                    render_tui(interval, limit);
                }
            }
        }

        /* 检查真实流逝时间 */
        struct timespec ts_cur;
        clock_gettime(CLOCK_MONOTONIC, &ts_cur);
        double actual_elapsed = (ts_cur.tv_sec - ts_last.tv_sec) + (ts_cur.tv_nsec - ts_last.tv_nsec) / 1e9;

        if (!g_paused && actual_elapsed >= interval) {
            ts_last = ts_cur;
            if (read_ecm_state(dev_path) == 0) {
                collect_stats(actual_elapsed);
                render_tui(interval, limit);
            }
        }
    }

    restore_terminal();
    return 0;
}
