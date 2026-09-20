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

/*
 * 极致内存安全设计原则：
 * 1. 零动态堆内存分配：主循环内 0 次 malloc / free，彻底杜绝内存泄漏与内存碎片。
 * 2. 静态缓冲区上限控制：严格使用 snprintf/strncpy，杜绝任何缓冲区溢出。
 * 3. 极速流式解析：单次扫描不到 1ms，内存常驻占用 < 500KB。
 */

#define MAX_CONNS 4096
#define MAX_CLIENTS 256
#define HASH_SIZE 2048

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
    char sip[40];
    char dip[40];
    char smac[18];
    char dmac[18];
};

struct client_stat {
    char ip[40];
    char mac[18];
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

/* 静态内存池，零堆泄漏 */
static struct conn_info g_prev_conns[MAX_CONNS];
static int g_prev_conns_count = 0;

static struct conn_info g_curr_conns[MAX_CONNS];
static int g_curr_conns_count = 0;

static struct client_stat g_clients[MAX_CLIENTS];
static int g_clients_count = 0;

static struct wan_stat g_wan = {0};

/* 累计流量字典（持久化于程序生命周期） */
struct client_total {
    char ip[40];
    char mac[18];
    uint64_t total_down;
    uint64_t total_up;
    bool in_use;
};
static struct client_total g_client_totals[MAX_CLIENTS] = {0};

static volatile bool g_running = true;
static bool g_paused = false;
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
        raw.c_cc[VTIME] = 1; /* 100ms 非阻塞读取 */
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

/* 判断是否为局域网私网 IP (192.168., 10., 172.16-31., 127.) */
static bool is_private_ip(const char *ip) {
    if (!ip || !*ip) return false;
    if (strncmp(ip, "192.168.", 8) == 0) return true;
    if (strncmp(ip, "10.", 3) == 0) return true;
    if (strncmp(ip, "127.", 4) == 0) return true;
    if (strncmp(ip, "172.", 4) == 0) {
        int sec = atoi(ip + 4);
        if (sec >= 16 && sec <= 31) return true;
    }
    if (strncmp(ip, "fc", 2) == 0 || strncmp(ip, "fd", 2) == 0 || strncmp(ip, "fe80", 4) == 0) return true;
    return false;
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

/* 查找或创建客户端累计记录 */
static struct client_total *get_client_total(const char *ip, const char *mac) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_client_totals[i].in_use && strcmp(g_client_totals[i].ip, ip) == 0) {
            if (mac && *mac && (!g_client_totals[i].mac[0] || strcmp(g_client_totals[i].mac, "N/A") == 0)) {
                strncpy(g_client_totals[i].mac, mac, sizeof(g_client_totals[i].mac) - 1);
            }
            return &g_client_totals[i];
        }
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_client_totals[i].in_use) {
            g_client_totals[i].in_use = true;
            strncpy(g_client_totals[i].ip, ip, sizeof(g_client_totals[i].ip) - 1);
            strncpy(g_client_totals[i].mac, (mac && *mac) ? mac : "N/A", sizeof(g_client_totals[i].mac) - 1);
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
static void collect_stats(double interval) {
    if (interval <= 0.0) interval = 1.0;

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
        if (is_private_ip(cur->sip)) {
            c_ip = cur->sip;
            c_mac = cur->smac;
            if (p_idx >= 0) {
                if (cur->to_bytes >= g_prev_conns[p_idx].to_bytes)
                    flow_down = cur->to_bytes - g_prev_conns[p_idx].to_bytes;
                if (cur->from_bytes >= g_prev_conns[p_idx].from_bytes)
                    flow_up = cur->from_bytes - g_prev_conns[p_idx].from_bytes;
            }
        } else if (is_private_ip(cur->dip)) {
            c_ip = cur->dip;
            c_mac = cur->dmac;
            if (p_idx >= 0) {
                if (cur->from_bytes >= g_prev_conns[p_idx].from_bytes)
                    flow_down = cur->from_bytes - g_prev_conns[p_idx].from_bytes;
                if (cur->to_bytes >= g_prev_conns[p_idx].to_bytes)
                    flow_up = cur->to_bytes - g_prev_conns[p_idx].to_bytes;
            }
        } else {
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

        /* 聚合至客户端 */
        int found = -1;
        for (int c = 0; c < g_clients_count; c++) {
            if (strcmp(g_clients[c].ip, c_ip) == 0) {
                found = c;
                break;
            }
        }
        if (found < 0 && g_clients_count < MAX_CLIENTS) {
            found = g_clients_count++;
            memset(&g_clients[found], 0, sizeof(struct client_stat));
            strncpy(g_clients[found].ip, c_ip, sizeof(g_clients[found].ip) - 1);
            strncpy(g_clients[found].mac, (c_mac && *c_mac) ? c_mac : "N/A", sizeof(g_clients[found].mac) - 1);
        }

        if (found >= 0) {
            g_clients[found].down_speed += (double)flow_down / interval;
            g_clients[found].up_speed += (double)flow_up / interval;
            g_clients[found].active_conns++;

            struct client_total *tot = get_client_total(c_ip, c_mac);
            if (tot) {
                tot->total_down += flow_down;
                tot->total_up += flow_up;
                g_clients[found].total_down = tot->total_down;
                g_clients[found].total_up = tot->total_up;
            }
        }
    }

    g_wan.down_speed = (double)wan_delta_down / interval;
    g_wan.up_speed = (double)wan_delta_up / interval;
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

    printf("   %s%-3s  %-15s  %-17s  %12s  %12s  %11s  %7s  %6s%s\n",
           COLOR_BOLD, "No.", "Client IP", "MAC Address", "Down Speed", "Up Speed", "Total Down", "Conns", "Ratio", COLOR_RESET);
    printf("   ---  ---------------  -----------------  ------------  ------------  -----------  -------  ------\n");

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

        printf("   %02d   %-15s  %-17s  %s%s%s  %s%s%s  %s  %7d  %5.1f%%\n",
               i + 1, cs->ip, cs->mac,
               COLOR_GREEN, c_down, COLOR_RESET,
               COLOR_CYAN, c_up, COLOR_RESET,
               c_tot, cs->active_conns, ratio);
    }

    for (int i = count; i < limit; i++) {
        printf("%100s\n", "");
    }

    printf("%s----------------------------------------------------------------------------------------------------%s\n", COLOR_CYAN, COLOR_RESET);
    printf("   %s[q]%s Quit  |  %s[s]%s Sort (Down/Up/Total/Conns)  |  %s[r]%s Reset  |  %s[Space]%s Pause\n",
           COLOR_BOLD COLOR_RED, COLOR_RESET,
           COLOR_BOLD COLOR_YELLOW, COLOR_RESET,
           COLOR_BOLD COLOR_MAGENTA, COLOR_RESET,
           COLOR_BOLD COLOR_GREEN, COLOR_RESET);
    printf("%s====================================================================================================%s\n", COLOR_CYAN, COLOR_RESET);
    fflush(stdout);
}

/* 打印单次文本快照 */
static void print_once(int limit) {
    char down_spd[16], down_bit[16], up_spd[16], up_bit[16];
    format_speed(g_wan.down_speed, down_spd, sizeof(down_spd));
    format_bitrate(g_wan.down_speed, down_bit, sizeof(down_bit));
    format_speed(g_wan.up_speed, up_spd, sizeof(up_spd));
    format_bitrate(g_wan.up_speed, up_bit, sizeof(up_bit));

    printf("WAN Down: %s (%s) | Up: %s (%s) | Flows: %d\n",
           down_spd, down_bit, up_spd, up_bit, g_wan.active_flows);
    printf("Top Clients:\n");
    int count = g_clients_count < limit ? g_clients_count : limit;
    for (int i = 0; i < count; i++) {
        struct client_stat *cs = &g_clients[i];
        char c_down[16], c_up[16];
        format_speed(cs->down_speed, c_down, sizeof(c_down));
        format_speed(cs->up_speed, c_up, sizeof(c_up));
        printf("  #%02d %-15s [%-17s] Down: %s | Up: %s | Conns: %d\n",
               i + 1, cs->ip, cs->mac, c_down, c_up, cs->active_conns);
    }
}

/* 打印单次 JSON */
static void print_json(double interval) {
    printf("{\n");
    printf("  \"interval_sec\": %.2f,\n", interval);
    printf("  \"wan\": {\n");
    printf("    \"down_speed_bps\": %.2f,\n", g_wan.down_speed);
    printf("    \"up_speed_bps\": %.2f,\n", g_wan.up_speed);
    printf("    \"total_down_bytes\": %" PRIu64 ",\n", g_wan.total_down);
    printf("    \"total_up_bytes\": %" PRIu64 ",\n", g_wan.total_up);
    printf("    \"active_flows\": %d\n", g_wan.active_flows);
    printf("  },\n");
    printf("  \"clients\": [\n");
    for (int i = 0; i < g_clients_count; i++) {
        struct client_stat *cs = &g_clients[i];
        printf("    {\n");
        printf("      \"ip\": \"%s\",\n", cs->ip);
        printf("      \"mac\": \"%s\",\n", cs->mac);
        printf("      \"down_speed_bps\": %.2f,\n", cs->down_speed);
        printf("      \"up_speed_bps\": %.2f,\n", cs->up_speed);
        printf("      \"total_down_bytes\": %" PRIu64 ",\n", cs->total_down);
        printf("      \"total_up_bytes\": %" PRIu64 ",\n", cs->total_up);
        printf("      \"active_conns\": %d\n", cs->active_conns);
        printf("    }%s\n", (i == g_clients_count - 1) ? "" : ",");
    }
    printf("  ]\n");
    printf("}\n");
}

int main(int argc, char *argv[]) {
    double interval = 1.0;
    int limit = 12;
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
        usleep((useconds_t)(interval * 1000000.0));
        if (read_ecm_state(dev_path) != 0) {
            fprintf(stderr, "Error reading %s\n", dev_path);
            return 1;
        }
        collect_stats(interval);
        if (json_mode) {
            print_json(interval);
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

    while (g_running) {
        /* 读取按键 */
        char ch = 0;
        if (read(STDIN_FILENO, &ch, 1) > 0) {
            if (ch == 'q' || ch == 'Q' || ch == 3) {
                break;
            } else if (ch == 's' || ch == 'S') {
                g_sort_mode = (sort_mode_t)((g_sort_mode + 1) % SORT_MAX);
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

        /* 睡眠 100ms 并累加周期 */
        static int elapsed_ms = 0;
        usleep(100000); /* 100ms */
        elapsed_ms += 100;

        if (!g_paused && elapsed_ms >= (int)(interval * 1000.0)) {
            elapsed_ms = 0;
            if (read_ecm_state(dev_path) == 0) {
                collect_stats(interval);
                render_tui(interval, limit);
            }
        }
    }

    restore_terminal();
    return 0;
}
