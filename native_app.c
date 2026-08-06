/* WiFiFiles native InkView control panel for PocketBook 650.
 * Freestanding ARM EABI build: only depends on libinkview.so from firmware.
 */

#define WF_VERSION "0.7.30"

typedef unsigned int uint32_t;
typedef unsigned long size_t;
typedef int (*iv_handler)(int, int, int);
typedef void (*iv_keyboardhandler)(char *);
typedef void (*iv_timerproc)(void);
typedef struct ifont_s ifont;
typedef struct iv_netinfo_s {
    int connected;
    char name[64];
    char device[64];
    char security[64];
    char prefix[64];
    int index;
    int atime;
    int speed;
    int reserved_0e;
    unsigned long bytes_in;
    unsigned long bytes_out;
    unsigned long packets_in;
    unsigned long packets_out;
} iv_netinfo;

/* InkView ABI (SDK 4.8/firmware 5.x subset). */
extern void InkViewMain(iv_handler h);
extern void CloseApp(void);
extern int ScreenWidth(void);
extern int ScreenHeight(void);
extern void SetPanelType(int type);
typedef struct ibitmap_s ibitmap;
extern int DrawPanel(const ibitmap *icon, const char *text, const char *title, int percent);
extern void SetOrientation(int n);
extern void ClearScreen(void);
extern void DrawLine(int x1, int y1, int x2, int y2, int color);
extern void DrawRect(int x, int y, int w, int h, int color);
extern void FillArea(int x, int y, int w, int h, int color);
extern ifont *OpenFont(const char *name, int size, int aa);
extern void CloseFont(ifont *f);
extern void SetFont(ifont *font, int color);
extern char *DrawTextRect(int x, int y, int w, int h, const char *s, int flags);
extern void FullUpdate(void);
extern void PartialUpdate(int x, int y, int w, int h);
extern void OpenKeyboard(const char *title, char *buffer, int maxlen, int flags, iv_keyboardhandler hproc);
extern void Message(int icon, const char *title, const char *text, int timeout);
extern void ShowHourglass(void);
extern void HideHourglass(void);
extern int NetConnect(const char *name);
extern int NetConnectSilent(const char *name) __attribute__((weak));
extern int NetDisconnect(void) __attribute__((weak));
extern int WiFiPower(int status) __attribute__((weak));
extern iv_netinfo *NetInfo(void) __attribute__((weak));
extern void SetHardTimer(const char *name, iv_timerproc tproc, int ms);
extern void ClearTimerByName(const char *name);

#define EVT_INIT 21
#define EVT_EXIT 22
#define EVT_SHOW 23
#define EVT_KEYPRESS 25
#define EVT_POINTERUP 29
#define EVT_TOUCHUP 40

#define KEY_BACK 0x1b
#define KEY_OK 0x0a
#define KEY_UP 0x11
#define KEY_DOWN 0x12
#define KEY_LEFT 0x13
#define KEY_RIGHT 0x14

#define BLACK 0x000000
#define DGRAY 0x555555
#define LGRAY 0xaaaaaa
#define VLGRAY 0xe5e5e5
#define WHITE 0xffffff

#define ALIGN_LEFT 1
#define ALIGN_CENTER 2
#define ALIGN_RIGHT 4
#define VALIGN_TOP 16
#define VALIGN_MIDDLE 32
#define DOTS 512

#define KBD_NORMAL 0
#define KBD_ENTEXT 1
#define KBD_NUMERIC 4
#define KBD_PASSWORD 0x100
#define ICON_INFORMATION 1
#define ICON_WARNING 3
#define ICON_ERROR 4
#define PANEL_ENABLED 2

#define SYS_EXIT 1
#define SYS_FORK 2
#define SYS_READ 3
#define SYS_WRITE 4
#define SYS_OPEN 5
#define SYS_CLOSE 6
#define SYS_WAIT4 114
#define SYS_UNLINK 10
#define SYS_EXECVE 11
#define SYS_LSEEK 19
#define SYS_KILL 37
#define SYS_RENAME 38
#define SYS_NANOSLEEP 162

#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000
#define SEEK_SET 0
#define SEEK_END 2

static char **g_envp;
static ifont *font_title;
static ifont *font_main;
static ifont *font_small;
static ifont *font_help;
static ifont *font_status;
static ifont *font_block_title;
static ifont *font_instruction;
static ifont *font_instruction_title;
static int screen_w = 758;
static int screen_h = 1024;
static int selected = 0;
static int dirty = 0;
static int edit_mode = 0;
static int wifi_refresh_in_progress = 0;
static int wifi_refresh_attempt = 0;
static int wifi_refresh_result = 0;
static int wifi_refresh_existing_connection = 0;
static int startup_wifi_refresh_pending = 0;
static int wifi_watch_active = 0;
static int open_wifi_warning_pending = 0;
static char wifi_name[64];
static char wifi_security[64];
static char warned_open_wifi[64];
static int wifi_security_known = 0;
static int wifi_is_open = 0;
static int instruction_font_scale = 1;

#define MAX_FOLDER_DIRS 80
#define FOLDER_PAGE_SIZE 9
#define QR_MAX_SIZE 41
static char folder_current[256];
static char folder_parent[256];
static char folder_dirs[MAX_FOLDER_DIRS][256];
static char folder_names[MAX_FOLDER_DIRS][128];
static char folder_error[192];
static int folder_count = 0;
static int folder_total = 0;
static int folder_page = 0;
static int folder_picker_skip = 0;
static char qr_target[256];
static char qr_url[160];
static char qr_access_mode[12] = "safe";
static char qr_rows[QR_MAX_SIZE][QR_MAX_SIZE + 1];
static int qr_size = 0;
static char helper_data[49152];
/* PocketBook firmware gives native applications a small stack. These buffers
 * are used during the nested startup path, so keep them in static storage. */
static unsigned char runtime_extract_buffer[8192];
static char runtime_upgrade_state_buffer[2048];
static char native_state_buffer[8192];
static char last_logged_state_buffer[8192];
static int runtime_server_ready = 0;

static const char SELF_PATH[] = "/proc/self/exe";
static const char SERVER_PATH[] = "/tmp/WiFiFiles.server";
static const char SERVER_STAGE_PATH[] = "/tmp/WiFiFiles.server.new";
static const char SERVER_MARK_PATH[] = "/tmp/WiFiFiles.server.mark";
static const char LEGACY_PREP_LOG_PATH[] = "/mnt/ext1/WiFiFiles_preparation.log";
static const char EMBED_MAGIC[] = "WFSRV722";
#define EMBED_FOOTER_SIZE 16
static const char STATE_PATH[] = "/tmp/WiFiFiles/native_state.ini";
static const char APPLY_PATH[] = "/tmp/WiFiFiles/native_apply.ini";
static const char LANGUAGE_PATH[] = "/tmp/WiFiFiles/native_language.ini";
static const char FONT_PATH[] = "/mnt/ext1/system/config/WiFiFiles_font.ini";
static const char LOG_PATH[] = "/mnt/ext1/WiFiFiles.log";
static const char FOLDER_REQUEST_PATH[] = "/tmp/WiFiFiles/native_folder_request.ini";
static const char FOLDER_LIST_PATH[] = "/tmp/WiFiFiles/native_folder_list.ini";
static const char MOBILE_REQUEST_PATH[] = "/tmp/WiFiFiles/native_mobile_request.ini";
static const char MOBILE_QR_PATH[] = "/tmp/WiFiFiles/native_mobile_qr.ini";
static const char MOBILE_DEFAULT_PATH[] = "/tmp/WiFiFiles/native_mobile_default.ini";
static const char UPDATE_STATUS_PATH[] = "/tmp/WiFiFiles/update_status.ini";

struct app_state {
    int running;
    int pid;
    char ip[64];
    int http_enabled;
    int http_running;
    int http_port;
    char http_error[128];
    int ftp_enabled;
    int ftp_running;
    int ftp_port;
    char ftp_error[128];
    int smb_enabled;
    int smb_running;
    int smb_port;
    int smb_credentials_ready;
    char smb_error[192];
    int internal_enabled;
    int sd_enabled;
    int logging_enabled;
    char username[40];
    char language[8];
    int password_is_default;
    int uid;
    char default_target[256];
    char recent_targets[4][256];
    char free_internal[32];
    char free_sd[32];
    char message[192];
    int active_connections;
    int uploaded_total;
    int deleted_total;
    char recent_log[1024];
};

static struct app_state st;
static char password[132];
static char keyboard_buf[132];

static void log_line(const char *text);
static void draw_current(void);
static void start_wifi_refresh(void);
static int read_all(const char *path, char *buf, int cap);
static int ini_value(const char *data, const char *key, char *out, int cap);

/* Minimal freestanding helpers. */
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}
void *memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}
static int slen(const char *s) { int n = 0; if (!s) return 0; while (s[n]) n++; return n; }
static int seq(const char *a, const char *b) {
    int i = 0; if (!a || !b) return 0;
    while (a[i] && b[i] && a[i] == b[i]) i++;
    return a[i] == 0 && b[i] == 0;
}
static void scopy(char *dst, int cap, const char *src) {
    int i = 0; if (cap <= 0) return; if (!src) src = "";
    while (i < cap - 1 && src[i]) { dst[i] = src[i]; i++; }
    dst[i] = 0;
}
static void scat(char *dst, int cap, const char *src) {
    int n = slen(dst), i = 0; if (!src) return;
    while (n < cap - 1 && src[i]) dst[n++] = src[i++];
    dst[n] = 0;
}
static int starts(const char *s, const char *p) {
    int i = 0; while (p[i]) { if (s[i] != p[i]) return 0; i++; } return 1;
}
static char ascii_lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c; }
static int contains_ci(const char *text, const char *needle) {
    int i, j;
    if (!text || !needle || !needle[0]) return 0;
    for (i = 0; text[i]; i++) {
        for (j = 0; needle[j] && text[i + j] && ascii_lower(text[i + j]) == ascii_lower(needle[j]); j++) {}
        if (!needle[j]) return 1;
    }
    return 0;
}

static int atoi10(const char *s) {
    int n = 0, i = 0;
    if (!s) return 0;
    while (s[i] >= '0' && s[i] <= '9') { n = n * 10 + (s[i] - '0'); i++; }
    return n;
}

static void append_int(char *dst, int cap, int value) {
    char t[16]; int n = 0; unsigned int v;
    if (value < 0) { scat(dst, cap, "-"); v = (unsigned int)(-value); } else v = (unsigned int)value;
    if (v == 0) { scat(dst, cap, "0"); return; }
    while (v && n < 15) {
        unsigned int q = 0, rem = v;
        /* Division-free base-10 conversion. */
        while (rem >= 1000000000U) { rem -= 1000000000U; q += 100000000U; }
        while (rem >= 100000000U) { rem -= 100000000U; q += 10000000U; }
        while (rem >= 10000000U) { rem -= 10000000U; q += 1000000U; }
        while (rem >= 1000000U) { rem -= 1000000U; q += 100000U; }
        while (rem >= 100000U) { rem -= 100000U; q += 10000U; }
        while (rem >= 10000U) { rem -= 10000U; q += 1000U; }
        while (rem >= 1000U) { rem -= 1000U; q += 100U; }
        while (rem >= 100U) { rem -= 100U; q += 10U; }
        while (rem >= 10U) { rem -= 10U; q += 1U; }
        t[n++] = (char)('0' + rem);
        v = q;
    }
    while (n--) { char c[2]; c[0] = t[n]; c[1] = 0; scat(dst, cap, c); }
}

static int sys_open(const char *path, int flags, int mode) {
    register int r0 asm("r0") = (int)path;
    register int r1 asm("r1") = flags;
    register int r2 asm("r2") = mode;
    register int r7 asm("r7") = SYS_OPEN;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}
static int sys_read(int fd, void *buf, int count) {
    register int r0 asm("r0") = fd;
    register int r1 asm("r1") = (int)buf;
    register int r2 asm("r2") = count;
    register int r7 asm("r7") = SYS_READ;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}
static int sys_write(int fd, const void *buf, int count) {
    register int r0 asm("r0") = fd;
    register int r1 asm("r1") = (int)buf;
    register int r2 asm("r2") = count;
    register int r7 asm("r7") = SYS_WRITE;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}
static int sys_close(int fd) {
    register int r0 asm("r0") = fd;
    register int r7 asm("r7") = SYS_CLOSE;
    asm volatile("svc 0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}
static int sys_unlink(const char *path) {
    register int r0 asm("r0") = (int)path;
    register int r7 asm("r7") = SYS_UNLINK;
    asm volatile("svc 0" : "+r"(r0) : "r"(r7) : "memory");
    return r0;
}
static int sys_rename(const char *oldpath, const char *newpath) {
    register int r0 asm("r0") = (int)oldpath;
    register int r1 asm("r1") = (int)newpath;
    register int r7 asm("r7") = SYS_RENAME;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r7) : "memory");
    return r0;
}
static int sys_kill(int pid, int sig) {
    register int r0 asm("r0") = pid;
    register int r1 asm("r1") = sig;
    register int r7 asm("r7") = SYS_KILL;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r7) : "memory");
    return r0;
}
struct tiny_timespec { int tv_sec; int tv_nsec; };
static int sys_sleep_100ms(void) {
    struct tiny_timespec ts;
    register int r0 asm("r0");
    register int r1 asm("r1") = 0;
    register int r7 asm("r7") = SYS_NANOSLEEP;
    ts.tv_sec = 0;
    ts.tv_nsec = 100000000;
    r0 = (int)&ts;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r7) : "memory");
    return r0;
}
static int sys_lseek(int fd, int offset, int whence) {
    register int r0 asm("r0") = fd;
    register int r1 asm("r1") = offset;
    register int r2 asm("r2") = whence;
    register int r7 asm("r7") = SYS_LSEEK;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}
static int sys_fork(void) {
    register int r0 asm("r0");
    register int r7 asm("r7") = SYS_FORK;
    asm volatile("svc 0" : "=r"(r0) : "r"(r7) : "memory");
    return r0;
}
static int sys_execve(const char *path, char *const argv[], char *const envp[]) {
    register int r0 asm("r0") = (int)path;
    register int r1 asm("r1") = (int)argv;
    register int r2 asm("r2") = (int)envp;
    register int r7 asm("r7") = SYS_EXECVE;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
    return r0;
}
static int sys_wait4(int pid, int *status) {
    register int r0 asm("r0") = pid;
    register int r1 asm("r1") = (int)status;
    register int r2 asm("r2") = 0;
    register int r3 asm("r3") = 0;
    register int r7 asm("r7") = SYS_WAIT4;
    asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r3), "r"(r7) : "memory");
    return r0;
}
static void sys_exit(int code) {
    register int r0 asm("r0") = code;
    register int r7 asm("r7") = SYS_EXIT;
    asm volatile("svc 0" :: "r"(r0), "r"(r7) : "memory");
    for (;;) {}
}

static int prep_started = 0;
static void migrate_legacy_prep_log(void) {
    char buffer[1024];
    int src = sys_open(LEGACY_PREP_LOG_PATH, O_RDONLY, 0);
    int dst, n;
    if (src < 0) return;
    dst = sys_open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (dst >= 0) {
        const char *h = "\n===== imported legacy preparation log =====\n";
        sys_write(dst, h, slen(h));
        while ((n = sys_read(src, buffer, sizeof(buffer))) > 0) sys_write(dst, buffer, n);
        { const char *e = "\n===== end imported legacy preparation log =====\n"; sys_write(dst, e, slen(e)); }
        sys_close(dst);
    }
    sys_close(src);
    sys_unlink(LEGACY_PREP_LOG_PATH);
}
static void prep_log_reset(void) {
    int fd;
    migrate_legacy_prep_log();
    fd = sys_open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { const char *h = "\n===== WiFiFiles " WF_VERSION " runtime preparation =====\n"; sys_write(fd, h, slen(h)); sys_close(fd); }
    prep_started = 1;
}
static void prep_log_raw(const char *text) {
    int fd = sys_open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { sys_write(fd, text, slen(text)); sys_write(fd, "\n", 1); sys_close(fd); }
}
static void prep_log_int(const char *name, int value) {
    char line[128]; line[0] = 0; scat(line, sizeof(line), name); scat(line, sizeof(line), "="); append_int(line, sizeof(line), value); prep_log_raw(line);
}
static void prep_log_file_snapshot(const char *label, const char *path) {
    char marker[160];
    char buffer[1024];
    int src, dst, n, total = 0;
    marker[0] = 0; scat(marker, sizeof(marker), "----- "); scat(marker, sizeof(marker), label); scat(marker, sizeof(marker), " begin -----");
    prep_log_raw(marker);
    src = sys_open(path, O_RDONLY, 0);
    if (src < 0) {
        prep_log_int("snapshot_open_error", src);
    } else {
        dst = sys_open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (dst < 0) {
            sys_close(src);
            return;
        }
        while (total < 16384 && (n = sys_read(src, buffer, sizeof(buffer))) > 0) {
            if (total + n > 16384) n = 16384 - total;
            if (n > 0) sys_write(dst, buffer, n);
            total += n;
        }
        sys_write(dst, "\n", 1);
        sys_close(dst);
        sys_close(src);
        prep_log_int("snapshot_bytes", total);
    }
    marker[0] = 0; scat(marker, sizeof(marker), "----- "); scat(marker, sizeof(marker), label); scat(marker, sizeof(marker), " end -----");
    prep_log_raw(marker);
}
static unsigned int u32le(const unsigned char *p) {
    return ((unsigned int)p[0]) | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}
static int read_exact_fd(int fd, void *buf, int len) {
    int off = 0;
    while (off < len) { int n = sys_read(fd, (char *)buf + off, len - off); if (n <= 0) return -1; off += n; }
    return off;
}
static int write_exact_fd(int fd, const void *buf, int len) {
    int off = 0;
    while (off < len) { int n = sys_write(fd, (const char *)buf + off, len - off); if (n <= 0) return -1; off += n; }
    return off;
}
static int probe_elf_size(const char *path, int expected_size) {
    unsigned char b[8];
    int fd = sys_open(path, O_RDONLY, 0), n, size;
    if (fd < 0) return fd;
    n = sys_read(fd, b, sizeof(b));
    size = sys_lseek(fd, 0, SEEK_END);
    sys_close(fd);
    if (n < 4) return -100;
    if (b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F') return -101;
    if (expected_size > 0 && size != expected_size) return -102;
    return n;
}
static void cleanup_legacy_runtime_servers(void) {
    static const char *paths[] = {
        "/tmp/WiFiFiles.server.078",
        "/tmp/WiFiFiles.server.079",
        "/tmp/WiFiFiles.server.0710",
        "/tmp/WiFiFiles.server.0711",
        "/tmp/WiFiFiles.server.0712",
        "/tmp/WiFiFiles.server.0713",
        "/tmp/WiFiFiles.server.0714",
        "/tmp/WiFiFiles.server.0715",
        "/tmp/WiFiFiles.server.0716",
        "/tmp/WiFiFiles.server.0717",
        "/tmp/WiFiFiles.server.0718",
        "/tmp/WiFiFiles.server.0719",
        "/tmp/WiFiFiles.server.0720",
        "/tmp/WiFiFiles.server.0721",
        0
    };
    int i;
    for (i = 0; paths[i]; i++) sys_unlink(paths[i]);
    sys_unlink(SERVER_STAGE_PATH);
}
static int state_pid_and_version(int *pid_out, char *version_out, int version_cap) {
    char *data = runtime_upgrade_state_buffer;
    char pidbuf[32], runningbuf[16];
    if (pid_out) *pid_out = 0;
    if (version_cap > 0) version_out[0] = 0;
    if (read_all(STATE_PATH, data, 2048) >= 0) {
        ini_value(data, "version", version_out, version_cap);
        ini_value(data, "pid", pidbuf, sizeof(pidbuf));
        ini_value(data, "running", runningbuf, sizeof(runningbuf));
        if (pid_out && atoi10(runningbuf) != 0) *pid_out = atoi10(pidbuf);
        return 0;
    }
    /* If state writing was interrupted, the PID file still lets an upgrade
     * stop the previous manager and release its deleted executable blocks. */
    if (read_all("/tmp/WiFiFiles/wififiles.pid", pidbuf, sizeof(pidbuf)) >= 0) {
        if (pid_out) *pid_out = atoi10(pidbuf);
        return 0;
    }
    return -1;
}
static int stop_runtime_manager_if_needed(int force, const char *reason) {
    char state_version[32];
    int pid = 0, i;
    if (state_pid_and_version(&pid, state_version, sizeof(state_version)) < 0) return 0;
    if (!force && seq(state_version, WF_VERSION)) return 0;
    if (pid <= 1) {
        sys_unlink(STATE_PATH);
        return 1;
    }
    prep_log_raw(reason);
    prep_log_int("stale_manager_pid", pid);
    sys_kill(pid, 15);
    for (i = 0; i < 30; i++) {
        if (sys_kill(pid, 0) < 0) break;
        sys_sleep_100ms();
    }
    if (sys_kill(pid, 0) >= 0) {
        prep_log_raw("stale_manager_sigkill");
        sys_kill(pid, 9);
        for (i = 0; i < 10; i++) {
            if (sys_kill(pid, 0) < 0) break;
            sys_sleep_100ms();
        }
    }
    sys_unlink("/tmp/WiFiFiles/wififiles.pid");
    sys_unlink("/tmp/WiFiFiles/wififiles.ready");
    sys_unlink(STATE_PATH);
    return 1;
}
static int runtime_marker_valid(int expected_size) {
    char data[96], expected[96];
    expected[0] = 0;
    scat(expected, sizeof(expected), EMBED_MAGIC);
    scat(expected, sizeof(expected), "\n");
    append_int(expected, sizeof(expected), expected_size);
    scat(expected, sizeof(expected), "\n");
    if (read_all(SERVER_MARK_PATH, data, sizeof(data)) < 0) return 0;
    return seq(data, expected);
}
static int write_runtime_marker(int expected_size) {
    char data[96];
    int fd, off = 0, len;
    data[0] = 0;
    scat(data, sizeof(data), EMBED_MAGIC);
    scat(data, sizeof(data), "\n");
    append_int(data, sizeof(data), expected_size);
    scat(data, sizeof(data), "\n");
    fd = sys_open(SERVER_MARK_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return fd;
    len = slen(data);
    while (off < len) {
        int n = sys_write(fd, data + off, len - off);
        if (n <= 0) { sys_close(fd); return -1; }
        off += n;
    }
    sys_close(fd);
    return 0;
}
static int ensure_embedded_server(void) {
    unsigned char footer[EMBED_FOOTER_SIZE];
    unsigned char *buffer = runtime_extract_buffer;
    int src, dst, endpos, payload_off, left, total = 0, i;
    unsigned int payload_size, payload_check;
    int existing, stage_probe, rename_rc, upgrade_needed, marker_ok;

    src = sys_open(SELF_PATH, O_RDONLY, 0);
    if (src < 0) { prep_log_int("open_self_error", src); return -10; }
    endpos = sys_lseek(src, 0, SEEK_END);
    prep_log_int("self_size", endpos);
    if (endpos < EMBED_FOOTER_SIZE) { sys_close(src); return -11; }
    if (sys_lseek(src, endpos - EMBED_FOOTER_SIZE, SEEK_SET) < 0 || read_exact_fd(src, footer, EMBED_FOOTER_SIZE) < 0) { sys_close(src); return -12; }
    for (i = 0; i < 8; i++) if (footer[i] != (unsigned char)EMBED_MAGIC[i]) { sys_close(src); prep_log_int("footer_magic_error_at", i); return -13; }
    payload_size = u32le(footer + 8);
    payload_check = u32le(footer + 12);
    prep_log_int("embedded_server_bytes", (int)payload_size);
    if ((payload_size ^ 0xA55AA55AU) != payload_check || payload_size < 1024U * 1024U || payload_size > 32U * 1024U * 1024U) { sys_close(src); return -14; }

    upgrade_needed = stop_runtime_manager_if_needed(0, "stopping manager from older WiFiFiles version");
    cleanup_legacy_runtime_servers();
    existing = probe_elf_size(SERVER_PATH, (int)payload_size);
    marker_ok = runtime_marker_valid((int)payload_size);
    prep_log_int("probe_runtime_server", existing);
    prep_log_int("runtime_marker_valid", marker_ok);
    if (!upgrade_needed && existing >= 4 && marker_ok) { sys_close(src); return 0; }

    /* A partial or stale fixed-path binary must never be executed. If a manager
     * still references it, stop that manager first, then replace atomically. */
    stop_runtime_manager_if_needed(1, "stopping manager before replacing invalid runtime server");
    sys_unlink(SERVER_PATH);
    sys_unlink(SERVER_STAGE_PATH);
    sys_unlink(SERVER_MARK_PATH);

    payload_off = endpos - EMBED_FOOTER_SIZE - (int)payload_size;
    if (payload_off < 0 || sys_lseek(src, payload_off, SEEK_SET) < 0) { sys_close(src); return -15; }
    dst = sys_open(SERVER_STAGE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0700);
    if (dst < 0) { sys_close(src); prep_log_int("open_runtime_stage_error", dst); return -16; }
    left = (int)payload_size;
    while (left > 0) {
        int chunk = left > 8192 ? 8192 : left;
        int rr = read_exact_fd(src, buffer, chunk);
        int wr;
        if (rr < 0) {
            prep_log_int("extract_read_error", rr);
            sys_close(dst); sys_close(src); sys_unlink(SERVER_STAGE_PATH); return -17;
        }
        wr = write_exact_fd(dst, buffer, chunk);
        if (wr < 0) {
            prep_log_int("extract_write_error", wr);
            prep_log_int("extract_written_before_error", total);
            sys_close(dst); sys_close(src); sys_unlink(SERVER_STAGE_PATH); return -18;
        }
        left -= chunk; total += chunk;
    }
    sys_close(dst); sys_close(src);
    prep_log_int("extract_runtime_server_bytes", total);
    stage_probe = probe_elf_size(SERVER_STAGE_PATH, (int)payload_size);
    prep_log_int("probe_runtime_stage", stage_probe);
    if (stage_probe < 4) { sys_unlink(SERVER_STAGE_PATH); return -19; }
    rename_rc = sys_rename(SERVER_STAGE_PATH, SERVER_PATH);
    prep_log_int("rename_runtime_server", rename_rc);
    if (rename_rc < 0) { sys_unlink(SERVER_STAGE_PATH); return -20; }
    existing = probe_elf_size(SERVER_PATH, (int)payload_size);
    prep_log_int("probe_runtime_server_after", existing);
    if (existing < 4) { sys_unlink(SERVER_PATH); return -21; }
    rename_rc = write_runtime_marker((int)payload_size);
    prep_log_int("write_runtime_marker", rename_rc);
    if (rename_rc < 0) { sys_unlink(SERVER_PATH); return -22; }
    return 0;
}

static void prep_log_state_if_changed(void) {
    char *data = native_state_buffer;
    if (read_all(STATE_PATH, data, 8192) < 0) return;
    if (seq(data, last_logged_state_buffer)) return;
    scopy(last_logged_state_buffer, sizeof(last_logged_state_buffer), data);
    prep_log_file_snapshot("native_state.ini", STATE_PATH);
}

static int run_helper(const char *arg) {
    int pid, prep = 0;
    if (!prep_started) prep_log_reset();
    if (!runtime_server_ready) {
        prep_log_raw("runtime_server=/tmp/WiFiFiles.server");
        prep = ensure_embedded_server();
        prep_log_int("ensure_embedded_server", prep);
        if (prep < 0) return prep;
        runtime_server_ready = 1;
    }
    pid = sys_fork();
    if (pid == 0) {
        char *argv[3];
        argv[0] = (char *)SERVER_PATH;
        argv[1] = (char *)arg;
        argv[2] = 0;
        sys_execve(SERVER_PATH, argv, g_envp);
        sys_exit(127);
    }
    if (pid < 0) { prep_log_int("helper_fork_error", pid); return -1; }
    {
        int status = 0;
        sys_wait4(pid, &status);
        if (status != 0) {
            prep_log_int("helper_wait_status", status);
            prep_log_int("helper_exit_code", (status >> 8) & 255);
            prep_log_int("helper_term_signal", status & 127);
            if (((status >> 8) & 255) == 127 || (status & 127) != 0) runtime_server_ready = 0;
        }
        if (seq(arg, "--native-state")) {
            prep_log_state_if_changed();
        } else if (seq(arg, "--native-apply-file") || seq(arg, "--native-start") || seq(arg, "--native-stop") || seq(arg, "--native-set-language-file")) {
            last_logged_state_buffer[0] = 0;
            prep_log_state_if_changed();
        }
        return status;
    }
}

static int read_all(const char *path, char *buf, int cap) {
    int fd, n, total = 0;
    if (cap < 2) return -1;
    fd = sys_open(path, O_RDONLY, 0);
    if (fd < 0) { buf[0] = 0; return -1; }
    while (total < cap - 1) {
        n = sys_read(fd, buf + total, cap - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    sys_close(fd); buf[total] = 0; return total;
}
static void log_line(const char *text) {
    int fd;
    if (!st.logging_enabled) return;
    fd = sys_open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { sys_write(fd, text, slen(text)); sys_write(fd, "\n", 1); sys_close(fd); }
}

static int write_all(const char *path, const char *buf) {
    int fd = sys_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int len = slen(buf), off = 0;
    if (fd < 0) return -1;
    while (off < len) { int n = sys_write(fd, buf + off, len - off); if (n <= 0) { sys_close(fd); return -1; } off += n; }
    sys_close(fd); return 0;
}

static int ini_value(const char *data, const char *key, char *out, int cap) {
    int klen = slen(key), i = 0;
    while (data[i]) {
        int line = i, j = 0;
        while (data[i] && data[i] != '\n') i++;
        if (starts(data + line, key) && data[line + klen] == '=') {
            int p = line + klen + 1;
            while (p < i && j < cap - 1 && data[p] != '\r') out[j++] = data[p++];
            out[j] = 0; return 1;
        }
        if (data[i] == '\n') i++;
    }
    if (cap) out[0] = 0; return 0;
}
static int ini_int(const char *data, const char *key, int def) {
    char v[32]; if (!ini_value(data, key, v, sizeof(v))) return def; return atoi10(v);
}
static int current_lang = 0;
static int screen_mode = 0;
static int language_return_mode = 0;
static int instruction_index = 0;
static int instruction_page = 0;
static int settings_picker_mode = 0;
static char update_latest[32];

#define LANG_RU 0
#define LANG_EN 1
#define LANG_FR 2
#define LANG_DE 3
#define MODE_MAIN 0
#define MODE_LANGUAGE 1
#define MODE_INSTRUCTIONS 2
#define MODE_INSTRUCTION_DETAIL 3
#define MODE_STORAGE_PICKER 4
#define MODE_FOLDER_PICKER 5
#define MODE_QR_MODE 6
#define MODE_QR 7
#define MODE_SETTINGS 8
#define MODE_LOG 9
#define LOG_BACK 0
#define MAIN_ROW_COUNT 13
#define MAIN_STOP 13
#define MAIN_PHONE 14
#define MAIN_REFRESH 15
#define MAIN_START 16
#define STORAGE_BACK 2
#define STORAGE_DEFAULT 3
#define STORAGE_RECENT1 4
#define STORAGE_RECENT2 5
#define STORAGE_RECENT3 6
#define STORAGE_RECENT4 7
#define FOLDER_BACK 10
#define FOLDER_UP 11
#define FOLDER_PREV 12
#define FOLDER_NEXT 13
#define FOLDER_REMEMBER 14
#define QR_MODE_SAFE 0
#define QR_MODE_EDIT 1
#define QR_MODE_BACK 2
#define QR_BACK 0
#define QR_CHANGE_FOLDER 1

static const char *L(const char *ru, const char *en, const char *fr, const char *de) {
    if (current_lang == LANG_EN) return en;
    if (current_lang == LANG_FR) return fr;
    if (current_lang == LANG_DE) return de;
    return ru;
}
static int lang_from_code(const char *code) {
    if (seq(code, "en")) return LANG_EN;
    if (seq(code, "fr")) return LANG_FR;
    if (seq(code, "de")) return LANG_DE;
    return LANG_RU;
}
static const char *lang_code(int lang) {
    if (lang == LANG_EN) return "en";
    if (lang == LANG_FR) return "fr";
    if (lang == LANG_DE) return "de";
    return "ru";
}
static void localize_helper_message(char *message, int cap) {
    const char *translated = 0;
    const char *suffix = 0;
    char out[192];
    if (!message || !message[0] || current_lang == LANG_RU) return;

    if (seq(message, "Серверы выключены"))
        translated = L("Серверы выключены", "Servers are stopped", "Les serveurs sont arrêtés", "Server sind gestoppt");
    else if (seq(message, "Не найден файл языка"))
        translated = L("Не найден файл языка", "Language file not found", "Fichier de langue introuvable", "Sprachdatei nicht gefunden");
    else if (seq(message, "Неподдерживаемый язык"))
        translated = L("Неподдерживаемый язык", "Unsupported language", "Langue non prise en charge", "Nicht unterstützte Sprache");
    else if (seq(message, "Не найден файл настроек"))
        translated = L("Не найден файл настроек", "Settings file not found", "Fichier de paramètres introuvable", "Einstellungsdatei nicht gefunden");
    else if (seq(message, "Логин должен содержать 3–32 символа"))
        translated = L("Логин должен содержать 3–32 символа", "Username must contain 3–32 characters", "L’identifiant doit contenir de 3 à 32 caractères", "Der Benutzername muss 3–32 Zeichen enthalten");
    else if (seq(message, "Порты должны быть разными числами 1024–65535 и не равны 8090"))
        translated = L("Порты должны быть разными числами 1024–65535 и не равны 8090", "Ports must be distinct numbers from 1024 to 65535 and must not be 8090", "Les ports doivent être des nombres distincts de 1024 à 65535 et différents de 8090", "Die Ports müssen verschiedene Zahlen zwischen 1024 und 65535 und ungleich 8090 sein");
    else if (seq(message, "Включите хотя бы одну память"))
        translated = L("Включите хотя бы одну память", "Enable at least one storage location", "Activez au moins un emplacement de stockage", "Aktivieren Sie mindestens einen Speicherort");
    else if (seq(message, "Пароль должен содержать 6–128 символов"))
        translated = L("Пароль должен содержать 6–128 символов", "Password must contain 6–128 characters", "Le mot de passe doit contenir de 6 à 128 caractères", "Das Passwort muss 6–128 Zeichen enthalten");
    else if (seq(message, "Для SMB введите пароль заново и нажмите Старт"))
        translated = L("Для SMB введите пароль заново и нажмите Старт", "For SMB, enter the password again and press Start", "Pour SMB, saisissez de nouveau le mot de passe, puis appuyez sur Démarrer", "Geben Sie für SMB das Passwort erneut ein und drücken Sie Start");
    else if (starts(message, "Ошибка запуска: ")) {
        translated = L("Ошибка запуска", "Startup error", "Erreur de démarrage", "Startfehler");
        suffix = message + slen("Ошибка запуска: ");
    } else if (starts(message, "Ошибка обновления сервера: ")) {
        translated = L("Ошибка обновления сервера", "Server update error", "Erreur de mise à jour du serveur", "Fehler beim Aktualisieren des Servers");
        suffix = message + slen("Ошибка обновления сервера: ");
    } else if (starts(message, "Ошибка сохранения языка: ")) {
        translated = L("Ошибка сохранения языка", "Language save error", "Erreur d’enregistrement de la langue", "Fehler beim Speichern der Sprache");
        suffix = message + slen("Ошибка сохранения языка: ");
    } else if (starts(message, "Ошибка сохранения: ")) {
        translated = L("Ошибка сохранения", "Save error", "Erreur d’enregistrement", "Speicherfehler");
        suffix = message + slen("Ошибка сохранения: ");
    } else if (starts(message, "Ошибка SMB: ")) {
        translated = L("Ошибка SMB", "SMB error", "Erreur SMB", "SMB-Fehler");
        suffix = message + slen("Ошибка SMB: ");
    }

    if (!translated) return;
    if (!suffix) {
        scopy(message, cap, translated);
        return;
    }
    out[0] = 0;
    scat(out, sizeof(out), translated);
    scat(out, sizeof(out), ": ");
    scat(out, sizeof(out), suffix);
    scopy(message, cap, out);
}
static const char *lang_label(void) {
    if (current_lang == LANG_EN) return "EN";
    if (current_lang == LANG_FR) return "FR";
    if (current_lang == LANG_DE) return "DE";
    return "RU";
}

static int instruction_body_size(void) {
    if (instruction_font_scale == 0) return 17;
    if (instruction_font_scale == 2) return 23;
    return 20;
}
static int instruction_title_size(void) {
    if (instruction_font_scale == 0) return 19;
    if (instruction_font_scale == 2) return 24;
    return 21;
}
static int instruction_line_height(void) { return instruction_body_size() + 5; }
static const char *instruction_font_label(void) {
    if (instruction_font_scale == 0) return L("ШРИФТ: 90%", "FONT: 90%", "POLICE : 90 %", "SCHRIFT: 90 %");
    if (instruction_font_scale == 2) return L("ШРИФТ: 115%", "FONT: 115%", "POLICE : 115 %", "SCHRIFT: 115 %");
    return L("ШРИФТ: 100%", "FONT: 100%", "POLICE : 100 %", "SCHRIFT: 100 %");
}
static void reopen_instruction_fonts(void) {
    if (font_instruction) CloseFont(font_instruction);
    if (font_instruction_title) CloseFont(font_instruction_title);
    font_instruction = OpenFont("DejaVu Sans", instruction_body_size(), 1);
    font_instruction_title = OpenFont("DejaVu Sans", instruction_title_size(), 1);
}
static void load_instruction_font_scale(void) {
    char data[64];
    int value;
    instruction_font_scale = 1;
    if (read_all(FONT_PATH, data, sizeof(data)) < 0) return;
    value = ini_int(data, "scale", 1);
    if (value >= 0 && value <= 2) instruction_font_scale = value;
}
static void save_instruction_font_scale(void) {
    char data[32];
    data[0] = 0;
    scat(data, sizeof(data), "scale=");
    append_int(data, sizeof(data), instruction_font_scale);
    scat(data, sizeof(data), "\n");
    write_all(FONT_PATH, data);
}
static void cycle_instruction_font(void) {
    instruction_font_scale++;
    if (instruction_font_scale > 2) instruction_font_scale = 0;
    save_instruction_font_scale();
    reopen_instruction_fonts();
    instruction_page = 0;
    selected = 5;
    draw_current();
}

static void update_wifi_info(void) {
    iv_netinfo *info;
    wifi_name[0] = 0; wifi_security[0] = 0;
    wifi_security_known = 0; wifi_is_open = 0;
    if (!NetInfo) return;
    info = NetInfo();
    if (!info) return;
    scopy(wifi_name, sizeof(wifi_name), info->name);
    scopy(wifi_security, sizeof(wifi_security), info->security);
    if (!wifi_security[0] || contains_ci(wifi_security, "unknown")) return;
    wifi_security_known = 1;
    if (contains_ci(wifi_security, "none") || contains_ci(wifi_security, "open") ||
        contains_ci(wifi_security, "no security") || seq(wifi_security, "NO") || seq(wifi_security, "0")) {
        wifi_is_open = 1;
    }
}
static int wifi_link_connected(void) {
    iv_netinfo *info;
    if (st.ip[0]) return 1;
    if (!NetInfo) return 0;
    info = NetInfo();
    return info && info->connected;
}
static void prepare_open_wifi_warning(void) {
    const char *key;
    if (!st.ip[0] || !wifi_security_known || !wifi_is_open) {
        open_wifi_warning_pending = 0;
        if (!st.ip[0] || (wifi_security_known && !wifi_is_open)) warned_open_wifi[0] = 0;
        return;
    }
    key = wifi_name[0] ? wifi_name : st.ip;
    if (seq(warned_open_wifi, key)) {
        open_wifi_warning_pending = 0;
        return;
    }
    scopy(warned_open_wifi, sizeof(warned_open_wifi), key);
    open_wifi_warning_pending = 1;
}
static void show_open_wifi_warning(void) {
    if (!open_wifi_warning_pending) return;
    open_wifi_warning_pending = 0;
    Message(ICON_WARNING,
        L("Открытая Wi-Fi-сеть", "Open Wi-Fi network", "Réseau Wi-Fi ouvert", "Offenes WLAN"),
        L("Эта сеть не защищена паролем. Не используйте WiFiFiles в общественной открытой сети: подключитесь к доверенной защищённой точке доступа.",
          "This network is not protected by a password. Do not use WiFiFiles on a public open network; connect to a trusted secured access point.",
          "Ce réseau n’est pas protégé par un mot de passe. N’utilisez pas WiFiFiles sur un réseau public ouvert ; connectez-vous à un point d’accès sécurisé et fiable.",
          "Dieses WLAN ist nicht durch ein Passwort geschützt. Verwenden Sie WiFiFiles nicht in einem öffentlichen offenen Netz, sondern verbinden Sie den Reader mit einem vertrauenswürdigen geschützten Zugangspunkt."),
        5200);
}

static void reset_state(void) {
    memset(&st, 0, sizeof(st));
    st.http_enabled = 1; st.http_port = 8080;
    st.ftp_port = 2121; st.smb_port = 4445;
    st.internal_enabled = 1; st.sd_enabled = 1; st.logging_enabled = 0;
    st.password_is_default = 1; st.uid = 101;
    scopy(st.username, sizeof(st.username), "pocketbook");
    password[0] = 0;
}
static void load_state(void) {
    char *data = native_state_buffer;
    char v[192];
    int helper_status;
    reset_state();
    helper_status = run_helper("--native-state");
    if (helper_status != 0) {
        scopy(st.message, sizeof(st.message), "Runtime helper failed");
        prep_log_int("load_state_helper_status", helper_status);
        return;
    }
    if (read_all(STATE_PATH, data, 8192) < 0) {
        scopy(st.message, sizeof(st.message), "Cannot read server state");
        return;
    }
    st.running = ini_int(data, "running", 0);
    st.pid = ini_int(data, "pid", 0);
    ini_value(data, "ip", st.ip, sizeof(st.ip));
    st.http_enabled = ini_int(data, "http_enabled", 1);
    st.http_running = ini_int(data, "http_running", 0);
    st.http_port = ini_int(data, "http_port", 8080);
    ini_value(data, "http_error", st.http_error, sizeof(st.http_error));
    st.ftp_enabled = ini_int(data, "ftp_enabled", 0);
    st.ftp_running = ini_int(data, "ftp_running", 0);
    st.ftp_port = ini_int(data, "ftp_port", 2121);
    ini_value(data, "ftp_error", st.ftp_error, sizeof(st.ftp_error));
    st.smb_enabled = ini_int(data, "smb_enabled", 0);
    st.smb_running = ini_int(data, "smb_running", 0);
    st.smb_port = ini_int(data, "smb_port", 4445);
    st.smb_credentials_ready = ini_int(data, "smb_credentials_ready", 1);
    ini_value(data, "smb_error", st.smb_error, sizeof(st.smb_error));
    st.internal_enabled = ini_int(data, "internal_enabled", 1);
    st.sd_enabled = ini_int(data, "sd_enabled", 1);
    st.logging_enabled = ini_int(data, "logging_enabled", 0);
    ini_value(data, "username", st.username, sizeof(st.username));
    ini_value(data, "language", st.language, sizeof(st.language));
    st.password_is_default = ini_int(data, "password_is_default", 1);
    st.uid = ini_int(data, "uid", 101);
    ini_value(data, "default_target", st.default_target, sizeof(st.default_target));
    ini_value(data, "recent1", st.recent_targets[0], sizeof(st.recent_targets[0]));
    ini_value(data, "recent2", st.recent_targets[1], sizeof(st.recent_targets[1]));
    ini_value(data, "recent3", st.recent_targets[2], sizeof(st.recent_targets[2]));
    ini_value(data, "recent4", st.recent_targets[3], sizeof(st.recent_targets[3]));
    ini_value(data, "free_internal", st.free_internal, sizeof(st.free_internal));
    ini_value(data, "free_sd", st.free_sd, sizeof(st.free_sd));
    st.active_connections = ini_int(data, "active_connections", 0);
    st.uploaded_total = ini_int(data, "uploaded_total", 0);
    st.deleted_total = ini_int(data, "deleted_total", 0);
    ini_value(data, "recent_log", st.recent_log, sizeof(st.recent_log));
    ini_value(data, "message", v, sizeof(v)); scopy(st.message, sizeof(st.message), v);
    current_lang = lang_from_code(st.language);
    localize_helper_message(st.message, sizeof(st.message));
    localize_helper_message(st.smb_error, sizeof(st.smb_error));
    update_wifi_info();
    prepare_open_wifi_warning();
    dirty = 0; password[0] = 0;
}

static void virtual_path_label(const char *path, char *out, int cap) {
    const char *rest = path;
    out[0] = 0;
    if (starts(path, "internal")) {
        scat(out, cap, L("Память ридера", "Reader storage", "Mémoire du lecteur", "Reader-Speicher"));
        rest = path + 8;
    } else if (starts(path, "sd")) {
        scat(out, cap, L("Карта SD", "SD card", "Carte SD", "SD-Karte"));
        rest = path + 2;
    }
    while (*rest == '/') rest++;
    if (*rest) { scat(out, cap, " / "); scat(out, cap, rest); }
}

static int request_folder_list(const char *path) {
    char request[320], key[32];
    int i, count;
    request[0] = 0; scat(request, sizeof(request), "path="); scat(request, sizeof(request), path); scat(request, sizeof(request), "\n");
    if (write_all(FOLDER_REQUEST_PATH, request) < 0) {
        scopy(folder_error, sizeof(folder_error), L("Не удалось записать запрос папок", "Cannot write the folder request", "Impossible d’écrire la demande de dossiers", "Ordneranfrage konnte nicht geschrieben werden"));
        return -1;
    }
    run_helper("--native-folder-list-file");
    if (read_all(FOLDER_LIST_PATH, helper_data, sizeof(helper_data)) < 0) {
        scopy(folder_error, sizeof(folder_error), L("Не удалось получить список папок", "Cannot read the folder list", "Impossible de lire la liste des dossiers", "Ordnerliste konnte nicht gelesen werden"));
        return -1;
    }
    ini_value(helper_data, "error", folder_error, sizeof(folder_error));
    if (folder_error[0]) return -1;
    ini_value(helper_data, "current", folder_current, sizeof(folder_current));
    ini_value(helper_data, "parent", folder_parent, sizeof(folder_parent));
    count = ini_int(helper_data, "count", 0);
    if (count < 0) count = 0;
    if (count > MAX_FOLDER_DIRS) count = MAX_FOLDER_DIRS;
    folder_count = count;
    folder_total = ini_int(helper_data, "total", 0);
    if (folder_total < count) folder_total = count;
    for (i = 0; i < count; i++) {
        key[0] = 0; scat(key, sizeof(key), "dir"); append_int(key, sizeof(key), i);
        ini_value(helper_data, key, folder_dirs[i], sizeof(folder_dirs[i]));
        key[0] = 0; scat(key, sizeof(key), "name"); append_int(key, sizeof(key), i);
        ini_value(helper_data, key, folder_names[i], sizeof(folder_names[i]));
    }
    folder_page = 0;
    folder_error[0] = 0;
    return 0;
}

static int request_mobile_qr(const char *access_mode) {
    char request[640], key[32];
    int i, size;
    request[0] = 0;
    scat(request, sizeof(request), "target="); scat(request, sizeof(request), folder_current); scat(request, sizeof(request), "\n");
    scat(request, sizeof(request), "mode="); scat(request, sizeof(request), access_mode && access_mode[0] ? access_mode : "safe"); scat(request, sizeof(request), "\n");
    scat(request, sizeof(request), "ip="); scat(request, sizeof(request), st.ip); scat(request, sizeof(request), "\n");
    if (write_all(MOBILE_REQUEST_PATH, request) < 0) {
        Message(ICON_ERROR, "WiFiFiles", L("Не удалось создать запрос QR-кода", "Cannot create the QR request", "Impossible de créer la demande de QR code", "QR-Anfrage konnte nicht erstellt werden"), 2800);
        return -1;
    }
    ShowHourglass(); run_helper("--native-mobile-qr-file"); HideHourglass();
    if (read_all(MOBILE_QR_PATH, helper_data, sizeof(helper_data)) < 0) {
        Message(ICON_ERROR, "WiFiFiles", L("Не удалось прочитать QR-код", "Cannot read the QR code", "Impossible de lire le QR code", "QR-Code konnte nicht gelesen werden"), 2800);
        return -1;
    }
    ini_value(helper_data, "error", folder_error, sizeof(folder_error));
    if (folder_error[0]) { Message(ICON_ERROR, "WiFiFiles", folder_error, 3800); return -1; }
    ini_value(helper_data, "target", qr_target, sizeof(qr_target));
    ini_value(helper_data, "mode", qr_access_mode, sizeof(qr_access_mode));
    if (!seq(qr_access_mode, "edit")) scopy(qr_access_mode, sizeof(qr_access_mode), "safe");
    ini_value(helper_data, "url", qr_url, sizeof(qr_url));
    size = ini_int(helper_data, "size", 0);
    if (size <= 0 || size > QR_MAX_SIZE) {
        Message(ICON_ERROR, "WiFiFiles", L("Получен некорректный QR-код", "Invalid QR code received", "QR code reçu incorrect", "Ungültiger QR-Code empfangen"), 2800);
        return -1;
    }
    qr_size = size;
    for (i = 0; i < size; i++) {
        key[0] = 0; scat(key, sizeof(key), "row"); append_int(key, sizeof(key), i);
        ini_value(helper_data, key, qr_rows[i], sizeof(qr_rows[i]));
        if (slen(qr_rows[i]) != size) {
            Message(ICON_ERROR, "WiFiFiles", L("QR-код повреждён", "The QR code is damaged", "Le QR code est endommagé", "Der QR-Code ist beschädigt"), 2800);
            qr_size = 0;
            return -1;
        }
    }
    return 0;
}

static int save_default_target(const char *path) {
    char request[320];
    request[0] = 0;
    scat(request, sizeof(request), "default_target="); scat(request, sizeof(request), path); scat(request, sizeof(request), "\n");
    if (write_all(MOBILE_DEFAULT_PATH, request) < 0) {
        Message(ICON_ERROR, "WiFiFiles", L("Не удалось сохранить путь по умолчанию", "Cannot save default path", "Impossible d'enregistrer le chemin par défaut", "Der Standardpfad konnte nicht gespeichert werden"), 2800);
        return -1;
    }
    ShowHourglass(); run_helper("--native-mobile-default-save"); HideHourglass();
    load_state();
    return 0;
}

static int folder_visible_count(void) {
    int left = folder_count - folder_page * FOLDER_PAGE_SIZE;
    if (left < 0) left = 0;
    return left > FOLDER_PAGE_SIZE ? FOLDER_PAGE_SIZE : left;
}

static void draw_text(ifont *font, int x, int y, int w, int h, const char *text, int flags) {
    SetFont(font, BLACK); DrawTextRect(x, y, w, h, text, flags);
}
static void finish_screen_update(void) {
    /* FW5 reserves panel space when it is enabled, but does not paint the panel
     * until DrawPanel is called. Draw it last so ClearScreen/app rendering cannot
     * erase it, then refresh the complete E-Ink frame once. */
    DrawPanel((const ibitmap *)0, "", "", 0);
    FullUpdate();
}
static void draw_header(const char *title) {
    FillArea(0, 0, screen_w, 68, BLACK);
    SetFont(font_title, WHITE);
    DrawTextRect(20, 0, screen_w - 40, 68, title, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
}
static void draw_row(int idx, int y, const char *left, const char *right, int disabled) {
    int h = 45, active = (selected == idx);
    FillArea(18, y, screen_w - 36, h, active ? LGRAY : WHITE);
    DrawRect(18, y, screen_w - 36, h, disabled ? LGRAY : BLACK);
    SetFont(font_main, disabled ? DGRAY : BLACK);
    DrawTextRect(30, y, screen_w - 245, h, left, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
    DrawTextRect(screen_w - 218, y, 182, h, right, ALIGN_RIGHT | VALIGN_MIDDLE | DOTS);
}
static void draw_action(int idx, int x, int y, int w, int h, const char *label, int disabled) {
    FillArea(x, y, w, h, selected == idx ? LGRAY : WHITE);
    DrawRect(x, y, w, h, disabled ? LGRAY : BLACK);
    SetFont(font_small, disabled ? DGRAY : BLACK);
    DrawTextRect(x + 3, y, w - 6, h, label, ALIGN_CENTER | VALIGN_MIDDLE | DOTS);
}
static void make_onoff(char *out, int cap, int on) {
    scopy(out, cap, on ? L("ВКЛ", "ON", "ACTIVÉ", "EIN") : L("ВЫКЛ", "OFF", "DÉSACTIVÉ", "AUS"));
}
static void make_port(char *out, int cap, int port) { out[0] = 0; append_int(out, cap, port); }

#define MAIN_STATUS_Y 78
#define MAIN_STATUS_H 180
#define MAIN_ROWS_TOP 268
#define MAIN_ROW_STEP 47
#define MAIN_ROW_H 45
#define MAIN_BUTTON_Y_OFFSET 72

static int main_row_y(int idx) { return MAIN_ROWS_TOP + idx * MAIN_ROW_STEP; }

static void draw_no_wifi(void) {
    int by = screen_h - 88;
    int bw = (screen_w - 54) / 2;
    int x1 = 18, x2 = x1 + bw + 18;
    const char *title;
    const char *body;
    ClearScreen();
    draw_header("WiFiFiles " WF_VERSION);
    if (wifi_refresh_in_progress) {
        title = L("Выполняется поиск…", "Searching…", "Recherche en cours…", "Suche läuft…");
        if (wifi_refresh_existing_connection) {
            body = L("Ридер уже подключён к Wi-Fi. Приложение не перезапускает Wi-Fi и ждёт, пока сеть выдаст IP-адрес. После этого главный экран откроется автоматически.",
                     "The reader is already connected to Wi-Fi. The app will not restart Wi-Fi; it is waiting for the network to assign an IP address. The main screen will then open automatically.",
                     "Le lecteur est déjà connecté au Wi-Fi. L’application ne redémarre pas le Wi-Fi ; elle attend que le réseau attribue une adresse IP. L’écran principal s’ouvrira ensuite automatiquement.",
                     "Der Reader ist bereits mit dem WLAN verbunden. Die App startet das WLAN nicht neu, sondern wartet auf die Zuweisung einer IP-Adresse. Danach öffnet sich der Hauptbildschirm automatisch.");
        } else {
            body = L("Wi-Fi автоматически выключен и включается снова. Подождите: ридер ищет сохранённые сети и пытается восстановить подключение. Повторное нажатие не запускает второй поиск.",
                     "Wi-Fi has been switched off and is turning on again. Please wait while the reader searches for saved networks and tries to reconnect. Repeated presses do not start another scan.",
                     "Le Wi-Fi a été désactivé puis réactivé. Patientez pendant que le lecteur recherche les réseaux enregistrés et tente de se reconnecter. Un nouvel appui ne lance pas une seconde recherche.",
                     "Das WLAN wurde aus- und wieder eingeschaltet. Bitte warten Sie, während der Reader gespeicherte Netze sucht und die Verbindung wiederherstellt. Mehrfaches Drücken startet keine zweite Suche.");
        }
    } else if (wifi_refresh_result < 0) {
        title = L("Подключение не найдено", "No connection found", "Aucune connexion trouvée", "Keine Verbindung gefunden");
        body = L("Автоматическое подключение не удалось. Откройте «Настройки Wi-Fi» и выберите нужную точку доступа. Затем вернитесь и снова нажмите «Проверить подключение».",
                 "Automatic reconnection failed. Open Wi-Fi Settings and select the required access point, then return and press Check connection again.",
                 "La reconnexion automatique a échoué. Ouvrez les réglages Wi-Fi et choisissez le point d’accès voulu, puis revenez et relancez la vérification.",
                 "Die automatische Wiederverbindung ist fehlgeschlagen. Öffnen Sie die WLAN-Einstellungen, wählen Sie den gewünschten Zugangspunkt und prüfen Sie danach erneut.");
    } else {
        title = L("Нет подключения к Wi-Fi", "No Wi-Fi connection", "Aucune connexion Wi-Fi", "Keine WLAN-Verbindung");
        body = L("Приложение автоматически проверяет подключение при запуске и после возврата из настроек Wi-Fi. Кнопка «Проверить подключение» повторно запустит поиск сохранённой сети. Для выбора другой точки доступа откройте «Настройки Wi-Fi».",
                 "The app checks the connection automatically at startup and after returning from Wi-Fi Settings. Check connection starts another search for a saved network. To choose a different access point, open Wi-Fi Settings.",
                 "L’application vérifie automatiquement la connexion au démarrage et au retour des réglages Wi-Fi. Vérifier la connexion relance la recherche d’un réseau enregistré. Pour choisir un autre point d’accès, ouvrez les réglages Wi-Fi.",
                 "Die App prüft die Verbindung automatisch beim Start und nach der Rückkehr aus den WLAN-Einstellungen. Verbindung prüfen startet eine neue Suche nach einem gespeicherten Netz. Für einen anderen Zugangspunkt öffnen Sie die WLAN-Einstellungen.");
    }
    draw_text(font_title, 42, 200, screen_w - 84, 82, title, ALIGN_CENTER | VALIGN_MIDDLE);
    draw_text(font_main, 52, 300, screen_w - 104, 245, body, ALIGN_CENTER | VALIGN_TOP);
    draw_action(MAIN_START, x1, by, bw, 60,
        L("НАСТРОЙКИ WI-FI", "WI-FI SETTINGS", "RÉGLAGES WI-FI", "WLAN-EINSTELLUNGEN"), 0);
    draw_action(MAIN_REFRESH, x2, by, bw, 60,
        wifi_refresh_in_progress ? L("ВЫПОЛНЯЕТСЯ ПОИСК", "SEARCHING", "RECHERCHE…", "SUCHE LÄUFT") :
        L("ПРОВЕРИТЬ ПОДКЛЮЧЕНИЕ", "CHECK CONNECTION", "VÉRIFIER LA CONNEXION", "VERBINDUNG PRÜFEN"),
        wifi_refresh_in_progress);
    finish_screen_update();
}

static void build_status_line(int service, char *line, int cap) {
    line[0] = 0;
    if (service == 0) {
        if (st.http_running) {
            scat(line, cap, "HTTP/DAV  http://"); scat(line, cap, st.ip); scat(line, cap, ":"); append_int(line, cap, st.http_port); scat(line, cap, "/dav/");
        } else if (st.http_error[0]) { scat(line, cap, "HTTP/DAV  "); scat(line, cap, st.http_error); }
        else scat(line, cap, st.http_enabled ? L("HTTP/DAV  готов к запуску", "HTTP/DAV  ready to start", "HTTP/DAV  prêt à démarrer", "HTTP/DAV  startbereit") : L("HTTP/DAV  выключен", "HTTP/DAV  off", "HTTP/DAV  désactivé", "HTTP/DAV  aus"));
    } else if (service == 1) {
        if (st.ftp_running) { scat(line, cap, "FTP  "); scat(line, cap, st.ip); scat(line, cap, ":"); append_int(line, cap, st.ftp_port); }
        else if (st.ftp_error[0]) { scat(line, cap, "FTP  "); scat(line, cap, st.ftp_error); }
        else scat(line, cap, st.ftp_enabled ? L("FTP  готов к запуску", "FTP  ready to start", "FTP  prêt à démarrer", "FTP  startbereit") : L("FTP  выключен", "FTP  off", "FTP  désactivé", "FTP  aus"));
    } else {
        if (st.smb_running) { scat(line, cap, "SMB  "); scat(line, cap, st.ip); scat(line, cap, ":"); append_int(line, cap, st.smb_port); }
        else if (st.smb_error[0]) { scat(line, cap, "SMB  "); scat(line, cap, st.smb_error); }
        else scat(line, cap, st.smb_enabled ? L("SMB  готов к запуску", "SMB  ready to start", "SMB  prêt à démarrer", "SMB  startbereit") : L("SMB  выключен", "SMB  off", "SMB  désactivé", "SMB  aus"));
    }
}

static const char *connection_word(int n) {
    if (current_lang == LANG_EN) return n == 1 ? "connection" : "connections";
    if (current_lang == LANG_FR) return n == 1 ? "connexion" : "connexions";
    if (current_lang == LANG_DE) return n == 1 ? "Verbindung" : "Verbindungen";
    {
        int d = n % 10, h = n % 100;
        if (d == 1 && h != 11) return "подключение";
        if (d >= 2 && d <= 4 && (h < 12 || h > 14)) return "подключения";
        return "подключений";
    }
}

static void append_server_counters(char *line, int cap) {
    if (!st.running) return;
    if (st.active_connections > 0) {
        scat(line, cap, " · ");
        append_int(line, cap, st.active_connections);
        scat(line, cap, " ");
        scat(line, cap, connection_word(st.active_connections));
    }
    if (st.uploaded_total > 0 || st.deleted_total > 0) {
        scat(line, cap, " · ");
        scat(line, cap, L("удалено ", "deleted ", "supprimé ", "gelöscht "));
        append_int(line, cap, st.deleted_total);
        scat(line, cap, " / ");
        scat(line, cap, L("загружено ", "uploaded ", "téléversé ", "hochgeladen "));
        append_int(line, cap, st.uploaded_total);
    }
}

static void draw_main_status(void) {
    char line[320]; int y = MAIN_STATUS_Y;
    int service_y;
    FillArea(18, y, screen_w - 36, MAIN_STATUS_H, VLGRAY);
    DrawRect(18, y, screen_w - 36, MAIN_STATUS_H, BLACK);
    line[0] = 0;
    scat(line, sizeof(line), st.running ? L("СЕРВЕР РАБОТАЕТ", "SERVER RUNNING", "SERVEUR ACTIF", "SERVER LÄUFT") : L("СЕРВЕР ОСТАНОВЛЕН", "SERVER STOPPED", "SERVEUR ARRÊTÉ", "SERVER GESTOPPT"));
    append_server_counters(line, sizeof(line));
    if (dirty) scat(line, sizeof(line), L("  • есть несохранённые изменения", "  • unapplied changes", "  • modifications non appliquées", "  • nicht übernommene Änderungen"));
    draw_text(font_status, 31, y + 5, screen_w - 62, 34, line, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);

    line[0] = 0;
    scat(line, sizeof(line), "Wi-Fi  ");
    scat(line, sizeof(line), wifi_name[0] ? wifi_name : L("подключён", "connected", "connecté", "verbunden"));
    if (wifi_security_known) {
        scat(line, sizeof(line), wifi_is_open ? L("  • БЕЗ ПАРОЛЯ", "  • OPEN", "  • SANS MOT DE PASSE", "  • OFFEN") : L("  • защищённая", "  • secured", "  • protégé", "  • geschützt"));
    }
    scat(line, sizeof(line), "  • IP "); scat(line, sizeof(line), st.ip);
    draw_text(font_main, 31, y + 39, screen_w - 62, 28, line, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);

    if (wifi_is_open) {
        FillArea(27, y + 68, screen_w - 54, 38, WHITE);
        DrawRect(27, y + 68, screen_w - 54, 38, BLACK);
        draw_text(font_help, 36, y + 69, screen_w - 72, 36,
            L("ВНИМАНИЕ: сеть без пароля. Не используйте WiFiFiles в общественной сети.",
              "WARNING: this network has no password. Do not use WiFiFiles on a public network.",
              "ATTENTION : réseau sans mot de passe. N’utilisez pas WiFiFiles sur un réseau public.",
              "WARNUNG: Dieses Netz hat kein Passwort. WiFiFiles nicht in öffentlichen Netzen verwenden."),
            ALIGN_CENTER | VALIGN_MIDDLE | DOTS);
        service_y = y + 108;
        build_status_line(0, line, sizeof(line)); draw_text(font_small, 31, service_y, screen_w - 62, 22, line, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
        build_status_line(1, line, sizeof(line)); draw_text(font_small, 31, service_y + 23, screen_w - 62, 22, line, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
        build_status_line(2, line, sizeof(line)); draw_text(font_small, 31, service_y + 46, screen_w - 62, 22, line, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
    } else {
        build_status_line(0, line, sizeof(line)); draw_text(font_small, 31, y + 76, screen_w - 62, 28, line, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
        build_status_line(1, line, sizeof(line)); draw_text(font_small, 31, y + 108, screen_w - 62, 28, line, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
        build_status_line(2, line, sizeof(line)); draw_text(font_small, 31, y + 140, screen_w - 62, 28, line, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
    }
}

static void draw_main_row_idx(int idx) {
    char val[80]; int y = main_row_y(idx);
    if (idx == 0) { make_onoff(val, sizeof(val), st.http_enabled); draw_row(0, y, "HTTP + WebDAV", val, 0); }
    else if (idx == 1) { make_port(val, sizeof(val), st.http_port); draw_row(1, y, L("Порт HTTP/DAV", "HTTP/DAV port", "Port HTTP/DAV", "HTTP/DAV-Port"), val, 0); }
    else if (idx == 2) { make_onoff(val, sizeof(val), st.ftp_enabled); draw_row(2, y, "FTP", val, 0); }
    else if (idx == 3) { make_port(val, sizeof(val), st.ftp_port); draw_row(3, y, L("Порт FTP", "FTP port", "Port FTP", "FTP-Port"), val, 0); }
    else if (idx == 4) {
        if (st.smb_running) scopy(val, sizeof(val), L("РАБОТАЕТ", "RUNNING", "ACTIF", "LÄUFT"));
        else if (st.smb_enabled && st.smb_error[0]) scopy(val, sizeof(val), L("ОШИБКА", "ERROR", "ERREUR", "FEHLER"));
        else make_onoff(val, sizeof(val), st.smb_enabled);
        draw_row(4, y, "SMB2 / SMB3", val, 0);
    }
    else if (idx == 5) { make_port(val, sizeof(val), st.smb_port); draw_row(5, y, L("Порт SMB", "SMB port", "Port SMB", "SMB-Port"), val, 0); }
    else if (idx == 6) { make_onoff(val, sizeof(val), st.internal_enabled); draw_row(6, y, L("Внутренняя память", "Internal storage", "Mémoire interne", "Interner Speicher"), val, 0); }
    else if (idx == 7) { make_onoff(val, sizeof(val), st.sd_enabled); draw_row(7, y, L("Карта памяти SD", "SD card", "Carte SD", "SD-Karte"), val, 0); }
    else if (idx == 8) draw_row(8, y, L("Логин", "Username", "Identifiant", "Benutzername"), st.username, 0);
    else if (idx == 9) {
        if (password[0]) scopy(val, sizeof(val), "********");
        else if (st.password_is_default) scopy(val, sizeof(val), L("СМЕНИТЬ", "CHANGE", "À MODIFIER", "ÄNDERN"));
        else scopy(val, sizeof(val), "********");
        draw_row(9, y, L("Пароль", "Password", "Mot de passe", "Passwort"), val, 0);
    }
    else if (idx == 10) { make_onoff(val, sizeof(val), st.logging_enabled); draw_row(10, y, L("Ведение логов", "Logging", "Journalisation", "Protokollierung"), val, 0); }
    else if (idx == 11) draw_row(11, y, L("Инструкции", "Instructions", "Instructions", "Anleitungen"), lang_label(), 0);
    else if (idx == 12) draw_row(12, y, L("Настройки", "Settings", "Réglages", "Einstellungen"), "", 0);
}

static void draw_main_action_idx(int idx) {
    int by = screen_h - MAIN_BUTTON_Y_OFFSET;
    int bw = (screen_w - 60) / 4;
    int x1 = 18, x2 = x1 + bw + 8, x3 = x2 + bw + 8, x4 = x3 + bw + 8;
    if (idx == MAIN_STOP) draw_action(idx, x1, by, bw, 54, L("СТОП", "STOP", "ARRÊT", "STOPP"), !st.running);
    else if (idx == MAIN_PHONE) draw_action(idx, x2, by, bw, 54, L("ПО QR", "QR", "QR", "QR"), 0);
    else if (idx == MAIN_REFRESH) draw_action(idx, x3, by, bw, 54, L("ОБНОВИТЬ", "REFRESH", "ACTUALISER", "AKTUALISIEREN"), 0);
    else if (idx == MAIN_START) draw_action(idx, x4, by, bw, 54, st.running ? L("ПЕРЕЗАПУСК", "RESTART", "REDÉMARRER", "NEUSTART") : L("СТАРТ", "START", "DÉMARRER", "START"), 0);
}

static void draw_main(void) {
    int i;
    if (!st.ip[0]) { if (selected != MAIN_REFRESH && selected != MAIN_START) selected = MAIN_START; draw_no_wifi(); return; }
    ClearScreen();
    draw_header("WiFiFiles " WF_VERSION);
    draw_main_status();
    for (i = 0; i < MAIN_ROW_COUNT; i++) draw_main_row_idx(i);
    if (st.message[0]) draw_text(font_help, 22, 879, screen_w - 44, 72, st.message, ALIGN_CENTER | VALIGN_MIDDLE | DOTS);
    draw_main_action_idx(MAIN_STOP); draw_main_action_idx(MAIN_PHONE); draw_main_action_idx(MAIN_REFRESH); draw_main_action_idx(MAIN_START);
    finish_screen_update();
}

static void partial_main_item(int idx) {
    if (!st.ip[0]) {
        draw_no_wifi();
        return;
    }
    if (idx >= 0 && idx < MAIN_ROW_COUNT) {
        draw_main_row_idx(idx);
        PartialUpdate(16, main_row_y(idx) - 2, screen_w - 32, MAIN_ROW_H + 4);
    } else if (idx == MAIN_STOP || idx == MAIN_PHONE || idx == MAIN_REFRESH || idx == MAIN_START) {
        draw_main_action_idx(idx);
        PartialUpdate(16, screen_h - MAIN_BUTTON_Y_OFFSET - 2, screen_w - 32, 60);
    }
}

static void partial_main_status(void) {
    draw_main_status();
    PartialUpdate(16, MAIN_STATUS_Y - 2, screen_w - 32, MAIN_STATUS_H + 4);
}

static void draw_current(void);

static void change_selection(int new_selected) {
    int old = selected;
    if (old == new_selected) return;
    selected = new_selected;
    if (screen_mode == MODE_MAIN && st.ip[0]) {
        partial_main_item(old); partial_main_item(new_selected);
    } else {
        draw_current();
    }
}


static const char *instruction_title(int idx) {
    if (idx == 0) return L("HTTP: браузер", "HTTP: browser", "HTTP : navigateur", "HTTP: Browser");
    if (idx == 1) return "WebDAV";
    if (idx == 2) return "FTP";
    return "SMB2 / SMB3";
}
static const char *instruction_summary(int idx) {
    if (idx == 0) return L("Самый простой способ: открыть страницу и загрузить книги", "The easiest way: open a page and upload books", "Le moyen le plus simple : ouvrir une page et envoyer des livres", "Der einfachste Weg: Webseite öffnen und Bücher hochladen");
    if (idx == 1) return L("Сетевая папка в Проводнике Windows", "A network location in Windows File Explorer", "Un emplacement réseau dans l’Explorateur Windows", "Netzwerkadresse im Windows-Explorer");
    if (idx == 2) return L("Для FileZilla, WinSCP и других FTP-клиентов", "For FileZilla, WinSCP and other FTP clients", "Pour FileZilla, WinSCP et les autres clients FTP", "Für FileZilla, WinSCP und andere FTP-Clients");
    return L("SMB на настраиваемом порту, по умолчанию 4445", "SMB on a configurable port, default 4445", "SMB sur un port configurable, 4445 par défaut", "SMB auf einstellbarem Port, Standard 4445");
}

static void append_http_address(char *out, int cap, int dav) {
    scat(out, cap, "http://"); scat(out, cap, st.ip[0] ? st.ip : "—"); scat(out, cap, ":"); append_int(out, cap, st.http_port); if (dav) scat(out, cap, "/dav/"); else scat(out, cap, "/");
}
static void append_http_dav_volume(char *out, int cap, const char *volume) {
    scat(out, cap, "http://"); scat(out, cap, st.ip[0] ? st.ip : "—"); scat(out, cap, ":"); append_int(out, cap, st.http_port); scat(out, cap, "/dav/"); scat(out, cap, volume); scat(out, cap, "/");
}
static void append_ftp_address(char *out, int cap) {
    scat(out, cap, st.ip[0] ? st.ip : "—"); scat(out, cap, ":"); append_int(out, cap, st.ftp_port);
}
static void append_smb_address(char *out, int cap) {
    scat(out, cap, st.ip[0] ? st.ip : "—"); scat(out, cap, ":"); append_int(out, cap, st.smb_port);
}
static void append_password_hint(char *out, int cap) {
    if (st.password_is_default && !password[0]) scat(out, cap, L("Перед запуском задайте новый пароль в WiFiFiles.", "Set a new password in WiFiFiles before starting.", "Définissez un nouveau mot de passe dans WiFiFiles avant le démarrage.", "Legen Sie vor dem Start ein neues Passwort in WiFiFiles fest."));
    else scat(out, cap, L("Пароль: тот, который задан в WiFiFiles.", "Password: the one configured in WiFiFiles.", "Mot de passe : celui défini dans WiFiFiles.", "Passwort: das in WiFiFiles festgelegte Passwort."));
}

static void build_instruction_block(int idx, int block, char *title, int tcap, char *body, int bcap) {
    title[0] = 0; body[0] = 0;
    if (idx == 0) {
        if (block == 0) {
            scopy(title, tcap, L("Когда выбирать HTTP", "When to choose HTTP", "Quand choisir HTTP", "Wann HTTP verwenden"));
            scopy(body, bcap, L("HTTP работает в любом современном браузере и не требует установки программы. Это лучший вариант, когда нужно быстро отправить несколько книг с компьютера или телефона. Включите «HTTP + WebDAV», затем нажмите «Старт».",
                "HTTP works in any modern browser and requires no extra application. It is the best choice for quickly sending a few books from a computer or phone. Enable HTTP + WebDAV, then press Start.",
                "HTTP fonctionne dans tout navigateur moderne et ne nécessite aucune application supplémentaire. C’est le meilleur choix pour envoyer rapidement quelques livres depuis un ordinateur ou un téléphone. Activez « HTTP + WebDAV », puis appuyez sur « Démarrer ».",
                "HTTP funktioniert in jedem modernen Browser und benötigt kein Zusatzprogramm. Es eignet sich am besten, um schnell einige Bücher vom Computer oder Telefon zu übertragen. Aktivieren Sie „HTTP + WebDAV“ und drücken Sie anschließend „Start“."));
        } else if (block == 1) {
            scopy(title, tcap, L("Ваш адрес для входа", "Your connection address", "Votre adresse de connexion", "Ihre Verbindungsadresse"));
            scat(body, bcap, L("Откройте в браузере именно этот адрес:\n", "Open this exact address in a browser:\n", "Ouvrez exactement cette adresse dans le navigateur :\n", "Öffnen Sie genau diese Adresse im Browser:\n"));
            append_http_address(body, bcap, 0);
            scat(body, bcap, L("\n\nЛогин: ", "\n\nUsername: ", "\n\nIdentifiant : ", "\n\nBenutzername: ")); scat(body, bcap, st.username); scat(body, bcap, "\n"); append_password_hint(body, bcap);
            scat(body, bcap, L("\nОба устройства должны быть подключены к одной Wi-Fi-сети.", "\nBoth devices must be connected to the same Wi-Fi network.", "\nLes deux appareils doivent être connectés au même réseau Wi-Fi.", "\nBeide Geräte müssen mit demselben WLAN verbunden sein."));
        } else if (block == 2) {
            scopy(title, tcap, L("Как загрузить книгу", "How to upload a book", "Comment envoyer un livre", "So laden Sie ein Buch hoch"));
            scopy(body, bcap, L("Откройте INTERNAL или SDCARD. В форме загрузки сначала выберите файлы, затем укажите папку назначения — выбранные файлы при смене папки не сбросятся. Нажмите «Загрузить». При совпадении имени приложение отдельно спросит, разрешена ли замена файла.",
                "Open INTERNAL or SDCARD. In the upload form, select the files and then choose the destination folder—the selected files are preserved when the folder changes. Press Upload. If a name already exists, replacement must be explicitly allowed.",
                "Ouvrez INTERNAL ou SDCARD. Dans le formulaire, choisissez les fichiers puis le dossier de destination : les fichiers sélectionnés restent mémorisés. Appuyez sur Envoyer. Si un nom existe déjà, le remplacement doit être autorisé explicitement.",
                "Öffnen Sie INTERNAL oder SDCARD. Wählen Sie im Upload-Formular die Dateien und danach den Zielordner; die Auswahl bleibt beim Ordnerwechsel erhalten. Hochladen drücken. Bei gleichem Namen muss das Ersetzen ausdrücklich erlaubt werden."));
        } else {
            scopy(title, tcap, L("Безопасность и неполадки", "Security and troubleshooting", "Sécurité et dépannage", "Sicherheit und Fehlerbehebung"));
            scopy(body, bcap, L("HTTP не шифрует пароль и файлы, поэтому используйте его только в доверенной домашней сети и не открывайте порт в Интернет. Если страница не открывается: проверьте, что строка HTTP/DAV в статусе показывает адрес, нажмите «Старт», сверьте IP и порт, затем убедитесь, что клиент не подключён к гостевой Wi-Fi-сети.",
                "HTTP does not encrypt the password or files, so use it only on a trusted local network and never expose the port to the Internet. If the page does not open, check that the HTTP/DAV status shows an address, press Start, verify the IP and port, and make sure the client is not on an isolated guest Wi-Fi network.",
                "HTTP ne chiffre ni le mot de passe ni les fichiers. Utilisez-le uniquement sur un réseau local de confiance et n’exposez jamais le port à Internet. Si la page ne s’ouvre pas, vérifiez l’adresse HTTP/DAV, appuyez sur Démarrer, contrôlez l’IP et le port et évitez un réseau Wi-Fi invité isolé.",
                "HTTP verschlüsselt weder Passwort noch Dateien. Nur im vertrauenswürdigen lokalen Netz verwenden und den Port nicht ins Internet freigeben. Wenn die Seite nicht öffnet: HTTP/DAV-Status prüfen, Start drücken, IP und Port vergleichen und sicherstellen, dass der Client nicht in einem isolierten Gast-WLAN ist."));
        }
        return;
    }
    if (idx == 1) {
        if (block == 0) {
            scopy(title, tcap, L("Что даёт WebDAV", "What WebDAV provides", "À quoi sert WebDAV", "Was WebDAV bietet"));
            scopy(body, bcap, L("WebDAV показывает память PocketBook как сетевое расположение. В Windows папки INTERNAL и SDCARD открываются почти как обычные папки: можно копировать, перемещать, переименовывать и удалять файлы. WebDAV работает на том же порту, что и HTTP.",
                "WebDAV exposes PocketBook storage as a network location. In Windows, INTERNAL and SDCARD behave almost like ordinary folders: files can be copied, moved, renamed and deleted. WebDAV uses the same port as HTTP.",
                "WebDAV présente la mémoire du PocketBook comme un emplacement réseau. Sous Windows, INTERNAL et SDCARD se comportent presque comme des dossiers ordinaires : copie, déplacement, renommage et suppression sont possibles. WebDAV utilise le même port que HTTP.",
                "WebDAV stellt den PocketBook-Speicher als Netzwerkadresse bereit. Unter Windows verhalten sich INTERNAL und SDCARD fast wie normale Ordner: Dateien können kopiert, verschoben, umbenannt und gelöscht werden. WebDAV nutzt denselben Port wie HTTP."));
        } else if (block == 1) {
            scopy(title, tcap, L("Адреса WebDAV", "WebDAV addresses", "Adresses WebDAV", "WebDAV-Adressen"));
            scat(body, bcap, L("В Windows добавляйте конкретный накопитель. Внутренняя память:\n", "In Windows, add a specific storage volume. Internal memory:\n", "Sous Windows, ajoutez un stockage précis. Mémoire interne :\n", "Fügen Sie unter Windows einen bestimmten Speicher hinzu. Interner Speicher:\n"));
            append_http_dav_volume(body, bcap, "internal");
            scat(body, bcap, L("\n\nSD-карта:\n", "\n\nSD card:\n", "\n\nCarte SD :\n", "\n\nSD-Karte:\n"));
            append_http_dav_volume(body, bcap, "sd");
            scat(body, bcap, L("\n\nОбщий корень: ", "\n\nCommon root: ", "\n\nRacine commune : ", "\n\nGemeinsames Stammverzeichnis: "));
            append_http_address(body, bcap, 1);
            scat(body, bcap, L("\n\nЛогин: ", "\n\nUsername: ", "\n\nIdentifiant : ", "\n\nBenutzername: ")); scat(body, bcap, st.username); scat(body, bcap, "\n"); append_password_hint(body, bcap);
        } else if (block == 2) {
            scopy(title, tcap, L("Работа в Проводнике", "Using File Explorer", "Utilisation dans l’Explorateur", "Arbeiten im Explorer"));
            scopy(body, bcap, L("Для Windows надёжнее создать два отдельных сетевых расположения: внутреннюю память и SD-карту. После входа копируйте книги обычным перетаскиванием. Перед извлечением карты или остановкой сервера дождитесь завершения копирования. После передачи нажмите «Стоп», если доступ больше не нужен.",
                "For Windows it is more reliable to create two separate network locations: internal memory and the SD card. After signing in, copy books by drag and drop. Wait for transfers to finish before removing the card or stopping the server. Press Stop when network access is no longer needed.",
                "Sous Windows, il est plus fiable de créer deux emplacements réseau distincts : la mémoire interne et la carte SD. Après la connexion, copiez les livres par glisser-déposer. Attendez la fin des transferts avant de retirer la carte ou d’arrêter le serveur. Appuyez sur Arrêt lorsque l’accès n’est plus nécessaire.",
                "Unter Windows ist es zuverlässiger, zwei getrennte Netzwerkadressen anzulegen: interner Speicher und SD-Karte. Nach der Anmeldung Bücher per Drag-and-drop kopieren. Vor dem Entfernen der Karte oder Stoppen des Servers das Ende der Übertragung abwarten. Danach Stopp drücken."));
        } else {
            scopy(title, tcap, L("Если Windows не подключается", "If Windows cannot connect", "Si Windows ne se connecte pas", "Wenn Windows nicht verbindet"));
            scopy(body, bcap, L("Удалите ранее созданное нерабочее сетевое расположение и добавьте его заново с текущим адресом. Проверьте службу Windows WebClient. При необходимости запустите командную строку от администратора и выполните: net stop WebClient, затем net start WebClient. После смены IP всегда используйте новый адрес, показанный приложением.",
                "Remove any previously failed network location and add it again with the current address. Check the Windows WebClient service. If necessary, run an elevated Command Prompt and execute net stop WebClient followed by net start WebClient. After the IP changes, always use the new address shown by the app.",
                "Supprimez l’ancien emplacement réseau en échec et recréez-le avec l’adresse actuelle. Vérifiez le service Windows WebClient. Si nécessaire, ouvrez une invite de commandes administrateur et exécutez net stop WebClient puis net start WebClient. Après un changement d’IP, utilisez toujours la nouvelle adresse affichée.",
                "Entfernen Sie eine zuvor fehlgeschlagene Netzwerkadresse und legen Sie sie mit der aktuellen Adresse neu an. Prüfen Sie den Windows-Dienst WebClient. Falls nötig, Eingabeaufforderung als Administrator öffnen und net stop WebClient sowie danach net start WebClient ausführen. Nach einer IP-Änderung immer die neue angezeigte Adresse verwenden."));
        }
        return;
    }
    if (idx == 2) {
        if (block == 0) {
            scopy(title, tcap, L("Когда использовать FTP", "When to use FTP", "Quand utiliser FTP", "Wann FTP verwenden"));
            scopy(body, bcap, L("FTP удобен для FileZilla, WinSCP и файловых менеджеров, которые поддерживают FTP. Он подходит для больших очередей файлов и привычного двухпанельного интерфейса. Включите FTP и нажмите «Старт».",
                "FTP is convenient with FileZilla, WinSCP and file managers that support FTP. It is useful for large transfer queues and a familiar two-pane interface. Enable FTP and press Start.",
                "FTP est pratique avec FileZilla, WinSCP et les gestionnaires de fichiers compatibles. Il convient aux longues files de transfert et aux interfaces à deux panneaux. Activez FTP, puis appuyez sur « Démarrer ».",
                "FTP ist praktisch mit FileZilla, WinSCP und FTP-fähigen Dateimanagern. Es eignet sich für größere Warteschlangen und eine vertraute Zwei-Fenster-Ansicht. Aktivieren Sie FTP und drücken Sie anschließend „Start“."));
        } else if (block == 1) {
            scopy(title, tcap, L("Параметры подключения", "Connection settings", "Paramètres de connexion", "Verbindungseinstellungen"));
            scat(body, bcap, L("Хост: ", "Host: ", "Hôte : ", "Host: ")); append_ftp_address(body, bcap);
            scat(body, bcap, L("\nПротокол: обычный FTP\nЛогин: ", "\nProtocol: plain FTP\nUsername: ", "\nProtocole : FTP simple\nIdentifiant : ", "\nProtokoll: normales FTP\nBenutzername: ")); scat(body, bcap, st.username); scat(body, bcap, "\n"); append_password_hint(body, bcap);
            scat(body, bcap, L("\nПассивный режим обычно подходит лучше всего.", "\nPassive mode is usually the best choice.", "\nLe mode passif est généralement préférable.", "\nDer passive Modus ist normalerweise die beste Wahl."));
        } else if (block == 2) {
            scopy(title, tcap, L("Папки и передача", "Folders and transfers", "Dossiers et transferts", "Ordner und Übertragung"));
            scopy(body, bcap, L("После входа доступны INTERNAL и SDCARD. Загружайте книги в нужную папку, дождитесь завершения очереди и только затем нажимайте «Стоп». Специализированный FTP-клиент надёжнее встроенной поддержки FTP в Проводнике Windows.",
                "After signing in, INTERNAL and SDCARD are available. Upload books to the required folder, wait for the transfer queue to finish, and only then press Stop. A dedicated FTP client is more reliable than File Explorer's built-in FTP support.",
                "Après la connexion, INTERNAL et SDCARD sont disponibles. Envoyez les livres dans le dossier voulu, attendez la fin de la file puis appuyez sur Arrêt. Un client FTP dédié est plus fiable que la prise en charge FTP de l’Explorateur Windows.",
                "Nach der Anmeldung stehen INTERNAL und SDCARD zur Verfügung. Bücher in den gewünschten Ordner laden, das Ende der Warteschlange abwarten und erst dann Stopp drücken. Ein eigener FTP-Client ist zuverlässiger als die FTP-Funktion des Windows-Explorers."));
        } else {
            scopy(title, tcap, L("Важно о безопасности", "Important security note", "Remarque de sécurité", "Wichtiger Sicherheitshinweis"));
            scopy(body, bcap, L("Обычный FTP не шифрует логин, пароль и содержимое файлов. Используйте его только в своей доверенной локальной сети. Не пробрасывайте FTP-порт на роутере в Интернет. Если соединение не создаётся, проверьте IP, порт, пассивный режим и отсутствие изоляции клиентов Wi-Fi.",
                "Plain FTP does not encrypt the username, password or file contents. Use it only on a trusted local network. Never forward the FTP port to the Internet. If connection fails, verify the IP, port, passive mode and that Wi-Fi client isolation is disabled.",
                "Le FTP simple ne chiffre ni l’identifiant, ni le mot de passe, ni les fichiers. Utilisez-le uniquement sur un réseau local de confiance. Ne redirigez jamais le port FTP vers Internet. En cas d’échec, vérifiez l’IP, le port, le mode passif et l’absence d’isolation Wi-Fi.",
                "Normales FTP verschlüsselt weder Benutzername, Passwort noch Dateiinhalte. Nur im vertrauenswürdigen lokalen Netz verwenden. Den FTP-Port niemals ins Internet weiterleiten. Bei Problemen IP, Port, passiven Modus und WLAN-Client-Isolation prüfen."));
        }
        return;
    }
    if (block == 0) {
        scopy(title, tcap, L("Как работает SMB", "How SMB works", "Fonctionnement de SMB", "So funktioniert SMB"));
        scopy(body, bcap, L("SMB2/SMB3 публикует две сетевые папки: INTERNAL и SDCARD. По умолчанию WiFiFiles использует порт 4445, поэтому приложению не нужны root-права и оно не занимает системный порт 445. Гостевой доступ отключён; используются общий логин и пароль WiFiFiles.",
            "SMB2/SMB3 exposes two shares: INTERNAL and SDCARD. WiFiFiles uses port 4445 by default, so it does not require root access and does not claim the system port 445. Guest access is disabled; the common WiFiFiles username and password are used.",
            "SMB2/SMB3 publie deux partages : INTERNAL et SDCARD. WiFiFiles utilise par défaut le port 4445, sans accès root et sans occuper le port système 445. L’accès invité est désactivé ; l’identifiant et le mot de passe WiFiFiles sont utilisés.",
            "SMB2/SMB3 stellt zwei Freigaben bereit: INTERNAL und SDCARD. WiFiFiles verwendet standardmäßig Port 4445, benötigt daher keine root-Rechte und belegt nicht den Systemport 445. Gastzugriff ist deaktiviert; Benutzername und Passwort von WiFiFiles gelten."));
    } else if (block == 1) {
        scopy(title, tcap, L("Ваш SMB-сервер", "Your SMB server", "Votre serveur SMB", "Ihr SMB-Server"));
        scat(body, bcap, L("Сервер: ", "Server: ", "Serveur : ", "Server: ")); append_smb_address(body, bcap);
        scat(body, bcap, L("\nОбщие ресурсы: INTERNAL и SDCARD\nЛогин: ", "\nShares: INTERNAL and SDCARD\nUsername: ", "\nPartages : INTERNAL et SDCARD\nIdentifiant : ", "\nFreigaben: INTERNAL und SDCARD\nBenutzername: ")); scat(body, bcap, st.username); scat(body, bcap, "\n"); append_password_hint(body, bcap);
        scat(body, bcap, L("\nВ SMB-клиенте порт необходимо указать отдельным полем.", "\nEnter the port in the SMB client's dedicated port field.", "\nIndiquez le port dans le champ dédié du client SMB.", "\nDen Port im dafür vorgesehenen Feld des SMB-Clients angeben."));
    } else if (block == 2) {
        scopy(title, tcap, L("Ограничение Windows", "Windows limitation", "Limitation de Windows", "Windows-Einschränkung"));
        scopy(body, bcap, L("Обычный Проводник Windows не позволяет указать нестандартный SMB-порт и подключается только к порту 445. Поэтому адрес с портом 4445 в Проводнике не заработает. Для Windows используйте WebDAV. SMB подходит Linux и специализированным клиентам, где порт задаётся отдельно.",
            "Standard Windows File Explorer cannot specify a custom SMB port and connects only to port 445. Therefore an address using port 4445 will not work in File Explorer. Use WebDAV on Windows. SMB is suitable for Linux and dedicated clients that allow a separate port.",
            "L’Explorateur Windows standard ne permet pas d’indiquer un port SMB personnalisé et utilise uniquement le port 445. Une adresse avec le port 4445 ne fonctionnera donc pas. Sous Windows, utilisez WebDAV. SMB convient à Linux et aux clients spécialisés permettant de définir le port.",
            "Der normale Windows-Explorer kann keinen abweichenden SMB-Port angeben und verbindet nur mit Port 445. Eine Adresse mit Port 4445 funktioniert dort daher nicht. Unter Windows WebDAV verwenden. SMB eignet sich für Linux und spezielle Clients mit eigener Porteinstellung."));
    } else {
        scopy(title, tcap, L("Пример и неполадки", "Example and troubleshooting", "Exemple et dépannage", "Beispiel und Fehlerbehebung"));
        scat(body, bcap, L("Пример для Linux:\nsmbclient -p ", "Linux example:\nsmbclient -p ", "Exemple Linux :\nsmbclient -p ", "Linux-Beispiel:\nsmbclient -p ")); append_int(body, bcap, st.smb_port); scat(body, bcap, " //"); scat(body, bcap, st.ip); scat(body, bcap, "/INTERNAL -U "); scat(body, bcap, st.username);
        scat(body, bcap, L("\n\nЕсли клиент не подключается, проверьте поддержку SMB2/SMB3, правильность порта и отсутствие изоляции устройств в Wi-Fi-сети.", "\n\nIf the client cannot connect, verify SMB2/SMB3 support, the configured port and that devices are not isolated on the Wi-Fi network.", "\n\nSi le client ne se connecte pas, vérifiez la prise en charge de SMB2/SMB3, le port et l’absence d’isolation des appareils Wi-Fi.", "\n\nWenn der Client nicht verbindet, SMB2/SMB3-Unterstützung, den Port und eine mögliche WLAN-Geräteisolation prüfen."));
    }
}

static int utf8_char_len(unsigned char c) {
    if ((c & 0x80) == 0) return 1;
    if ((c & 0xe0) == 0xc0) return 2;
    if ((c & 0xf0) == 0xe0) return 3;
    if ((c & 0xf8) == 0xf0) return 4;
    return 1;
}

static int estimate_text_lines(const char *text, int max_columns) {
    int lines = 1, column = 0, i = 0, step;
    if (!text || !text[0]) return 0;
    if (max_columns < 8) max_columns = 8;
    while (text[i]) {
        if (text[i] == '\n') {
            lines++;
            column = 0;
            i++;
            continue;
        }
        step = utf8_char_len((unsigned char)text[i]);
        column++;
        if (column >= max_columns) {
            lines++;
            column = 0;
        }
        i += step;
    }
    return lines;
}

static int instruction_title_area_height(const char *title) {
    int size = instruction_title_size();
    int columns = instruction_font_scale == 0 ? 58 : (instruction_font_scale == 2 ? 43 : 50);
    int lines = estimate_text_lines(title, columns);
    int height = 12 + lines * (size + 5) + 8;
    if (height < 48) height = 48;
    return height;
}

static int instruction_card_height(const char *title, const char *body) {
    int columns = instruction_font_scale == 0 ? 72 : (instruction_font_scale == 2 ? 53 : 62);
    int lines = estimate_text_lines(body, columns);
    int height = instruction_title_area_height(title) + 12 + lines * instruction_line_height() + 15;
    if (height < 118) height = 118;
    return height;
}

static int instruction_layout(int *page_start, int *page_count_blocks) {
    char title[96], body[1100];
    int page = 0, block, used = 0, count = 0;
    int available = screen_h - 84 - 72 - 38;
    if (available < 300) available = 300;
    page_start[0] = 0;
    page_count_blocks[0] = 0;
    for (block = 0; block < 4; block++) {
        int height;
        build_instruction_block(instruction_index, block, title, sizeof(title), body, sizeof(body));
        height = instruction_card_height(title, body);
        if (count > 0 && used + 10 + height > available) {
            page_count_blocks[page] = count;
            page++;
            page_start[page] = block;
            used = 0;
            count = 0;
        }
        if (count > 0) used += 10;
        used += height;
        count++;
    }
    page_count_blocks[page] = count;
    if (page == 1 && page_count_blocks[0] == 3 && page_count_blocks[1] == 1) {
        page_count_blocks[0] = 2;
        page_start[1] = 2;
        page_count_blocks[1] = 2;
    }
    return page + 1;
}

static void draw_instruction_menu(void) {
    int y = 118, i, by = screen_h - 72;
    ClearScreen(); draw_header(L("Инструкции", "Instructions", "Instructions", "Anleitungen"));
    draw_text(font_main, 24, 76, screen_w - 48, 34,
        L("Выберите способ подключения", "Choose a connection method", "Choisissez une méthode de connexion", "Verbindungsmethode wählen"),
        ALIGN_CENTER | VALIGN_MIDDLE);
    for (i = 0; i < 4; i++) {
        FillArea(18, y, screen_w - 36, 128, selected == i ? LGRAY : WHITE);
        DrawRect(18, y, screen_w - 36, 128, BLACK);
        draw_text(font_instruction_title, 32, y + 8, screen_w - 76, 38, instruction_title(i), ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
        draw_text(font_instruction, 32, y + 48, screen_w - 90, 66, instruction_summary(i), ALIGN_LEFT | VALIGN_TOP | DOTS);
        draw_text(font_main, screen_w - 58, y, 30, 128, ">", ALIGN_CENTER | VALIGN_MIDDLE);
        y += 142;
    }
    draw_action(4, 18, by, 220, 54, L("НАЗАД", "BACK", "RETOUR", "ZURÜCK"), 0);
    draw_action(5, screen_w - 238, by, 220, 54, instruction_font_label(), 0);
    finish_screen_update();
}

static void draw_instruction_card(int y, int height, const char *title, const char *body) {
    int title_h = instruction_title_area_height(title);
    FillArea(18, y, screen_w - 36, height, WHITE);
    DrawRect(18, y, screen_w - 36, height, BLACK);
    FillArea(18, y, screen_w - 36, title_h, VLGRAY);
    DrawLine(18, y + title_h, screen_w - 18, y + title_h, BLACK);
    draw_text(font_instruction_title, 32, y + 4, screen_w - 64, title_h - 8, title, ALIGN_LEFT | VALIGN_MIDDLE);
    draw_text(font_instruction, 32, y + title_h + 9, screen_w - 64, height - title_h - 18, body, ALIGN_LEFT | VALIGN_TOP);
}

static void draw_instruction_detail(void) {
    char title[96], body[1100], page_label[32];
    int starts[4] = {0,0,0,0}, counts[4] = {0,0,0,0};
    int pages = instruction_layout(starts, counts);
    int by = screen_h - 72, y = 84, i;
    if (instruction_page >= pages) instruction_page = pages - 1;
    if (instruction_page < 0) instruction_page = 0;
    ClearScreen(); draw_header(instruction_title(instruction_index));
    for (i = 0; i < counts[instruction_page]; i++) {
        int block = starts[instruction_page] + i;
        int height;
        build_instruction_block(instruction_index, block, title, sizeof(title), body, sizeof(body));
        height = instruction_card_height(title, body);
        draw_instruction_card(y, height, title, body);
        y += height + 10;
    }
    if (pages > 1) {
        page_label[0] = 0;
        append_int(page_label, sizeof(page_label), instruction_page + 1);
        scat(page_label, sizeof(page_label), " / ");
        append_int(page_label, sizeof(page_label), pages);
        draw_text(font_main, 18, by - 38, screen_w - 36, 32, page_label, ALIGN_CENTER | VALIGN_MIDDLE);
    }
    draw_action(0, 18, by, 210, 54, L("К СПИСКУ", "TO LIST", "LISTE", "ZUR LISTE"), 0);
    draw_action(1, (screen_w - 210) / 2, by, 210, 54, L("НАЗАД", "PREVIOUS", "PRÉCÉDENT", "ZURÜCK"), instruction_page == 0);
    draw_action(2, screen_w - 228, by, 210, 54, L("ДАЛЕЕ", "NEXT", "SUIVANT", "WEITER"), instruction_page >= pages - 1);
    finish_screen_update();
}

static void draw_language(void) {
    const char *names[4] = {"Русский", "English", "Français", "Deutsch"};
    int i, y = 170, by = screen_h - 72;
    ClearScreen(); draw_header("WiFiFiles — Language");
    draw_text(font_main, 25, 88, screen_w - 50, 58, "Выберите язык / Choose language", ALIGN_CENTER | VALIGN_MIDDLE);
    for (i = 0; i < 4; i++) {
        FillArea(75, y, screen_w - 150, 92, selected == i ? LGRAY : WHITE);
        DrawRect(75, y, screen_w - 150, 92, BLACK);
        draw_text(font_main, 85, y, screen_w - 170, 92, names[i], ALIGN_CENTER | VALIGN_MIDDLE);
        y += 112;
    }
    if (st.language[0]) draw_action(4, 18, by, 220, 54, L("НАЗАД", "BACK", "RETOUR", "ZURÜCK"), 0);
    finish_screen_update();
}

static void draw_storage_picker(void) {
    char default_label[320];
    int y = 220, by = screen_h - 72;
    ClearScreen();
    if (settings_picker_mode) {
        draw_header(L("Настройки — папка по умолчанию", "Settings — default folder", "Réglages — dossier par défaut", "Einstellungen — Standardordner"));
        draw_text(font_main, 34, 92, screen_w - 68, 92,
            L("Выберите память. На следующем экране откройте папку, которая станет папкой по умолчанию.",
              "Choose the storage. On the next screen open the folder that will become the default folder.",
              "Choisissez la mémoire. À l'écran suivant, ouvrez le dossier qui deviendra le dossier par défaut.",
              "Wählen Sie den Speicher. Öffnen Sie im nächsten Bildschirm den Ordner, der zum Standardordner wird."),
            ALIGN_CENTER | VALIGN_MIDDLE);
    } else {
        draw_header(L("Передача с телефона по QR-коду", "Phone transfer by QR code", "Transfert depuis un téléphone par code QR", "Übertragung vom Telefon per QR-Code"));
        draw_text(font_main, 34, 92, screen_w - 68, 92,
            L("Сначала выберите память. На следующем экране можно открыть любую папку и указать, куда сохранять книги.",
              "First choose the storage. On the next screen you can open any folder and select where books will be saved.",
              "Choisissez d'abord la mémoire. À l'écran suivant, vous pourrez ouvrir n'importe quel dossier et choisir où enregistrer les livres.",
              "Wählen Sie zuerst den Speicher. Im nächsten Bildschirm können Sie jeden Ordner öffnen und als Ziel auswählen."),
            ALIGN_CENTER | VALIGN_MIDDLE);
    }
    draw_row(0, y, L("Память ридера", "Reader storage", "Mémoire du lecteur", "Reader-Speicher"), st.internal_enabled ? ">" : L("ВЫКЛ", "OFF", "DÉSACTIVÉ", "AUS"), !st.internal_enabled);
    if (st.internal_enabled && st.free_internal[0]) {
        char free_label[96];
        free_label[0] = 0;
        scat(free_label, sizeof(free_label), L("Свободно: ", "Free: ", "Libre : ", "Frei: "));
        scat(free_label, sizeof(free_label), st.free_internal);
        draw_text(font_help, 34, y + 44, screen_w - 68, 22, free_label, ALIGN_LEFT | VALIGN_MIDDLE);
    }
    draw_row(1, y + 70, L("Карта памяти SD", "SD card", "Carte SD", "SD-Karte"), st.sd_enabled ? ">" : L("ВЫКЛ", "OFF", "DÉSACTIVÉ", "AUS"), !st.sd_enabled);
    if (st.sd_enabled && st.free_sd[0]) {
        char free_label[96];
        free_label[0] = 0;
        scat(free_label, sizeof(free_label), L("Свободно: ", "Free: ", "Libre : ", "Frei: "));
        scat(free_label, sizeof(free_label), st.free_sd);
        draw_text(font_help, 34, y + 114, screen_w - 68, 22, free_label, ALIGN_LEFT | VALIGN_MIDDLE);
    }
    if (!settings_picker_mode) {
        if (st.default_target[0]) {
            char path_label[280];
            virtual_path_label(st.default_target, path_label, sizeof(path_label));
            default_label[0] = 0;
            scat(default_label, sizeof(default_label), L("По умолчанию: ", "Default: ", "Par défaut : ", "Standard: "));
            scat(default_label, sizeof(default_label), path_label);
            draw_row(STORAGE_DEFAULT, y + 140, default_label, ">", 0);
        }
        {
            int i, rows = 0;
            for (i = 0; i < 4; i++) if (st.recent_targets[i][0]) rows = i + 1;
            if (rows > 0) {
                char recent_label[320];
                draw_text(font_help, 34, y + 192, screen_w - 68, 24,
                    L("Недавние: ", "Recent: ", "Récents : ", "Zuletzt: "), ALIGN_LEFT | VALIGN_MIDDLE);
                for (i = 0; i < rows; i++) {
                    char path_label[280];
                    virtual_path_label(st.recent_targets[i], path_label, sizeof(path_label));
                    recent_label[0] = 0;
                    scat(recent_label, sizeof(recent_label), "· ");
                    scat(recent_label, sizeof(recent_label), path_label);
                    draw_row(STORAGE_RECENT1 + i, y + 214 + i * 70, recent_label, ">", 0);
                }
            }
        }
    }
    draw_action(STORAGE_BACK, 18, by, 220, 54, L("НАЗАД", "BACK", "RETOUR", "ZURÜCK"), 0);
    finish_screen_update();
}

static void draw_folder_picker(void) {
    char path_label[420], page_label[64];
    int i, visible = folder_visible_count(), start = folder_page * FOLDER_PAGE_SIZE;
    int y = 225, by = screen_h - 72;
    int bw = (screen_w - 60) / 4;
    int x1 = 18, x2 = x1 + bw + 8, x3 = x2 + bw + 8, x4 = x3 + bw + 8;
    int half_w = (screen_w - 44) / 2;
    ClearScreen();
    draw_header(L("Выберите папку", "Choose a folder", "Choisir un dossier", "Ordner auswählen"));
    virtual_path_label(folder_current, path_label, sizeof(path_label));
    FillArea(18, 78, screen_w - 36, 58, VLGRAY); DrawRect(18, 78, screen_w - 36, 58, BLACK);
    draw_text(font_main, 30, 81, screen_w - 60, 52, path_label, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
    FillArea(18, 150, half_w, 58, selected == 0 ? LGRAY : WHITE); DrawRect(18, 150, half_w, 58, BLACK);
    draw_text(font_block_title, 20, 150, half_w - 16, 58,
        L("✓ СОХРАНИТЬ", "✓ SAVE", "✓ ENREGISTRER", "✓ SPEICHERN"),
        ALIGN_CENTER | VALIGN_MIDDLE | DOTS);
    FillArea(26 + half_w, 150, half_w, 58, selected == FOLDER_REMEMBER ? LGRAY : WHITE); DrawRect(26 + half_w, 150, half_w, 58, BLACK);
    draw_text(font_block_title, 28 + half_w, 150, half_w - 16, 58,
        L("★ ЗАПОМНИТЬ", "★ REMEMBER", "★ MÉMORISER", "★ MERKEN"),
        ALIGN_CENTER | VALIGN_MIDDLE | DOTS);
    for (i = 0; i < visible; i++) {
        int idx = i + 1;
        FillArea(18, y, screen_w - 36, 54, selected == idx ? LGRAY : WHITE);
        DrawRect(18, y, screen_w - 36, 54, BLACK);
        draw_text(font_main, 32, y, screen_w - 100, 54, folder_names[start + i], ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
        draw_text(font_main, screen_w - 62, y, 32, 54, ">", ALIGN_CENTER | VALIGN_MIDDLE);
        y += 62;
    }
    if (folder_count == 0) {
        draw_text(font_help, 32, 300, screen_w - 64, 90,
            L("В этой папке нет вложенных папок. Можно сохранить книгу сюда.", "This folder has no subfolders. You can save the book here.", "Ce dossier ne contient aucun sous-dossier. Vous pouvez enregistrer le livre ici.", "Dieser Ordner enthält keine Unterordner. Das Buch kann hier gespeichert werden."),
            ALIGN_CENTER | VALIGN_MIDDLE);
    }
    page_label[0] = 0;
    if (folder_count > FOLDER_PAGE_SIZE) {
        append_int(page_label, sizeof(page_label), folder_page + 1); scat(page_label, sizeof(page_label), " / "); append_int(page_label, sizeof(page_label), (folder_count + FOLDER_PAGE_SIZE - 1) / FOLDER_PAGE_SIZE);
        draw_text(font_small, 18, by - 38, screen_w - 36, 30, page_label, ALIGN_CENTER | VALIGN_MIDDLE);
    }
    if (folder_total > folder_count) {
        char shown_label[48];
        scopy(shown_label, sizeof(shown_label), L("Показано ", "Showing ", "Affiché ", "Gezeigt "));
        append_int(shown_label, sizeof(shown_label), folder_count);
        scat(shown_label, sizeof(shown_label), L(" из ", " of ", " sur ", " von "));
        append_int(shown_label, sizeof(shown_label), folder_total);
        draw_text(font_small, 18, by - 38, screen_w - 36, 30, shown_label, ALIGN_LEFT | VALIGN_MIDDLE);
    }
    draw_action(FOLDER_BACK, x1, by, bw, 54, L("НАЗАД", "BACK", "RETOUR", "ZURÜCK"), 0);
    draw_action(FOLDER_UP, x2, by, bw, 54, L("ВВЕРХ", "UP", "DOSSIER PARENT", "HOCH"), folder_parent[0] == 0);
    draw_action(FOLDER_PREV, x3, by, bw, 54, L("ПРЕД.", "PREV.", "PRÉC.", "ZURÜCK"), folder_page == 0);
    draw_action(FOLDER_NEXT, x4, by, bw, 54, L("СЛЕД.", "NEXT", "SUIV.", "WEITER"), start + visible >= folder_count);
    finish_screen_update();
}

static void draw_qr_mode(void) {
    int by = screen_h - 72;
    ClearScreen();
    draw_header(L("Режим передачи по QR-коду", "QR transfer mode", "Mode de transfert par QR code", "QR-Übertragungsmodus"));
    draw_text(font_main, 34, 84, screen_w - 68, 76,
        L("Выбранная папка будет единственной доступной с телефона.",
          "Only the selected folder will be accessible from the phone.",
          "Seul le dossier sélectionné sera accessible depuis le téléphone.",
          "Vom Telefon ist nur der ausgewählte Ordner erreichbar."),
        ALIGN_CENTER | VALIGN_MIDDLE);
    FillArea(18, 190, screen_w - 36, 118, selected == QR_MODE_SAFE ? LGRAY : WHITE); DrawRect(18, 190, screen_w - 36, 118, BLACK);
    draw_text(font_block_title, 32, 198, screen_w - 64, 38,
        L("БЕЗОПАСНЫЙ РЕЖИМ", "SAFE MODE", "MODE SÉCURISÉ", "SICHERER MODUS"), ALIGN_CENTER | VALIGN_MIDDLE);
    draw_text(font_help, 40, 238, screen_w - 80, 58,
        L("Просмотр списка и отправка книг. Скачивание, удаление и переименование запрещены.",
          "View the list and send books. Download, delete and rename are disabled.",
          "Consultez la liste et envoyez des livres. Téléchargement, suppression et renommage sont désactivés.",
          "Liste ansehen und Bücher senden. Herunterladen, Löschen und Umbenennen sind deaktiviert."), ALIGN_CENTER | VALIGN_MIDDLE);
    FillArea(18, 332, screen_w - 36, 138, selected == QR_MODE_EDIT ? LGRAY : WHITE); DrawRect(18, 332, screen_w - 36, 138, BLACK);
    draw_text(font_block_title, 32, 340, screen_w - 64, 38,
        L("РЕЖИМ РЕДАКТИРОВАНИЯ", "EDIT MODE", "MODE ÉDITION", "BEARBEITUNGSMODUS"), ALIGN_CENTER | VALIGN_MIDDLE);
    draw_text(font_help, 40, 380, screen_w - 80, 76,
        L("Отправка и скачивание книг, переименование и удаление — только в выбранной папке.",
          "Upload and download books, rename and delete — only inside the selected folder.",
          "Envoyez et téléchargez des livres, renommez et supprimez — uniquement dans le dossier sélectionné.",
          "Bücher hoch- und herunterladen, umbenennen und löschen — nur im ausgewählten Ordner."), ALIGN_CENTER | VALIGN_MIDDLE);
    draw_action(QR_MODE_BACK, 18, by, 220, 54, L("НАЗАД", "BACK", "RETOUR", "ZURÜCK"), 0);
    finish_screen_update();
}

static void draw_qr_screen(void) {
    char path_label[420];
    int module = 12, quiet = 4, total, x0, y0 = 158, x, y;
    int by = screen_h - 72;
    int bw = (screen_w - 44) / 2;
    ClearScreen();
    draw_header(L("Передача с телефона по QR-коду", "Phone transfer by QR code", "Transfert depuis un téléphone par code QR", "Übertragung vom Telefon per QR-Code"));
    virtual_path_label(qr_target, path_label, sizeof(path_label));
    draw_text(font_small, 24, 70, screen_w - 48, 32, seq(qr_access_mode, "edit") ? L("Режим редактирования", "Edit mode", "Mode édition", "Bearbeitungsmodus") : L("Безопасный режим", "Safe mode", "Mode sécurisé", "Sicherer Modus"), ALIGN_CENTER | VALIGN_MIDDLE);
    draw_text(font_main, 24, 101, screen_w - 48, 42, path_label, ALIGN_CENTER | VALIGN_MIDDLE | DOTS);
    total = (qr_size + quiet * 2) * module;
    x0 = (screen_w - total) / 2;
    FillArea(x0, y0, total, total, WHITE);
    DrawRect(x0, y0, total, total, BLACK);
    for (y = 0; y < qr_size; y++) {
        for (x = 0; x < qr_size; x++) {
            if (qr_rows[y][x] == '1') FillArea(x0 + (x + quiet) * module, y0 + (y + quiet) * module, module, module, BLACK);
        }
    }
    draw_text(font_small, 25, y0 + total + 8, screen_w - 50, 34, qr_url, ALIGN_CENTER | VALIGN_MIDDLE | DOTS);
    draw_text(font_help, 36, y0 + total + 45, screen_w - 72, 86,
        seq(qr_access_mode, "edit") ?
        L("Отсканируйте код телефоном. В выбранной папке можно отправлять и скачивать книги, переименовывать и удалять файлы. Ссылка действует 20 минут.",
          "Scan the code with a phone. In the selected folder you can upload and download books, rename and delete files. The link is valid for 20 minutes.",
          "Scannez le code avec un téléphone. Dans le dossier sélectionné, vous pouvez envoyer et télécharger des livres, renommer et supprimer des fichiers. Le lien reste valide 20 minutes.",
          "Scannen Sie den Code mit einem Telefon. Im ausgewählten Ordner können Bücher hoch- und heruntergeladen sowie Dateien umbenannt und gelöscht werden. Der Link ist 20 Minuten gültig.") :
        L("Отсканируйте код телефоном. Можно видеть содержимое выбранной папки и только отправлять в неё книги. Ссылка действует 20 минут.",
          "Scan the code with a phone. You can view the selected folder and only send books to it. The link is valid for 20 minutes.",
          "Scannez le code avec un téléphone. Vous pouvez voir le contenu du dossier sélectionné et uniquement y envoyer des livres. Le lien reste valide 20 minutes.",
          "Scannen Sie den Code mit einem Telefon. Sie können den Inhalt des ausgewählten Ordners sehen und nur Bücher dorthin senden. Der Link ist 20 Minuten gültig."),
        ALIGN_CENTER | VALIGN_TOP);
    draw_action(QR_BACK, 18, by, bw, 54, L("ГОТОВО", "DONE", "TERMINÉ", "FERTIG"), 0);
    draw_action(QR_CHANGE_FOLDER, 26 + bw, by, bw, 54, L("ДРУГАЯ ПАПКА", "CHANGE FOLDER", "AUTRE DOSSIER", "ANDERER ORDNER"), 0);
    finish_screen_update();
}

static void draw_settings(void) {
    char val[280], label[96];
    int y = 210, by = screen_h - 72;
    ClearScreen();
    draw_header(L("Настройки", "Settings", "Réglages", "Einstellungen"));
    draw_row(0, y, L("Язык", "Language", "Langue", "Sprache"), lang_label(), 0);
    if (st.default_target[0]) virtual_path_label(st.default_target, val, sizeof(val));
    else scopy(val, sizeof(val), L("—", "—", "—", "—"));
    draw_row(1, y + 70, L("Папка по умолчанию", "Default folder", "Dossier par défaut", "Standardordner"), val, 0);
    if (update_latest[0]) {
        scopy(label, sizeof(label), L("Обновить до ", "Update to ", "Mettre à jour vers ", "Aktualisieren auf "));
        scat(label, sizeof(label), update_latest);
    } else {
        scopy(label, sizeof(label), L("Проверить обновления", "Check for updates", "Rechercher des mises à jour", "Nach Updates suchen"));
    }
    draw_row(2, y + 140, label, "", 0);
    draw_row(3, y + 210, L("Журнал операций", "Operation log", "Journal des opérations", "Vorgangsprotokoll"), "", 0);
    draw_action(4, 18, by, 220, 54, L("НАЗАД", "BACK", "RETOUR", "ZURÜCK"), 0);
    finish_screen_update();
}

static void draw_log(void) {
    char *p;
    int y = 210, shown = 0;
    ClearScreen();
    draw_header(L("Журнал операций", "Operation log", "Journal des opérations", "Vorgangsprotokoll"));
    p = st.recent_log;
    while (*p && shown < 12 && y < screen_h - 96) {
        char item[128];
        int i = 0;
        while (*p && *p != 1 && i < sizeof(item) - 1) item[i++] = *p++;
        item[i] = 0;
        if (*p == 1) p++;
        if (item[0]) {
            draw_text(font_small, 36, y, screen_w - 72, 26, item, ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
            y += 28;
            shown++;
        }
    }
    if (!st.recent_log[0]) {
        draw_text(font_help, 36, y, screen_w - 72, 28,
            L("Пока нет операций", "No operations yet", "Aucune opération pour l’instant", "Noch keine Vorgänge"),
            ALIGN_LEFT | VALIGN_MIDDLE | DOTS);
    }
    draw_action(LOG_BACK, 18, screen_h - 72, 220, 54, L("НАЗАД", "BACK", "RETOUR", "ZURÜCK"), 0);
    finish_screen_update();
}

static void run_update_action(void) {
    char data[1536];
    char status[16], latest[32], message[512];
    ShowHourglass();
    run_helper(update_latest[0] ? "--native-update-install" : "--native-update-check");
    HideHourglass();
    status[0] = latest[0] = message[0] = 0;
    if (read_all(UPDATE_STATUS_PATH, data, sizeof(data)) < 0) {
        Message(ICON_ERROR, L("Обновления", "Updates", "Mises à jour", "Updates"),
            L("Не удалось проверить обновления", "Update check failed", "Échec de la recherche de mises à jour", "Update-Prüfung fehlgeschlagen"), 3600);
        return;
    }
    ini_value(data, "status", status, sizeof(status));
    ini_value(data, "latest", latest, sizeof(latest));
    ini_value(data, "message", message, sizeof(message));
    if (seq(status, "latest")) {
        update_latest[0] = 0;
        Message(ICON_INFORMATION, L("Обновления", "Updates", "Mises à jour", "Updates"),
            L("Установлена последняя версия", "The latest version is installed", "La dernière version est installée", "Die neueste Version ist installiert"), 3000);
    } else if (seq(status, "found")) {
        char msg[160];
        scopy(update_latest, sizeof(update_latest), latest);
        scopy(msg, sizeof(msg), L("Доступна версия ", "Version ", "Version ", "Version "));
        scat(msg, sizeof(msg), latest);
        scat(msg, sizeof(msg), L(". Нажмите ещё раз, чтобы обновить.", ". Press again to update.", ". Appuyez à nouveau pour mettre à jour.", ". Erneut drücken, um zu aktualisieren."));
        Message(ICON_INFORMATION, L("Обновления", "Updates", "Mises à jour", "Updates"), msg, 4200);
    } else if (seq(status, "updated")) {
        char msg[160];
        update_latest[0] = 0;
        scopy(msg, sizeof(msg), L("Обновлено до версии ", "Updated to version ", "Mis à jour vers la version ", "Aktualisiert auf Version "));
        scat(msg, sizeof(msg), latest);
        scat(msg, sizeof(msg), L(". Закройте и снова откройте приложение.", ". Close and reopen the app.", ". Fermez puis rouvrez l'application.", ". App schließen und neu öffnen."));
        Message(ICON_INFORMATION, L("Обновления", "Updates", "Mises à jour", "Updates"), msg, 4200);
    } else {
        update_latest[0] = 0;
        Message(ICON_ERROR, L("Обновления", "Updates", "Mises à jour", "Updates"),
            message[0] ? message : L("Ошибка обновления", "Update error", "Erreur de mise à jour", "Update-Fehler"), 4200);
    }
    draw_current();
}

static void draw_current(void) {
    if (screen_mode == MODE_LANGUAGE) draw_language();
    else if (screen_mode == MODE_INSTRUCTIONS) draw_instruction_menu();
    else if (screen_mode == MODE_INSTRUCTION_DETAIL) draw_instruction_detail();
    else if (screen_mode == MODE_STORAGE_PICKER) draw_storage_picker();
    else if (screen_mode == MODE_FOLDER_PICKER) draw_folder_picker();
    else if (screen_mode == MODE_QR_MODE) draw_qr_mode();
    else if (screen_mode == MODE_QR) draw_qr_screen();
    else if (screen_mode == MODE_SETTINGS) draw_settings();
    else if (screen_mode == MODE_LOG) draw_log();
    else draw_main();
}

static void keyboard_done(char *text) {
    if (!text) { edit_mode = 0; draw_current(); return; }
    if (edit_mode == 1) { scopy(st.username, sizeof(st.username), text); dirty = 1; }
    else if (edit_mode == 2) { scopy(password, sizeof(password), text); if (password[0]) dirty = 1; }
    else if (edit_mode == 3) { int p = atoi10(text); if (p >= 1024 && p <= 65535) { st.http_port = p; dirty = 1; } else Message(ICON_WARNING, L("Порт HTTP/DAV", "HTTP/DAV port", "Port HTTP/DAV", "HTTP/DAV-Port"), L("Введите число от 1024 до 65535", "Enter a number from 1024 to 65535", "Entrez un nombre de 1024 à 65535", "Zahl von 1024 bis 65535 eingeben"), 2400); }
    else if (edit_mode == 4) { int p = atoi10(text); if (p >= 1024 && p <= 65535) { st.ftp_port = p; dirty = 1; } else Message(ICON_WARNING, L("Порт FTP", "FTP port", "Port FTP", "FTP-Port"), L("Введите число от 1024 до 65535", "Enter a number from 1024 to 65535", "Entrez un nombre de 1024 à 65535", "Zahl von 1024 bis 65535 eingeben"), 2400); }
    else if (edit_mode == 5) { int p = atoi10(text); if (p >= 1024 && p <= 65535) { st.smb_port = p; dirty = 1; } else Message(ICON_WARNING, L("Порт SMB", "SMB port", "Port SMB", "SMB-Port"), L("Введите число от 1024 до 65535", "Enter a number from 1024 to 65535", "Entrez un nombre de 1024 à 65535", "Zahl von 1024 bis 65535 eingeben"), 2400); }
    edit_mode = 0; draw_current();
}
static void open_edit(int mode) {
    edit_mode = mode; keyboard_buf[0] = 0;
    if (mode == 1) { scopy(keyboard_buf, sizeof(keyboard_buf), st.username); OpenKeyboard(L("Логин", "Username", "Identifiant", "Benutzername"), keyboard_buf, 32, KBD_ENTEXT, keyboard_done); }
    else if (mode == 2) { OpenKeyboard(L("Новый пароль — минимум 6 символов", "New password — at least 6 characters", "Nouveau mot de passe — 6 caractères minimum", "Neues Passwort — mindestens 6 Zeichen"), keyboard_buf, 128, KBD_ENTEXT | KBD_PASSWORD, keyboard_done); }
    else if (mode == 3) { append_int(keyboard_buf, sizeof(keyboard_buf), st.http_port); OpenKeyboard(L("Порт HTTP/DAV", "HTTP/DAV port", "Port HTTP/DAV", "HTTP/DAV-Port"), keyboard_buf, 5, KBD_NUMERIC, keyboard_done); }
    else if (mode == 4) { append_int(keyboard_buf, sizeof(keyboard_buf), st.ftp_port); OpenKeyboard(L("Порт FTP", "FTP port", "Port FTP", "FTP-Port"), keyboard_buf, 5, KBD_NUMERIC, keyboard_done); }
    else if (mode == 5) { append_int(keyboard_buf, sizeof(keyboard_buf), st.smb_port); OpenKeyboard(L("Порт SMB", "SMB port", "Port SMB", "SMB-Port"), keyboard_buf, 5, KBD_NUMERIC, keyboard_done); }
}

static int write_language_file(int lang) {
    char b[32]; b[0] = 0; scat(b, sizeof(b), "language="); scat(b, sizeof(b), lang_code(lang)); scat(b, sizeof(b), "\n");
    return write_all(LANGUAGE_PATH, b);
}
static void choose_language(int lang) {
    int return_mode = language_return_mode;
    if (write_language_file(lang) < 0) { Message(ICON_ERROR, "WiFiFiles", L("Не удалось сохранить язык", "Cannot save language", "Impossible d’enregistrer la langue", "Sprache konnte nicht gespeichert werden"), 2400); return; }
    ShowHourglass();
    if (run_helper("--native-set-language-file") != 0) {
        HideHourglass();
        Message(ICON_ERROR, "WiFiFiles", L("Не удалось применить язык", "Cannot apply language", "Impossible d’appliquer la langue", "Sprache konnte nicht angewendet werden"), 2800);
        return;
    }
    load_state(); HideHourglass();
    current_lang = lang; scopy(st.language, sizeof(st.language), lang_code(lang));
    screen_mode = return_mode; selected = 0; draw_current();
    if (screen_mode == MODE_MAIN && !st.ip[0]) start_wifi_refresh();
    else if (st.ip[0]) show_open_wifi_warning();
}

static int write_apply_file(void) {
    char b[1280]; b[0] = 0;
    scat(b,sizeof(b),"http_enabled="); append_int(b,sizeof(b),st.http_enabled); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"http_port="); append_int(b,sizeof(b),st.http_port); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"ftp_enabled="); append_int(b,sizeof(b),st.ftp_enabled); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"ftp_port="); append_int(b,sizeof(b),st.ftp_port); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"smb_enabled="); append_int(b,sizeof(b),st.smb_enabled); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"smb_port="); append_int(b,sizeof(b),st.smb_port); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"internal_enabled="); append_int(b,sizeof(b),st.internal_enabled); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"sd_enabled="); append_int(b,sizeof(b),st.sd_enabled); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"logging_enabled="); append_int(b,sizeof(b),st.logging_enabled); scat(b,sizeof(b),"\n");
    scat(b,sizeof(b),"username="); scat(b,sizeof(b),st.username); scat(b,sizeof(b),"\npassword="); scat(b,sizeof(b),password); scat(b,sizeof(b),"\nlanguage="); scat(b,sizeof(b),lang_code(current_lang)); scat(b,sizeof(b),"\n");
    return write_all(APPLY_PATH,b);
}
static void start_services(void) {
    log_line("start services");
    if (!st.ip[0]) { Message(ICON_WARNING, "Wi-Fi", L("Сначала подключитесь к точке Wi-Fi", "Connect to Wi-Fi first", "Connectez-vous d’abord au Wi-Fi", "Zuerst mit WLAN verbinden"), 2600); return; }
    if (!st.internal_enabled && !st.sd_enabled) { Message(ICON_WARNING,L("Память", "Storage", "Mémoire", "Speicher"),L("Включите внутреннюю память или SD-карту", "Enable internal storage or SD card", "Activez la mémoire interne ou la carte SD", "Internen Speicher oder SD-Karte aktivieren"),2400); return; }
    if (slen(st.username) < 3) { Message(ICON_WARNING,L("Логин", "Username", "Identifiant", "Benutzername"),L("Минимум 3 символа", "At least 3 characters", "3 caractères minimum", "Mindestens 3 Zeichen"),2200); return; }
    if (st.password_is_default && !password[0]) {
        Message(ICON_WARNING, L("Безопасность", "Security", "Sécurité", "Sicherheit"), L("Перед первым запуском задайте новый пароль", "Set a new password before the first start", "Définissez un nouveau mot de passe avant le premier démarrage", "Legen Sie vor dem ersten Start ein neues Passwort fest"), 3400);
        open_edit(2);
        return;
    }
    if (password[0] && slen(password) < 6) { Message(ICON_WARNING,L("Пароль", "Password", "Mot de passe", "Passwort"),L("Минимум 6 символов", "At least 6 characters", "6 caractères minimum", "Mindestens 6 Zeichen"),2200); return; }
    if (st.http_port == st.ftp_port || st.http_port == st.smb_port || st.ftp_port == st.smb_port || st.http_port == 8090 || st.ftp_port == 8090 || st.smb_port == 8090) {
        Message(ICON_WARNING,L("Порты", "Ports", "Ports", "Ports"),L("Порты должны отличаться друг от друга и от 8090", "Ports must be different and must not be 8090", "Les ports doivent être différents et ne pas valoir 8090", "Ports müssen verschieden und ungleich 8090 sein"),3000); return;
    }
    if (write_apply_file() < 0) {
        cleanup_legacy_runtime_servers();
        if (write_apply_file() < 0) { Message(ICON_ERROR,"WiFiFiles",L("Не удалось сохранить настройки: системная временная память заполнена", "Cannot save settings: system temporary storage is full", "Impossible d’enregistrer les paramètres : le stockage temporaire système est plein", "Einstellungen konnten nicht gespeichert werden: temporärer Systemspeicher ist voll"),3600); return; }
    }
    ShowHourglass();
    if (run_helper("--native-apply-file") != 0) {
        HideHourglass();
        Message(ICON_ERROR,"WiFiFiles",L("Не удалось применить настройки. Перезапустите приложение", "Cannot apply settings. Restart the application", "Impossible d’appliquer les paramètres. Redémarrez l’application", "Einstellungen konnten nicht angewendet werden. Anwendung neu starten"),3600);
        draw_current();
        return;
    }
    load_state(); HideHourglass();
    if (st.smb_enabled && !st.smb_running && st.smb_error[0]) Message(ICON_ERROR,"SMB",st.smb_error,4200);
    else if (st.running) Message(ICON_INFORMATION,"WiFiFiles",L("Службы запущены", "Services started", "Services démarrés", "Dienste gestartet"),1700);
    else Message(ICON_ERROR,"WiFiFiles",st.message[0]?st.message:L("Сервер не запустился", "Server did not start", "Le serveur n’a pas démarré", "Server wurde nicht gestartet"),3200);
    draw_current();
}
static void stop_services(void) {
    log_line("stop services");
    ShowHourglass();
    if (run_helper("--native-stop") != 0) {
        HideHourglass();
        Message(ICON_ERROR,"WiFiFiles",L("Не удалось остановить службы", "Cannot stop services", "Impossible d’arrêter les services", "Dienste konnten nicht gestoppt werden"),3000);
        return;
    }
    load_state(); HideHourglass();
    Message(ICON_INFORMATION,"WiFiFiles",L("Все службы остановлены", "All services stopped", "Tous les services sont arrêtés", "Alle Dienste gestoppt"),1700); draw_current();
}
static void wifi_cycle_poll(void);
static void wifi_watch_poll(void);

static void cancel_wifi_refresh(void) {
    ClearTimerByName("wififiles-wifi-on");
    ClearTimerByName("wififiles-wifi-poll");
    ClearTimerByName("wififiles-wifi-watch");
    wifi_refresh_in_progress = 0;
    wifi_refresh_attempt = 0;
    wifi_refresh_existing_connection = 0;
    wifi_watch_active = 0;
}

static void start_wifi_watch(void) {
    if (st.ip[0] || wifi_refresh_in_progress || wifi_watch_active) return;
    wifi_watch_active = 1;
    SetHardTimer("wififiles-wifi-watch", wifi_watch_poll, 1500);
}

static void wifi_watch_poll(void) {
    if (!wifi_watch_active || wifi_refresh_in_progress) return;
    if (wifi_link_connected()) {
        load_state();
        if (st.ip[0]) {
            wifi_watch_active = 0;
            wifi_refresh_result = 1;
            screen_mode = MODE_MAIN;
            selected = 0;
            draw_current();
            show_open_wifi_warning();
            return;
        }
    }
    SetHardTimer("wififiles-wifi-watch", wifi_watch_poll, 1500);
}

static void wifi_cycle_power_on(void) {
    log_line("Wi-Fi power on");
    if (WiFiPower) WiFiPower(1);
    if (NetConnectSilent) NetConnectSilent((const char *)0);
    SetHardTimer("wififiles-wifi-poll", wifi_cycle_poll, 1000);
}

static void wifi_cycle_poll(void) {
    if (!wifi_refresh_in_progress) return;
    load_state();
    if (st.ip[0]) {
        wifi_refresh_in_progress = 0;
        wifi_refresh_existing_connection = 0;
        wifi_refresh_result = 1;
        screen_mode = MODE_MAIN;
        selected = 0;
        draw_current();
        show_open_wifi_warning();
        return;
    }
    wifi_refresh_attempt++;
    if (wifi_refresh_attempt >= 9) {
        wifi_refresh_in_progress = 0;
        wifi_refresh_existing_connection = 0;
        wifi_refresh_result = -1;
        selected = MAIN_REFRESH;
        draw_current();
        start_wifi_watch();
        return;
    }
    SetHardTimer("wififiles-wifi-poll", wifi_cycle_poll, 1000);
}

static void start_wifi_refresh(void) {
    if (wifi_refresh_in_progress) return;

    /* Always re-check the current state before touching Wi-Fi power. */
    load_state();
    if (st.ip[0]) {
        wifi_refresh_result = 1;
        screen_mode = MODE_MAIN;
        selected = 0;
        draw_current();
        show_open_wifi_warning();
        return;
    }

    ClearTimerByName("wififiles-wifi-watch");
    wifi_watch_active = 0;
    wifi_refresh_in_progress = 1;
    wifi_refresh_attempt = 0;
    wifi_refresh_result = 0;
    wifi_refresh_existing_connection = wifi_link_connected();
    selected = MAIN_REFRESH;
    draw_no_wifi();

    if (wifi_refresh_existing_connection) {
        log_line("Wi-Fi already connected; wait for IP without power cycle");
        SetHardTimer("wififiles-wifi-poll", wifi_cycle_poll, 1000);
        return;
    }

    log_line("restart Wi-Fi and search connection");
    if (NetDisconnect) NetDisconnect();
    if (WiFiPower) WiFiPower(0);
    SetHardTimer("wififiles-wifi-on", wifi_cycle_power_on, 900);
}

static void refresh_state(void) {
    /* On the connected main screen this button is primarily an E-Ink cleanup.
       Preserve unapplied edits instead of silently replacing them from disk. */
    if (screen_mode == MODE_MAIN && st.ip[0] && dirty) { draw_current(); return; }
    ShowHourglass(); load_state(); HideHourglass();
    if (!st.language[0]) { screen_mode = MODE_LANGUAGE; language_return_mode = MODE_MAIN; selected = 0; }
    draw_current();
}

static void open_wifi_settings(void) {
    log_line("open Wi-Fi settings");
    cancel_wifi_refresh();
    wifi_refresh_result = 0;
    NetConnect((const char *)0);
    load_state();
    screen_mode = MODE_MAIN;
    selected = st.ip[0] ? 0 : MAIN_REFRESH;
    draw_current();
    if (st.ip[0]) show_open_wifi_warning();
    else start_wifi_watch();
}

static void open_phone_flow(void) {
    if (st.password_is_default && !password[0]) {
        Message(ICON_WARNING, L("Безопасность", "Security", "Sécurité", "Sicherheit"), L("Перед передачей с телефона задайте новый пароль", "Set a new password before phone transfer", "Définissez un nouveau mot de passe avant le transfert depuis un téléphone", "Legen Sie vor der Übertragung vom Telefon ein neues Passwort fest"), 3400);
        open_edit(2);
        return;
    }
    /* Refresh the state file before drawing the picker so a default target,
       recent paths or free space changed while the app was running are shown
       without restarting the server or the app. Skip while there are unapplied
       edits so an entered password is not lost. */
    if (!dirty) load_state();
    if (!st.http_running) {
        if (!st.http_enabled) { st.http_enabled = 1; dirty = 1; }
        start_services();
        if (!st.http_running) {
            Message(ICON_ERROR, "WiFiFiles", L("Для передачи с телефона не удалось запустить веб-сервер", "The web server could not be started for phone upload", "Impossible de démarrer le serveur Web pour l’envoi depuis le téléphone", "Der Webserver für die Handy-Übertragung konnte nicht gestartet werden"), 3600);
            return;
        }
    }
    screen_mode = MODE_STORAGE_PICKER;
    selected = st.internal_enabled ? 0 : 1;
    draw_current();
}

static void open_folder_path(const char *path) {
    ShowHourglass();
    folder_picker_skip = 0;
    if (request_folder_list(path) < 0) {
        HideHourglass();
        Message(ICON_ERROR, L("Папка", "Folder", "Dossier", "Ordner"), folder_error[0] ? folder_error : L("Не удалось открыть папку", "Cannot open the folder", "Impossible d’ouvrir le dossier", "Ordner konnte nicht geöffnet werden"), 3400);
        return;
    }
    HideHourglass();
    screen_mode = MODE_FOLDER_PICKER;
    selected = 0;
    draw_current();
}

static void activate_main(int idx) {
    if (!st.ip[0]) {
        if (idx == MAIN_REFRESH) start_wifi_refresh();
        else if (idx == MAIN_START) open_wifi_settings();
        return;
    }
    switch (idx) {
        case 0: st.http_enabled = !st.http_enabled; dirty = 1; partial_main_item(0); partial_main_status(); return;
        case 1: open_edit(3); return;
        case 2: st.ftp_enabled = !st.ftp_enabled; dirty = 1; partial_main_item(2); partial_main_status(); return;
        case 3: open_edit(4); return;
        case 4: st.smb_enabled = !st.smb_enabled; dirty = 1; partial_main_item(4); partial_main_status(); return;
        case 5: open_edit(5); return;
        case 6: st.internal_enabled = !st.internal_enabled; dirty = 1; partial_main_item(6); partial_main_status(); return;
        case 7: st.sd_enabled = !st.sd_enabled; dirty = 1; partial_main_item(7); partial_main_status(); return;
        case 8: open_edit(1); return;
        case 9: open_edit(2); return;
        case 10: st.logging_enabled = !st.logging_enabled; dirty = 1; partial_main_item(10); partial_main_status(); return;
        case 11: instruction_page = 0; screen_mode = MODE_INSTRUCTIONS; selected = 0; draw_current(); return;
        case 12: settings_picker_mode = 0; screen_mode = MODE_SETTINGS; selected = 0; draw_current(); return;
        case MAIN_STOP: stop_services(); return;
        case MAIN_PHONE: open_phone_flow(); return;
        case MAIN_REFRESH: refresh_state(); return;
        case MAIN_START: start_services(); return;
    }
}
static void activate_current(int idx) {
    if (screen_mode == MODE_LANGUAGE) {
        if (idx >= 0 && idx < 4) choose_language(idx);
        else if (idx == 4 && st.language[0]) { screen_mode = language_return_mode; selected = 0; draw_current(); }
        return;
    }
    if (screen_mode == MODE_INSTRUCTIONS) {
        if (idx >= 0 && idx < 4) { instruction_index = idx; instruction_page = 0; screen_mode = MODE_INSTRUCTION_DETAIL; selected = 2; draw_current(); }
        else if (idx == 4) { screen_mode = MODE_MAIN; selected = 11; draw_current(); }
        else if (idx == 5) { cycle_instruction_font(); }
        return;
    }
    if (screen_mode == MODE_INSTRUCTION_DETAIL) {
        int starts[4] = {0,0,0,0}, counts[4] = {0,0,0,0};
        int pages = instruction_layout(starts, counts);
        if (idx == 0) { screen_mode = MODE_INSTRUCTIONS; selected = instruction_index; draw_current(); }
        else if (idx == 1 && instruction_page > 0) { instruction_page--; selected = 2; draw_current(); }
        else if (idx == 2 && instruction_page < pages - 1) { instruction_page++; selected = 1; draw_current(); }
        return;
    }
    if (screen_mode == MODE_SETTINGS) {
        if (idx == 0) { language_return_mode = MODE_SETTINGS; screen_mode = MODE_LANGUAGE; selected = current_lang; draw_current(); }
        else if (idx == 1) { settings_picker_mode = 1; screen_mode = MODE_STORAGE_PICKER; selected = st.internal_enabled ? 0 : 1; draw_current(); }
        else if (idx == 2) run_update_action();
        else if (idx == 3) { screen_mode = MODE_LOG; draw_current(); }
        else if (idx == 4) { screen_mode = MODE_MAIN; selected = 12; draw_current(); }
        return;
    }
    if (screen_mode == MODE_LOG) {
        if (idx == LOG_BACK) { screen_mode = MODE_SETTINGS; selected = 3; draw_current(); }
        return;
    }
    if (screen_mode == MODE_STORAGE_PICKER) {
        if (idx == 0) {
            if (!st.internal_enabled) Message(ICON_WARNING, L("Память", "Storage", "Mémoire", "Speicher"), L("Внутренняя память отключена в настройках", "Reader storage is disabled in settings", "La mémoire du lecteur est désactivée dans les réglages", "Der Reader-Speicher ist in den Einstellungen deaktiviert"), 2800);
            else open_folder_path("internal");
        } else if (idx == 1) {
            if (!st.sd_enabled) Message(ICON_WARNING, L("Память", "Storage", "Mémoire", "Speicher"), L("Карта SD отключена в настройках", "The SD card is disabled in settings", "La carte SD est désactivée dans les réglages", "Die SD-Karte ist in den Einstellungen deaktiviert"), 2800);
            else open_folder_path("sd");
        } else if (idx == STORAGE_DEFAULT && st.default_target[0] && !settings_picker_mode) {
            scopy(folder_current, sizeof(folder_current), st.default_target);
            folder_picker_skip = 1;
            if (request_folder_list(folder_current) == 0) { screen_mode = MODE_QR_MODE; selected = QR_MODE_SAFE; draw_current(); }
            else { Message(ICON_ERROR, L("Папка", "Folder", "Dossier", "Ordner"), folder_error[0] ? folder_error : L("Не удалось открыть папку", "Cannot open the folder", "Impossible d’ouvrir le dossier", "Ordner konnte nicht geöffnet werden"), 3400); folder_picker_skip = 0; }
        } else if (idx >= STORAGE_RECENT1 && idx <= STORAGE_RECENT4 && st.recent_targets[idx - STORAGE_RECENT1][0] && !settings_picker_mode) {
            scopy(folder_current, sizeof(folder_current), st.recent_targets[idx - STORAGE_RECENT1]);
            folder_picker_skip = 1;
            if (request_folder_list(folder_current) == 0) { screen_mode = MODE_QR_MODE; selected = QR_MODE_SAFE; draw_current(); }
            else { Message(ICON_ERROR, L("Папка", "Folder", "Dossier", "Ordner"), folder_error[0] ? folder_error : L("Не удалось открыть папку", "Cannot open the folder", "Impossible d’ouvrir le dossier", "Ordner konnte nicht geöffnet werden"), 3400); folder_picker_skip = 0; }
        } else if (idx == STORAGE_BACK) {
            if (settings_picker_mode) { settings_picker_mode = 0; screen_mode = MODE_SETTINGS; selected = 1; draw_current(); }
            else { screen_mode = MODE_MAIN; selected = MAIN_PHONE; draw_current(); }
        }
        return;
    }
    if (screen_mode == MODE_FOLDER_PICKER) {
        int visible = folder_visible_count();
        int start = folder_page * FOLDER_PAGE_SIZE;
        if (idx == 0) {
            if (settings_picker_mode) {
                save_default_target(folder_current);
                Message(ICON_INFORMATION, "WiFiFiles",
                    L("Путь по умолчанию сохранён", "Default path saved", "Chemin par défaut enregistré", "Standardpfad gespeichert"), 2600);
                settings_picker_mode = 0;
                screen_mode = MODE_SETTINGS; selected = 1; draw_current();
            } else {
                screen_mode = MODE_QR_MODE; selected = QR_MODE_SAFE; draw_current();
            }
        } else if (idx == FOLDER_REMEMBER) {
            save_default_target(folder_current);
            Message(ICON_INFORMATION, "WiFiFiles",
                L("Путь по умолчанию сохранён", "Default path saved", "Chemin par défaut enregistré", "Standardpfad gespeichert"), 2600);
            if (settings_picker_mode) { settings_picker_mode = 0; screen_mode = MODE_SETTINGS; selected = 1; draw_current(); }
            else draw_current();
        } else if (idx >= 1 && idx <= visible) {
            open_folder_path(folder_dirs[start + idx - 1]);
        } else if (idx == FOLDER_BACK) {
            if (settings_picker_mode) { screen_mode = MODE_STORAGE_PICKER; selected = 1; draw_current(); }
            else { screen_mode = MODE_STORAGE_PICKER; selected = starts(folder_current, "sd") ? 1 : 0; draw_current(); }
        } else if (idx == FOLDER_UP && folder_parent[0]) open_folder_path(folder_parent);
        else if (idx == FOLDER_PREV && folder_page > 0) { folder_page--; selected = 0; draw_current(); }
        else if (idx == FOLDER_NEXT && start + visible < folder_count) { folder_page++; selected = 0; draw_current(); }
        return;
    }
    if (screen_mode == MODE_QR_MODE) {
        if (idx == QR_MODE_SAFE) {
            if (request_mobile_qr("safe") == 0) { screen_mode = MODE_QR; selected = QR_BACK; draw_current(); }
        } else if (idx == QR_MODE_EDIT) {
            if (request_mobile_qr("edit") == 0) { screen_mode = MODE_QR; selected = QR_BACK; draw_current(); }
        } else if (idx == QR_MODE_BACK) {
            if (folder_picker_skip) { folder_picker_skip = 0; screen_mode = MODE_STORAGE_PICKER; selected = st.internal_enabled ? 0 : 1; draw_current(); }
            else { screen_mode = MODE_FOLDER_PICKER; selected = 0; draw_current(); }
        }
        return;
    }
    if (screen_mode == MODE_QR) {
        if (idx == QR_BACK) { screen_mode = MODE_MAIN; selected = MAIN_PHONE; draw_current(); }
        else if (idx == QR_CHANGE_FOLDER) { screen_mode = MODE_FOLDER_PICKER; selected = 0; draw_current(); }
        return;
    }
    activate_main(idx);
}

static int main_item_from_y(int x, int y) {
    int i;
    if (!st.ip[0]) {
        int by = screen_h - 88, bw = (screen_w - 54) / 2, x1 = 18, x2 = x1 + bw + 18;
        if (y >= by && y < by + 60) {
            if (x >= x1 && x < x1 + bw) return MAIN_START;
            if (x >= x2 && x < x2 + bw) return MAIN_REFRESH;
        }
        return -1;
    }
    for (i = 0; i < MAIN_ROW_COUNT; i++) { int yy = main_row_y(i); if (y >= yy && y < yy + 45) return i; }
    if (y >= screen_h - 72 && y < screen_h - 18) {
        int bw = (screen_w - 60) / 4, x1 = 18, x2 = x1 + bw + 8, x3 = x2 + bw + 8, x4 = x3 + bw + 8;
        if (x >= x1 && x < x1 + bw) return MAIN_STOP;
        if (x >= x2 && x < x2 + bw) return MAIN_PHONE;
        if (x >= x3 && x < x3 + bw) return MAIN_REFRESH;
        if (x >= x4 && x < x4 + bw) return MAIN_START;
    }
    return -1;
}
static int current_item_from_y(int x, int y) {
    int i;
    if (screen_mode == MODE_MAIN) return main_item_from_y(x, y);
    if (screen_mode == MODE_LANGUAGE) {
        for (i = 0; i < 4; i++) { int yy = 170 + i * 112; if (y >= yy && y < yy + 92) return i; }
        if (st.language[0] && y >= screen_h - 72 && x >= 18 && x < 238) return 4;
        return -1;
    }
    if (screen_mode == MODE_INSTRUCTIONS) {
        for (i = 0; i < 4; i++) { int yy = 118 + i * 142; if (y >= yy && y < yy + 128) return i; }
        if (y >= screen_h - 72) {
            if (x < 246) return 4;
            return 5;
        }
        return -1;
    }
    if (screen_mode == MODE_INSTRUCTION_DETAIL && y >= screen_h - 72) {
        if (x < 238) return 0;
        if (x >= (screen_w - 210) / 2 && x < (screen_w + 210) / 2) return 1;
        if (x > screen_w - 238) return 2;
    }
    if (screen_mode == MODE_SETTINGS) {
        if (y >= 210 && y < 255) return 0;
        if (y >= 280 && y < 325) return 1;
        if (y >= 350 && y < 395) return 2;
        if (y >= 420 && y < 465) return 3;
        if (y >= screen_h - 72 && x >= 18 && x < 238) return 4;
        return -1;
    }
    if (screen_mode == MODE_LOG) {
        if (y >= screen_h - 72 && x >= 18 && x < 238) return LOG_BACK;
        return -1;
    }
    if (screen_mode == MODE_STORAGE_PICKER) {
        if (y >= 220 && y < 265) return 0;
        if (y >= 290 && y < 335) return 1;
        if (!settings_picker_mode) {
            if (st.default_target[0] && y >= 360 && y < 405) return STORAGE_DEFAULT;
            if (y >= 434 && y < 479) return STORAGE_RECENT1;
            if (y >= 504 && y < 549) return STORAGE_RECENT2;
            if (y >= 574 && y < 619) return STORAGE_RECENT3;
            if (y >= 644 && y < 689) return STORAGE_RECENT4;
        }
        if (y >= screen_h - 72 && x >= 18 && x < 238) return STORAGE_BACK;
        return -1;
    }
    if (screen_mode == MODE_FOLDER_PICKER) {
        int visible = folder_visible_count();
        int half_w = (screen_w - 44) / 2;
        if (y >= 150 && y < 208) {
            if (x >= 18 && x < 18 + half_w) return 0;
            if (x >= 26 + half_w && x < 26 + half_w + half_w) return FOLDER_REMEMBER;
        }
        for (i = 0; i < visible; i++) { int yy = 225 + i * 62; if (y >= yy && y < yy + 54) return i + 1; }
        if (y >= screen_h - 72) {
            int bw = (screen_w - 60) / 4, x1 = 18, x2 = x1 + bw + 8, x3 = x2 + bw + 8, x4 = x3 + bw + 8;
            if (x >= x1 && x < x1 + bw) return FOLDER_BACK;
            if (x >= x2 && x < x2 + bw) return FOLDER_UP;
            if (x >= x3 && x < x3 + bw) return FOLDER_PREV;
            if (x >= x4 && x < x4 + bw) return FOLDER_NEXT;
        }
        return -1;
    }
    if (screen_mode == MODE_QR_MODE) {
        if (y >= 190 && y < 308) return QR_MODE_SAFE;
        if (y >= 332 && y < 470) return QR_MODE_EDIT;
        if (y >= screen_h - 72 && x >= 18 && x < 238) return QR_MODE_BACK;
        return -1;
    }
    if (screen_mode == MODE_QR && y >= screen_h - 72) {
        int bw = (screen_w - 44) / 2;
        if (x >= 18 && x < 18 + bw) return QR_BACK;
        if (x >= 26 + bw && x < 26 + bw + bw) return QR_CHANGE_FOLDER;
    }
    return -1;
}
static int max_selected(void) {
    if (screen_mode == MODE_LANGUAGE) return st.language[0] ? 4 : 3;
    if (screen_mode == MODE_INSTRUCTIONS) return 5;
    if (screen_mode == MODE_INSTRUCTION_DETAIL) return 2;
    if (screen_mode == MODE_STORAGE_PICKER) {
        if (settings_picker_mode) return STORAGE_BACK;
        return st.default_target[0] ? STORAGE_DEFAULT : STORAGE_BACK;
    }
    if (screen_mode == MODE_SETTINGS) return 4;
    if (screen_mode == MODE_LOG) return 0;
    if (screen_mode == MODE_FOLDER_PICKER) return FOLDER_REMEMBER;
    if (screen_mode == MODE_QR_MODE) return QR_MODE_BACK;
    if (screen_mode == MODE_QR) return QR_CHANGE_FOLDER;
    if (!st.ip[0]) return MAIN_START;
    return MAIN_START;
}
static int min_selected(void) {
    if (screen_mode == MODE_MAIN && !st.ip[0]) return MAIN_REFRESH;
    return 0;
}
static void handle_back(void) {
    if (screen_mode == MODE_INSTRUCTION_DETAIL) { screen_mode = MODE_INSTRUCTIONS; selected = instruction_index; draw_current(); }
    else if (screen_mode == MODE_INSTRUCTIONS) { screen_mode = MODE_MAIN; selected = 11; draw_current(); }
    else if (screen_mode == MODE_LANGUAGE && st.language[0]) { screen_mode = language_return_mode; selected = 0; draw_current(); }
    else if (screen_mode == MODE_QR) { screen_mode = MODE_QR_MODE; selected = seq(qr_access_mode, "edit") ? QR_MODE_EDIT : QR_MODE_SAFE; draw_current(); }
    else if (screen_mode == MODE_QR_MODE) { screen_mode = MODE_FOLDER_PICKER; selected = 0; draw_current(); }
    else if (screen_mode == MODE_FOLDER_PICKER) { screen_mode = MODE_STORAGE_PICKER; selected = settings_picker_mode ? 1 : (starts(folder_current, "sd") ? 1 : 0); draw_current(); }
    else if (screen_mode == MODE_STORAGE_PICKER) {
        if (settings_picker_mode) { settings_picker_mode = 0; screen_mode = MODE_SETTINGS; selected = 1; draw_current(); }
        else { screen_mode = MODE_MAIN; selected = MAIN_PHONE; draw_current(); }
    }
    else if (screen_mode == MODE_SETTINGS) { screen_mode = MODE_MAIN; selected = 12; draw_current(); }
    else if (screen_mode == MODE_LOG) { screen_mode = MODE_SETTINGS; selected = 3; draw_current(); }
    else CloseApp();
}


static int selection_valid(int idx) {
    if (screen_mode == MODE_STORAGE_PICKER) {
        if (idx == 0) return st.internal_enabled;
        if (idx == 1) return st.sd_enabled;
        if (idx == STORAGE_DEFAULT) return st.default_target[0] != 0;
        if (idx >= STORAGE_RECENT1 && idx <= STORAGE_RECENT4) return st.recent_targets[idx - STORAGE_RECENT1][0] != 0;
        return idx == STORAGE_BACK;
    }
    if (screen_mode == MODE_FOLDER_PICKER) {
        int visible = folder_visible_count();
        int start = folder_page * FOLDER_PAGE_SIZE;
        if (idx == 0 || idx == FOLDER_BACK || idx == FOLDER_REMEMBER) return 1;
        if (idx >= 1 && idx <= visible) return 1;
        if (idx == FOLDER_UP) return folder_parent[0] != 0;
        if (idx == FOLDER_PREV) return folder_page > 0;
        if (idx == FOLDER_NEXT) return start + visible < folder_count;
        return 0;
    }
    if (screen_mode == MODE_QR_MODE) return idx == QR_MODE_SAFE || idx == QR_MODE_EDIT || idx == QR_MODE_BACK;
    if (screen_mode == MODE_QR) return idx == QR_BACK || idx == QR_CHANGE_FOLDER;
    return 1;
}

static int moved_selection(int direction) {
    int minv = min_selected(), maxv = max_selected();
    int n = selected, attempts = maxv - minv + 2;
    while (attempts-- > 0) {
        n += direction;
        if (n < minv) n = maxv;
        if (n > maxv) n = minv;
        if (selection_valid(n)) return n;
    }
    return selected;
}

static int main_handler(int type, int p1, int p2) {
    if (type == EVT_INIT) {
        int physical_h, reported_h;
        SetOrientation(0);
        physical_h = ScreenHeight();
        SetPanelType(PANEL_ENABLED);
        screen_w = ScreenWidth();
        reported_h = ScreenHeight();
        /* Old FW5 builds may shift the framebuffer below the system panel while
         * still reporting the full physical height. In that case reserve a
         * conservative 64 px at the bottom of the logical layout. If firmware
         * already reports a reduced client height, use it unchanged. */
        if (reported_h >= physical_h - 8 && reported_h > 800) screen_h = reported_h - 64;
        else screen_h = reported_h;
        if (screen_h < 700 || screen_h > physical_h) screen_h = physical_h - 64;
        prep_log_int("physical_screen_h", physical_h);
        prep_log_int("reported_screen_h", reported_h);
        prep_log_int("layout_screen_h", screen_h);
        load_instruction_font_scale();
        font_title = OpenFont("DejaVu Sans", 29, 1);
        font_main = OpenFont("DejaVu Sans", 20, 1);
        font_small = OpenFont("DejaVu Sans", 18, 1);
        font_help = OpenFont("DejaVu Sans", 18, 1);
        font_status = OpenFont("DejaVu Sans", 23, 1);
        font_block_title = OpenFont("DejaVu Sans", 21, 1);
        font_instruction = OpenFont("DejaVu Sans", instruction_body_size(), 1);
        font_instruction_title = OpenFont("DejaVu Sans", instruction_title_size(), 1);
        ClearScreen(); SetFont(font_main, BLACK);
        DrawTextRect(20, 0, screen_w - 40, screen_h, "WiFiFiles\n\nLoading…", ALIGN_CENTER | VALIGN_MIDDLE); finish_screen_update();
        load_state(); log_line("state loaded");
        if (!st.language[0]) {
            screen_mode = MODE_LANGUAGE; language_return_mode = MODE_MAIN; selected = 0;
        } else {
            screen_mode = MODE_MAIN; selected = st.ip[0] ? 0 : MAIN_START;
            startup_wifi_refresh_pending = st.ip[0] ? 0 : 1;
        }
    } else if (type == EVT_SHOW) {
        draw_current();
        if (startup_wifi_refresh_pending && screen_mode == MODE_MAIN && !st.ip[0]) {
            startup_wifi_refresh_pending = 0;
            start_wifi_refresh();
        } else if (st.ip[0]) {
            show_open_wifi_warning();
        }
    } else if (type == EVT_KEYPRESS) {
        if (p1 == KEY_BACK) handle_back();
        else if (p1 == KEY_UP || p1 == KEY_LEFT) change_selection(moved_selection(-1));
        else if (p1 == KEY_DOWN || p1 == KEY_RIGHT) change_selection(moved_selection(1));
        else if (p1 == KEY_OK && selection_valid(selected)) activate_current(selected);
    } else if (type == EVT_POINTERUP || type == EVT_TOUCHUP) {
        int idx = current_item_from_y(p1, p2); if (idx >= 0) { if (screen_mode == MODE_MAIN) change_selection(idx); else selected = idx; activate_current(idx); }
    } else if (type == EVT_EXIT) {
        cancel_wifi_refresh();
        if (font_title) CloseFont(font_title); if (font_main) CloseFont(font_main); if (font_small) CloseFont(font_small); if (font_help) CloseFont(font_help); if (font_status) CloseFont(font_status); if (font_block_title) CloseFont(font_block_title); if (font_instruction) CloseFont(font_instruction); if (font_instruction_title) CloseFont(font_instruction_title);
    }
    return 0;
}


__attribute__((used,noinline)) void app_start(unsigned long *sp) {
    int argc = (int)sp[0]; char **argv = (char **)&sp[1];
    g_envp = argv + argc + 1;
    InkViewMain(main_handler);
    sys_exit(0);
}
__attribute__((naked)) void _start(void) { asm volatile("mov r0, sp\n b app_start"); }
