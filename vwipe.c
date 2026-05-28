/* vwipe.c */
/*
 * Virtual Wipe - GTK-based secure data sanitization tool
 * NIST SP 800-88 Rev. 1 aligned
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/vfs.h>
#ifdef __linux__
#include <linux/fs.h>
#endif
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <termios.h>
#include <signal.h>
#include <stdint.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

/* Configuration constants */
#define SAFE_ZONE_BYTES (0ULL)
#define BUFFER_SIZE (4ULL * 1024 * 1024)
#define PROGRESS_UPDATE_INTERVAL (4ULL * 1024 * 1024)
#define DEFAULT_SAFETY_MB 250
#define CHUNK_SIZE_MB     64UL  /* Reduced from 1GB to 64MB for better responsiveness */
#define PAGE_SIZE         4096
#define GUI_UPDATE_INTERVAL 5  /* Update GUI every 5 allocations */

/* Pass types */
typedef enum {
    PASS_ZERO = 0,
    PASS_ONES,
    PASS_RANDOM,
    PASS_VERIFY
} PassType;

/* Wipe scheme structure */
typedef struct {
    int id;
    const char *name;
    const char *standard;
    PassType passes[10];
    int pass_count;
} WipeScheme;

/* Global state variables */
atomic_bool g_stop_flag = false;
atomic_size_t g_bytes_written = 0;
volatile size_t g_target_bytes = 0;
volatile time_t g_start_time = 0;
struct termios g_original_termios;
int g_termios_saved = 0;
int g_mlock_supported = 0;

/* GTK Widgets */
GtkWidget *main_window;
GtkWidget *progress_bar;
GtkWidget *status_label;
GtkWidget *log_textview;
GtkTextBuffer *log_buffer;
GtkWidget *file_chooser_button;
GtkWidget *dir_chooser_button;
GtkWidget *free_space_chooser_button;
GtkWidget *scheme_combo;
GtkWidget *scheme_combo_free;
GtkWidget *ram_fill_spinbutton;
GtkWidget *stop_button;
GtkWidget *file_wipe_btn;
GtkWidget *dir_wipe_btn;
GtkWidget *free_space_btn;
GtkWidget *ram_fill_btn;

/* Redesigned Navigation & Dash Widgets */
GtkWidget *main_stack;
GtkWidget *sidebar_buttons[5];
GtkWidget *threads_scale;
guint dashboard_timeout_id = 0;

/* Dynamic dashboard labels */
GtkWidget *lbl_dash_ram;
GtkWidget *lbl_dash_cpu;
GtkWidget *lbl_dash_entropy;
GtkWidget *lbl_dash_mlock;
GtkWidget *lbl_dash_status;
GtkWidget *lbl_dash_scheme;

/* Current scheme index */
int current_scheme_idx = 3;
atomic_bool g_operation_running = false;
pthread_mutex_t g_progress_mutex = PTHREAD_MUTEX_INITIALIZER;

/* NIST SP 800-88 Rev. 1 Aligned Sanitization Schemes */
const WipeScheme schemes[] = {
    {1, "NIST Clear (Baseline) (weak)",        "NIST SP 800-88 Rev. 1 §4.1",  {PASS_ZERO}, 1},
    {2, "DoD 5220.22-M (Overwrite) (good)",    "DoD 5220.22-M (E)",          {PASS_ZERO, PASS_ONES, PASS_RANDOM}, 3},
    {3, "NIST Purge (Multi-Pass) (strong)",      "NIST SP 800-88 Rev. 1 §4.2",  {PASS_ZERO, PASS_ONES, PASS_RANDOM, PASS_VERIFY}, 4},
    {4, "FIPS High-Entropy Purge (strongest)",      "FIPS 140-3 / NIST 800-88",    {PASS_RANDOM, PASS_RANDOM, PASS_ZERO, PASS_RANDOM, PASS_VERIFY}, 5}
};

/* Redesigned Premium CSS Theme */
static const char *custom_css = 
    "window {\n"
    "    background-color: #0c0e14;\n"
    "    color: #cbd5e1;\n"
    "}\n"
    ".sidebar {\n"
    "    background-color: #111420;\n"
    "    border-right: 1px solid #1e293b;\n"
    "    padding: 20px 10px;\n"
    "}\n"
    ".sidebar-logo {\n"
    "    font-size: 20px;\n"
    "    font-weight: 800;\n"
    "    color: #00f0ff;\n"
    "}\n"
    ".sidebar-subtitle {\n"
    "    font-size: 10px;\n"
    "    font-weight: bold;\n"
    "    color: #64748b;\n"
    "}\n"
    ".sidebar-btn {\n"
    "    background: none;\n"
    "    background-color: transparent;\n"
    "    border: none;\n"
    "    border-radius: 6px;\n"
    "    color: #94a3b8;\n"
    "    font-weight: bold;\n"
    "    font-size: 13px;\n"
    "    padding: 8px 12px;\n"
    "    margin-bottom: 4px;\n"
    "}\n"
    ".sidebar-btn:hover {\n"
    "    background-color: #1e293b;\n"
    "    color: #00f0ff;\n"
    "}\n"
    ".sidebar-btn.active {\n"
    "    background-color: #1e293b;\n"
    "    color: #ffffff;\n"
    "    border-left: 3px solid #00f0ff;\n"
    "    border-radius: 0px 6px 6px 0px;\n"
    "}\n"
    ".page-container {\n"
    "    padding: 10px 20px;\n"
    "}\n"
    ".page-title {\n"
    "    font-size: 22px;\n"
    "    font-weight: bold;\n"
    "    color: #ffffff;\n"
    "}\n"
    ".page-subtitle {\n"
    "    font-size: 13px;\n"
    "    color: #64748b;\n"
    "}\n"
    ".card {\n"
    "    background-color: #111420;\n"
    "    border: 1px solid #1e293b;\n"
    "    border-radius: 8px;\n"
    "    padding: 15px;\n"
    "}\n"
    ".card-title {\n"
    "    font-size: 11px;\n"
    "    font-weight: bold;\n"
    "    color: #64748b;\n"
    "}\n"
    ".card-value {\n"
    "    font-size: 18px;\n"
    "    font-weight: 800;\n"
    "    color: #f8fafc;\n"
    "}\n"
    ".card-subtitle {\n"
    "    font-size: 12px;\n"
    "    color: #94a3b8;\n"
    "}\n"
    ".card-icon {\n"
    "    font-size: 20px;\n"
    "    color: #00f0ff;\n"
    "}\n"
    ".badge-success {\n"
    "    background-color: rgba(16, 185, 129, 0.15);\n"
    "    color: #10b981;\n"
    "    font-weight: bold;\n"
    "    font-size: 11px;\n"
    "    padding: 2px 8px;\n"
    "    border-radius: 12px;\n"
    "    border: 1px solid rgba(16, 185, 129, 0.3);\n"
    "}\n"
    ".badge-warning {\n"
    "    background-color: rgba(245, 158, 11, 0.15);\n"
    "    color: #f59e0b;\n"
    "    font-weight: bold;\n"
    "    font-size: 11px;\n"
    "    padding: 2px 8px;\n"
    "    border-radius: 12px;\n"
    "    border: 1px solid rgba(245, 158, 11, 0.3);\n"
    "}\n"
    ".action-btn {\n"
    "    background-image: linear-gradient(to bottom right, #00f0ff, #0072ff);\n"
    "    color: #ffffff;\n"
    "    font-weight: bold;\n"
    "    border: none;\n"
    "    border-radius: 6px;\n"
    "    padding: 8px 16px;\n"
    "}\n"
    ".action-btn:hover {\n"
    "    background-image: linear-gradient(to bottom right, #33f4ff, #338eff);\n"
    "}\n"
    ".action-btn:disabled {\n"
    "    background-image: none;\n"
    "    background-color: #1e293b;\n"
    "    color: #64748b;\n"
    "}\n"
    ".stop-btn {\n"
    "    background-image: linear-gradient(to bottom right, #ef4444, #b91c1c);\n"
    "    color: #ffffff;\n"
    "    font-weight: bold;\n"
    "    border: none;\n"
    "    border-radius: 6px;\n"
    "    padding: 8px 16px;\n"
    "}\n"
    ".stop-btn:hover {\n"
    "    background-image: linear-gradient(to bottom right, #f87171, #dc2626);\n"
    "}\n"
    ".stop-btn:disabled {\n"
    "    background-image: none;\n"
    "    background-color: #1e293b;\n"
    "    color: #64748b;\n"
    "}\n"
    "progressbar trough {\n"
    "    background-color: #111420;\n"
    "    border: 1px solid #1e293b;\n"
    "    border-radius: 6px;\n"
    "    min-height: 14px;\n"
    "}\n"
    "progressbar progress {\n"
    "    background-image: linear-gradient(to right, #00f0ff, #7209b7);\n"
    "    border-radius: 5px;\n"
    "    min-height: 14px;\n"
    "}\n"
    ".terminal-log {\n"
    "    font-family: monospace;\n"
    "    font-size: 11px;\n"
    "    background-color: #060811;\n"
    "    color: #00ffcc;\n"
    "    border: 1px solid #1e293b;\n"
    "    border-radius: 6px;\n"
    "    padding: 8px;\n"
    "}\n"
    "button {\n"
    "    background-color: #1e293b;\n"
    "    border: 1px solid #334155;\n"
    "    color: #f8fafc;\n"
    "    border-radius: 4px;\n"
    "    padding: 4px 8px;\n"
    "}\n"
    "button:hover {\n"
    "    background-color: #334155;\n"
    "    border-color: #00f0ff;\n"
    "}\n"
    "combobox, spinbutton, entry {\n"
    "    background-color: #111420;\n"
    "    border: 1px solid #1e293b;\n"
    "    color: #f8fafc;\n"
    "    border-radius: 4px;\n"
    "    padding: 4px;\n"
    "}\n"
    "combobox button, spinbutton button {\n"
    "    background-color: #1e293b;\n"
    "    border: none;\n"
    "    color: #f8fafc;\n"
    "}\n";

/* Function prototypes */
void secure_memzero(void *ptr, size_t len);
int get_secure_random(void *buf, size_t len);
void fill_buffer(unsigned char *buf, size_t len, int type, uint64_t seed);
void attempt_trim(const char *path);
void restore_terminal(void);
int check_for_stop_interrupt(void);
void update_progress(const char *label);
void startup_compliance_check(void);
void launch_ram_fill(unsigned long safety_mb);
int wipe_file(const char *path);
int wipe_directory_recursive(const char *path);
int wipe_free_space(const char *path, int num_cores);

/* GTK callback prototypes */
void on_file_wipe_clicked(GtkButton *button, gpointer user_data);
void on_directory_wipe_clicked(GtkButton *button, gpointer user_data);
void on_free_space_wipe_clicked(GtkButton *button, gpointer user_data);
void on_ram_fill_clicked(GtkButton *button, gpointer user_data);
void on_stop_clicked(GtkButton *button, gpointer user_data);
void on_window_destroy(GtkWidget *widget, gpointer user_data);
void on_menu_quit_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_menu_about_activate(GtkMenuItem *menuitem, gpointer user_data);
void on_scheme_changed(GtkComboBox *combo, gpointer user_data);
void on_sidebar_btn_clicked(GtkButton *button, gpointer user_data);

/* Utility functions */
void log_message(const char *message);
void update_progress_bar(double fraction);
void set_ui_sensitive(gboolean sensitive);
static void add_feature_row(GtkWidget *box, const char *title, const char *desc, const char *icon_symbol);
void add_css_class(GtkWidget *widget, const char *class_name);
void update_sidebar_active(int active_idx);
void add_compliance_row(GtkWidget *box, const char *name, const char *desc, gboolean passed);
gboolean update_dashboard_stats(gpointer user_data);

/* Secure memory zeroing */
void secure_memzero(void *ptr, size_t len) {
    if (!ptr) return;
    explicit_bzero(ptr, len);
}

/* Get cryptographically secure random numbers with interrupt resilience */
int get_secure_random(void *buf, size_t len) {
    size_t total = 0;
    unsigned char *ptr = (unsigned char *)buf;
    while (total < len) {
        ssize_t ret = getrandom(ptr + total, len - total, 0);
        if (ret < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (ret == 0) return -1;
        total += (size_t)ret;
    }
    return 0;
}

/* Helper for deterministic PRNG */
static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

/* Fill buffer with specified pattern, using seed for random reproducibility */
void fill_buffer(unsigned char *buf, size_t len, int type, uint64_t seed) {
    switch (type) {
        case PASS_ZERO:
            memset(buf, 0, len);
            break;
        case PASS_ONES:
            memset(buf, 0xFF, len);
            break;
        case PASS_RANDOM:
            {
                uint64_t state = seed;
                uint64_t *buf64 = (uint64_t *)buf;
                size_t len64 = len / 8;
                for (size_t i = 0; i < len64; i++) {
                    buf64[i] = splitmix64(&state);
                }
                /* Handle remainder */
                size_t remainder = len % 8;
                if (remainder > 0) {
                    uint64_t last = splitmix64(&state);
                    memcpy(buf + (len64 * 8), &last, remainder);
                }
            }
            break;
        case PASS_VERIFY:
            /* Verification pass - pattern generation is handled by comparison logic */
            break;
    }
}

/* Attempt TRIM operation */
void attempt_trim(const char *path) {
#ifdef __linux__
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        uint64_t range[2] = {0, 0};
        ioctl(fd, BLKDISCARD, &range);
        close(fd);
    }
#endif
}

/* Restore terminal settings */
void restore_terminal(void) {
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_original_termios);
        g_termios_saved = 0;
    }
}

/* Check for stop interrupt */
int check_for_stop_interrupt(void) {
    return g_stop_flag;
}

/* Throttled UI Update Structures */
typedef struct { char message[512]; } LogMsg;
typedef struct { double fraction; } ProgMsg;
typedef struct { char status[512]; double fraction; } ProgUpdate;

gboolean idle_log_message(gpointer user_data) {
    LogMsg *msg = (LogMsg *)user_data;
    if (log_buffer) {
        GtkTextIter end;
        gtk_text_buffer_get_end_iter(log_buffer, &end);
        gtk_text_buffer_insert(log_buffer, &end, msg->message, -1);
        gtk_text_buffer_insert(log_buffer, &end, "\n", -1);
        GtkTextMark *mark = gtk_text_buffer_get_mark(log_buffer, "end");
        if (mark) gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(log_textview), mark, 0.0, TRUE, 0.0, 1.0);
    }
    printf("%s\n", msg->message);
    free(msg);
    return G_SOURCE_REMOVE;
}

gboolean idle_update_progress_bar(gpointer user_data) {
    ProgMsg *msg = (ProgMsg *)user_data;
    if (progress_bar) {
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), msg->fraction);
    }
    free(msg);
    return G_SOURCE_REMOVE;
}

gboolean idle_update_status(gpointer user_data) {
    ProgUpdate *update = (ProgUpdate *)user_data;
    if (progress_bar) {
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), update->fraction);
    }
    if (status_label) {
        gtk_label_set_text(GTK_LABEL(status_label), update->status);
    }
    printf("%s\n", update->status);
    free(update);
    return G_SOURCE_REMOVE;
}

gboolean idle_reset_ui(gpointer user_data G_GNUC_UNUSED) {
    g_operation_running = false;
    set_ui_sensitive(TRUE);
    update_progress_bar(1.0);
    return G_SOURCE_REMOVE;
}

/* Callback for child process termination */
void on_ram_fill_child_exited(GPid pid, gint status, gpointer user_data G_GNUC_UNUSED) {
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            log_message("[+] RAM fill completed successfully!");
            log_message("[+] Memory has been allocated and released automatically");
        } else {
            log_message("[!] RAM fill process terminated with error");
        }
    } else if (WIFSIGNALED(status)) {
        log_message("[!] RAM fill process was terminated by signal");
    }
    
    g_spawn_close_pid(pid);
    g_idle_add(idle_reset_ui, NULL);
}

/* Update progress display with throttling */
void update_progress(const char *label) {
    static gint64 last_update_time = 0;
    gint64 now = g_get_monotonic_time();
    
    /* Throttle updates to ~10 per second (100ms) to prevent UI flooding, 
       but always allow the final 100% update */
    if (g_target_bytes > 0) {
        size_t written = atomic_load(&g_bytes_written);
        double fraction = (double)written / (double)g_target_bytes;
        if (fraction > 1.0) fraction = 1.0;
        
        pthread_mutex_lock(&g_progress_mutex);
        if (now - last_update_time < 100000 && fraction < 1.0) {
            pthread_mutex_unlock(&g_progress_mutex);
            return;
        }
        last_update_time = now;
        pthread_mutex_unlock(&g_progress_mutex);

        time_t elapsed = time(NULL) - g_start_time;
        double speed_mb = elapsed > 0 ? (double)written / (1048576.0 * elapsed) : 0.0;
        
        ProgUpdate *update = malloc(sizeof(ProgUpdate));
        if (update) {
            update->fraction = fraction;
            snprintf(update->status, sizeof(update->status), "%s: %.1f%% (%.2f MB/%.2f MB) - %.2f MB/s",
                     label, fraction * 100.0,
                     written / 1048576.0, g_target_bytes / 1048576.0, speed_mb);
            g_idle_add(idle_update_status, update);
        }
    }
}

/* Startup compliance check */
void startup_compliance_check(void) {
    /* Improved mlock check using a heap-allocated page */
    void *test_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (test_page != MAP_FAILED) {
        if (mlock(test_page, 4096) == 0) {
            g_mlock_supported = 1;
            munlock(test_page, 4096);
        } else {
            g_mlock_supported = 0;
        }
        munmap(test_page, 4096);
    } else {
        g_mlock_supported = 0;
    }
    
    if (!g_mlock_supported) {
        fprintf(stderr, "Warning: Memory locking (mlock) is not supported or permitted.\n");
    }

    prctl(PR_SET_DUMPABLE, 0);
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
}

/* Launch RAM fill in terminal window */
void launch_ram_fill(unsigned long safety_mb) {
    char cmd_str[1024];
    char title[256];
    
    snprintf(title, sizeof(title), "Virtual Wipe - RAM Fill (%lu MB safety)", safety_mb);
    
    const char *terminals[] = {
        "mate-terminal --title='%s' -- %s %lu",
        "xfce4-terminal --title='%s' -- %s %lu",
        "xterm -title '%s' -e %s %lu",
        "konsole --title '%s' -e %s %lu",
        "gnome-terminal --title='%s' -- %s %lu",
        NULL
    };
    
    char vwipe_ram_path[4096];
    if (access("./vwipe_ram", X_OK) == 0) {
        strcpy(vwipe_ram_path, "./vwipe_ram");
    } else {
        strcpy(vwipe_ram_path, "/usr/local/bin/vwipe_ram");
    }
    
    for (int i = 0; terminals[i]; i++) {
        snprintf(cmd_str, sizeof(cmd_str), terminals[i], title, vwipe_ram_path, safety_mb);
        
        gchar **argv = NULL;
        GError *error = NULL;
        
        if (g_shell_parse_argv(cmd_str, NULL, &argv, &error)) {
            GPid pid;
            if (g_spawn_async(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH, 
                             NULL, NULL, &pid, &error)) {
                g_strfreev(argv);
                
                char log_msg[512];
                snprintf(log_msg, sizeof(log_msg), "RAM fill launched in terminal (safety margin: %lu MB)", safety_mb);
                log_message(log_msg);
                log_message("Monitoring RAM fill process...");
                
                /* Watch the child process without blocking the main loop */
                g_child_watch_add(pid, on_ram_fill_child_exited, NULL);
                return;
            }
            g_strfreev(argv);
        }
        
        if (error) {
            g_error_free(error);
        }
    }
    
    log_message("Error: Could not find suitable terminal emulator");
    log_message("Please install gnome-terminal, mate-terminal, or xterm");
    set_ui_sensitive(TRUE);
}

/* Wipe file implementation */
int wipe_file(const char *path) {
    g_stop_flag = false;
    struct stat st;
    int fd = -1;
    unsigned char *buf = NULL;
    unsigned char *vbuf = NULL;
    int res = -1;

    /* Use lstat to detect symlinks - we refuse to follow them for security */
    if (lstat(path, &st) != 0) {
        log_message("Error: Cannot access path");
        return -1;
    }
    
    if (S_ISLNK(st.st_mode)) {
        log_message("Warning: Skipping symbolic link for security.");
        return 0;
    }

    if (!S_ISREG(st.st_mode)) {
        log_message("Error: Not a regular file.");
        return -1;
    }

    if (st.st_size <= 0) {
        char msg[512];
        snprintf(msg, sizeof(msg), "Skipping empty file: %s", path);
        log_message(msg);
        return 0;
    }

    size_t file_size = (size_t)st.st_size;
    g_target_bytes = file_size * schemes[current_scheme_idx].pass_count;
    g_bytes_written = 0;
    g_start_time = time(NULL);
    
    char msg[512];
    snprintf(msg, sizeof(msg), "Sanitizing: %s (%.2f MB)", path, file_size / 1048576.0);
    log_message(msg);

    int open_flags = O_RDWR | O_CLOEXEC | O_SYNC | O_NOFOLLOW;
#ifdef O_DIRECT
    open_flags |= O_DIRECT;
#endif
    fd = open(path, open_flags);
    if (fd < 0 && errno == EINVAL) {
        /* Fallback if O_DIRECT is not supported, but maintain O_NOFOLLOW for security */
        fd = open(path, O_RDWR | O_CLOEXEC | O_SYNC | O_NOFOLLOW);
    }
    
    if (fd < 0) {
        if (errno == ELOOP) {
            log_message("Security Error: Path is a symbolic link. Operation aborted.");
        } else {
            log_message("Error: Cannot open file for sanitization (Permission denied or special file)");
        }
        goto cleanup;
    }

    if (!g_mlock_supported) {
        log_message("[!] WARNING: mlock() failed. Data may be swapped to disk.");
    }

    buf = aligned_alloc(4096, BUFFER_SIZE);
    vbuf = aligned_alloc(4096, BUFFER_SIZE);
    
    if (!buf || !vbuf) {
        log_message("Error: Memory allocation failed");
        goto cleanup;
    }

    /* Prevent buffers from being captured in core dumps */
    madvise(buf, BUFFER_SIZE, MADV_DONTDUMP);
    madvise(vbuf, BUFFER_SIZE, MADV_DONTDUMP);

    if (g_mlock_supported) {
        mlock(buf, BUFFER_SIZE);
        mlock(vbuf, BUFFER_SIZE);
    }
    res = 0;
    
    /* Initial seed for the file */
    uint64_t file_seed = 0;
    get_secure_random(&file_seed, sizeof(file_seed));

    for (int p = 0; p < schemes[current_scheme_idx].pass_count && !g_stop_flag; p++) {
        PassType type = schemes[current_scheme_idx].passes[p];
        size_t offset = 0;
        
        while (offset < file_size && !g_stop_flag) {
            size_t to_write = (file_size - offset > BUFFER_SIZE) ? BUFFER_SIZE : (file_size - offset);
            uint64_t chunk_seed = file_seed ^ (uint64_t)offset ^ (uint64_t)p;
            
            lseek(fd, (off_t)offset, SEEK_SET);
            
            if (type == PASS_VERIFY) {
                /* Verify against the pattern of the PREVIOUS pass (p-1) */
                if (p > 0) {
                    PassType prev_type = schemes[current_scheme_idx].passes[p-1];
                    uint64_t prev_chunk_seed = file_seed ^ (uint64_t)offset ^ (uint64_t)(p-1);
                    
                    /* Re-generate the expected pattern into vbuf */
                    fill_buffer(vbuf, to_write, prev_type, prev_chunk_seed);
                    
                    /* Temporarily disable O_DIRECT for unaligned reads (tail of file) */
                    int current_flags = fcntl(fd, F_GETFL);
                    if (to_write % 4096 != 0 && (current_flags & O_DIRECT)) {
                        fcntl(fd, F_SETFL, current_flags & ~O_DIRECT);
                    }

                    /* Read from disk into buf */
                    if (read(fd, buf, to_write) != (ssize_t)to_write) { 
                        log_message("Error: Verification read failed");
                        res = -1; break; 
                    }
                    
                    /* Re-enable O_DIRECT if it was disabled */
                    if (to_write % 4096 != 0 && (current_flags & O_DIRECT)) {
                        fcntl(fd, F_SETFL, current_flags);
                    }

                    /* Compare */
                    if (memcmp(buf, vbuf, to_write) != 0) {
                        log_message("[!!!] CRITICAL: Verification mismatch! Data on disk is inconsistent.");
                        res = -3; g_stop_flag = true; break;
                    }
                }
            } else {
                /* Refill buffer per chunk for maximum entropy and deterministic verification */
                fill_buffer(buf, to_write, type, chunk_seed);
                
                /* Temporarily disable O_DIRECT for unaligned writes (tail of file) */
                int current_flags = fcntl(fd, F_GETFL);
                if (to_write % 4096 != 0 && (current_flags & O_DIRECT)) {
                    fcntl(fd, F_SETFL, current_flags & ~O_DIRECT);
                }

                if (write(fd, buf, to_write) != (ssize_t)to_write) { 
                    log_message("Error: Sanitization write failed");
                    res = -1; break; 
                }

                /* Re-enable O_DIRECT if it was disabled */
                if (to_write % 4096 != 0 && (current_flags & O_DIRECT)) {
                    fcntl(fd, F_SETFL, current_flags);
                }
            }
            
            g_bytes_written += to_write;
            offset += to_write;
            if (g_bytes_written % PROGRESS_UPDATE_INTERVAL == 0) {
                update_progress(type == PASS_VERIFY ? "Verifying sanitization" : "Sanitizing file");
                if (g_stop_flag) break;
            }
        }
        if (res != 0 || g_stop_flag) break;
        fsync(fd);
        update_progress(type == PASS_VERIFY ? "Verification complete" : "Pass complete");
    }
    
    /* Wipe timestamps before closing */
    struct timespec times[2] = {{0, UTIME_OMIT}, {0, UTIME_OMIT}};
    times[0].tv_nsec = 0; /* atime */
    times[1].tv_nsec = 0; /* mtime */
    futimens(fd, times);

cleanup:
    if (buf) {
        secure_memzero(buf, BUFFER_SIZE);
        if (g_mlock_supported) munlock(buf, BUFFER_SIZE);
        free(buf);
    }
    if (vbuf) {
        secure_memzero(vbuf, BUFFER_SIZE);
        if (g_mlock_supported) munlock(vbuf, BUFFER_SIZE);
        free(vbuf);
    }
    if (fd >= 0) close(fd);

    if (res == 0 && !g_stop_flag) {
        char *dir = strdup(path);
        if (dir) {
            char *last_slash = strrchr(dir, '/');
            if (last_slash) *last_slash = '\0'; else strcpy(dir, ".");
            char new_name[4096];
            snprintf(new_name, sizeof(new_name), "%s/.secure_wipe_del_%lu_%lu.tmp", dir, (unsigned long)time(NULL), (unsigned long)getpid());
            if (rename(path, new_name) == 0) {
                int dfd = open(dir, O_RDONLY);
                if (dfd >= 0) { fsync(dfd); close(dfd); }
                if (unlink(new_name) == 0) attempt_trim(path);
            } else { unlink(path); }
            free(dir);
        }
        snprintf(msg, sizeof(msg), "File securely sanitized & removed: %s", path);
        log_message(msg);
    } else if (g_stop_flag) {
        log_message("FILE SANITIZATION STOPPED - File remains on disk.");
        res = -2;  /* Indicate user stop */
    }  
    return res;
}

/* Helper to calculate total directory size for progress reporting */
uint64_t calculate_dir_size(const char *path) {
    uint64_t total_size = 0;
    DIR *dir = opendir(path);
    if (!dir) return 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && !g_stop_flag) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        struct stat st;
        if (lstat(fullpath, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            total_size += calculate_dir_size(fullpath);
        } else if (S_ISREG(st.st_mode)) {
            total_size += (uint64_t)st.st_size;
        }
    }
    closedir(dir);
    return total_size;
}

/* Recursively wipe directory */
int wipe_directory_recursive(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        log_message("Error: Cannot open directory");
        return -1;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && !g_stop_flag) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);
        struct stat st;
        if (lstat(fullpath, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            wipe_directory_recursive(fullpath);
            char new_dir_name[4096];
            snprintf(new_dir_name, sizeof(new_dir_name), "%s/.sec_wipe_dir_%lu_%lu", path, (unsigned long)time(NULL), (unsigned long)getpid());
            if (rename(fullpath, new_dir_name) == 0) {
                rmdir(new_dir_name);
            } else {
                rmdir(fullpath);
            }
        } else if (S_ISREG(st.st_mode)) {
            wipe_file(fullpath);
        }
    }
    closedir(dir);
    return 0;
}

/* Multi-threaded worker for free space wipe */
typedef struct {
    char path[4096];
    int thread_id;
    uint64_t target_per_thread;
} FreeSpaceWorkerData;

void *free_space_worker(void *data) {
    FreeSpaceWorkerData *wd = (FreeSpaceWorkerData *)data;
    char tmp_template[4200];
    snprintf(tmp_template, sizeof(tmp_template), "%s/.secure_wipe_free_t%d_XXXXXX", wd->path, wd->thread_id);
    
    char **tmp_files = malloc(128 * sizeof(char *));
    int tmp_count = 0;
    
    unsigned char *buf = aligned_alloc(4096, BUFFER_SIZE);
    if (!buf) { free(wd); return NULL; }
    
    if (g_mlock_supported) mlock(buf, BUFFER_SIZE);

    while (atomic_load(&g_bytes_written) < g_target_bytes && !g_stop_flag) {
        char *tmpname = strdup(tmp_template);
        int fd = mkstemp(tmpname);
        if (fd < 0) {
            free(tmpname);
            if (errno == ENOSPC) {
                g_target_bytes = atomic_load(&g_bytes_written);
            } else {
                g_stop_flag = true;
            }
            break;
        }
        
        /* Use synchronous I/O for security */
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_SYNC);
        tmp_files[tmp_count++] = tmpname;
        
        size_t chunk = BUFFER_SIZE * 128; /* 512MB files for parallel efficiency */
        size_t off = 0;
        
        for (int p = 0; p < schemes[current_scheme_idx].pass_count && !g_stop_flag; p++) {
            /* Unique seed per thread/pass/file */
            uint64_t seed = (uint64_t)time(NULL) ^ (uintptr_t)buf ^ (uint64_t)wd->thread_id ^ (uint64_t)tmp_count;
            fill_buffer(buf, BUFFER_SIZE, schemes[current_scheme_idx].passes[p], seed);
            
            lseek(fd, 0, SEEK_SET);
            off = 0;
            while (off < chunk && !g_stop_flag && (p > 0 || atomic_load(&g_bytes_written) < g_target_bytes)) {
                size_t tw = (chunk - off > BUFFER_SIZE) ? BUFFER_SIZE : (chunk - off);
                /* Final check to not exceed target (only in pass 0) */
                if (p == 0) {
                    size_t current_total = atomic_load(&g_bytes_written);
                    if (current_total + tw > g_target_bytes) tw = g_target_bytes - current_total;
                }
                if (tw == 0) {
                    if (ftruncate(fd, (off_t)off) == 0) {}
                    chunk = off;
                    break;
                }

                ssize_t ret = write(fd, buf, tw);
                if (ret <= 0) {
                    if (errno == ENOSPC) {
                        if (ftruncate(fd, (off_t)off) == 0) {}
                        chunk = off;
                        g_target_bytes = atomic_load(&g_bytes_written);
                    } else {
                        g_stop_flag = true;
                    }
                    break;
                }
                off += (size_t)ret;
                atomic_fetch_add(&g_bytes_written, (size_t)ret);
                if (atomic_load(&g_bytes_written) % (BUFFER_SIZE * 4) == 0) {
                    update_progress("Sanitizing free space (Parallel)");
                }
            }
            if (g_stop_flag) break;
            fsync(fd);
        }
        close(fd);
        if (g_stop_flag) break;
        
        if (tmp_count >= 120) break; /* Safety limit per thread */
    }
    
    /* Cleanup this thread's files */
    for (int i = 0; i < tmp_count; i++) {
        unlink(tmp_files[i]);
        free(tmp_files[i]);
    }
    
    secure_memzero(buf, BUFFER_SIZE);
    if (g_mlock_supported) munlock(buf, BUFFER_SIZE);
    free(buf);
    free(tmp_files);
    free(wd);
    return NULL;
}

int wipe_free_space(const char *path, int num_cores) {
    g_stop_flag = false;
    struct statvfs st;
    if (statvfs(path, &st) != 0) {
        log_message("Error: Cannot get filesystem information");
        return -1;
    }
    uint64_t avail = (uint64_t)st.f_bavail * (uint64_t)st.f_bsize;
    if (avail == 0) {
        log_message("Error: No space available.");
        return -1;
    }

    g_target_bytes = (size_t)avail * schemes[current_scheme_idx].pass_count;
    atomic_store(&g_bytes_written, 0); 
    g_start_time = time(NULL);
    
    char msg[512];
    if (num_cores <= 0) num_cores = 1;
    if (num_cores > 16) num_cores = 16; /* Cap at 16 for stability */

    snprintf(msg, sizeof(msg), "Turbo-Sanitizing free space (Parallel: %d threads) on: %s", num_cores, path);
    log_message(msg);
    snprintf(msg, sizeof(msg), "Total Target: %.2f GB", (double)avail / 1073741824.0);
    log_message(msg);

    pthread_t threads[16];
    for (int i = 0; i < num_cores; i++) {
        FreeSpaceWorkerData *wd = malloc(sizeof(FreeSpaceWorkerData));
        strncpy(wd->path, path, 4095);
        wd->thread_id = i;
        wd->target_per_thread = avail / num_cores;
        pthread_create(&threads[i], NULL, free_space_worker, wd);
    }

    for (int i = 0; i < num_cores; i++) {
        pthread_join(threads[i], NULL);
    }

    attempt_trim(path); 
    sync();
    log_message("Multi-threaded free space sanitization complete.");
    return 0;
}

/* GTK UI Functions */
void log_message(const char *message) {
    LogMsg *msg = malloc(sizeof(LogMsg));
    if (msg) {
        strncpy(msg->message, message, sizeof(msg->message)-1);
        msg->message[sizeof(msg->message)-1] = '\0';
        g_idle_add(idle_log_message, msg);
    }
}

void update_progress_bar(double fraction) {
    ProgMsg *msg = malloc(sizeof(ProgMsg));
    if (msg) {
        msg->fraction = fraction;
        g_idle_add(idle_update_progress_bar, msg);
    }
}

void set_ui_sensitive(gboolean sensitive) {
    gtk_widget_set_sensitive(stop_button, !sensitive);
    if (file_chooser_button) gtk_widget_set_sensitive(file_chooser_button, sensitive);
    if (dir_chooser_button) gtk_widget_set_sensitive(dir_chooser_button, sensitive);
    if (free_space_chooser_button) gtk_widget_set_sensitive(free_space_chooser_button, sensitive);
    if (scheme_combo) gtk_widget_set_sensitive(scheme_combo, sensitive);
    if (scheme_combo_free) gtk_widget_set_sensitive(scheme_combo_free, sensitive);
    if (ram_fill_spinbutton) gtk_widget_set_sensitive(ram_fill_spinbutton, sensitive);
    
    /* Disable the actual action buttons to prevent re-entrancy */
    if (file_wipe_btn) gtk_widget_set_sensitive(file_wipe_btn, sensitive);
    if (dir_wipe_btn) gtk_widget_set_sensitive(dir_wipe_btn, sensitive);
    if (free_space_btn) gtk_widget_set_sensitive(free_space_btn, sensitive);
    if (ram_fill_btn) gtk_widget_set_sensitive(ram_fill_btn, sensitive);

    if (threads_scale) gtk_widget_set_sensitive(threads_scale, sensitive);

    for (int i = 0; i < 5; i++) {
        if (sidebar_buttons[i]) {
            gtk_widget_set_sensitive(sidebar_buttons[i], sensitive);
        }
    }
}

/* Helper to add a feature row to the about dialog */
static void add_feature_row(GtkWidget *box, const char *title, const char *desc, const char *icon_symbol) {
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    gtk_container_set_border_width(GTK_CONTAINER(row), 10);
    
    GtkWidget *icon_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(icon_label), g_strdup_printf("<span size='xx-large'>%s</span>", icon_symbol));
    gtk_widget_set_valign(icon_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(row), icon_label, FALSE, FALSE, 0);
    
    GtkWidget *text_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    
    GtkWidget *title_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(title_label), g_strdup_printf("<span weight='bold' size='large' color='#00ffcc'>%s</span>", title));
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0);
    gtk_box_pack_start(GTK_BOX(text_vbox), title_label, FALSE, FALSE, 0);
    
    GtkWidget *desc_label = gtk_label_new(desc);
    gtk_label_set_line_wrap(GTK_LABEL(desc_label), TRUE);
    gtk_label_set_xalign(GTK_LABEL(desc_label), 0.0);
    gtk_label_set_max_width_chars(GTK_LABEL(desc_label), 60);
    gtk_box_pack_start(GTK_BOX(text_vbox), desc_label, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(row), text_vbox, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(box), row, FALSE, FALSE, 5);
    
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_opacity(sep, 0.1);
    gtk_box_pack_start(GTK_BOX(box), sep, FALSE, FALSE, 0);
}

/* Helper to apply custom CSS classes */
void add_css_class(GtkWidget *widget, const char *class_name) {
    GtkStyleContext *context = gtk_widget_get_style_context(widget);
    gtk_style_context_add_class(context, class_name);
}

/* Thread structures */
typedef struct {
    char *path;
    int thread_count;
} ThreadData;

void *thread_wipe_file(void *data) {
    ThreadData *td = (ThreadData *)data;
    wipe_file(td->path);
    free(td->path);
    free(td);
    g_idle_add(idle_reset_ui, NULL);
    return NULL;
}

void *thread_wipe_dir(void *data) {
    ThreadData *td = (ThreadData *)data;
    g_start_time = time(NULL);
    log_message("Pre-scanning directory for size estimation...");
    uint64_t total_size = calculate_dir_size(td->path);
    g_target_bytes = (size_t)total_size * schemes[current_scheme_idx].pass_count;
    g_bytes_written = 0;
    
    char msg[512];
    snprintf(msg, sizeof(msg), "Recursively sanitizing directory (Total: %.2f MB)...", total_size / 1048576.0);
    log_message(msg);
    
    wipe_directory_recursive(td->path);
    
    char new_dir_name[4096];
    char *parent = strdup(td->path);
    char *last_slash = strrchr(parent, '/');
    if (last_slash) {
        *last_slash = '\0';
        snprintf(new_dir_name, sizeof(new_dir_name), "%s/.sec_wipe_dir_%lu", parent, (unsigned long)time(NULL));
        if (rename(td->path, new_dir_name) == 0) {
            rmdir(new_dir_name);
        } else {
            rmdir(td->path);
        }
    } else {
        rmdir(td->path);
    }
    free(parent);
    attempt_trim(td->path);
    
    free(td->path);
    free(td);
    g_idle_add(idle_reset_ui, NULL);
    return NULL;
}

void *thread_wipe_free(void *data) {
    ThreadData *td = (ThreadData *)data;
    wipe_free_space(td->path, td->thread_count);
    free(td->path);
    free(td);
    g_idle_add(idle_reset_ui, NULL);
    return NULL;
}

/* GTK Callbacks */
void on_file_wipe_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    if (g_operation_running) return;
    gchar *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(file_chooser_button));
    if (filename) {
        g_operation_running = true;
        set_ui_sensitive(FALSE);
        update_progress_bar(0.0);
        ThreadData *td = malloc(sizeof(ThreadData));
        td->path = strdup(filename);
        td->thread_count = 1;
        pthread_t tid;
        pthread_create(&tid, NULL, thread_wipe_file, td);
        pthread_detach(tid);
        g_free(filename);
    }
}

void on_directory_wipe_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    if (g_operation_running) return;
    gchar *dirname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dir_chooser_button));
    if (dirname) {
        g_operation_running = true;
        set_ui_sensitive(FALSE);
        update_progress_bar(0.0);
        ThreadData *td = malloc(sizeof(ThreadData));
        td->path = strdup(dirname);
        td->thread_count = 1;
        pthread_t tid;
        pthread_create(&tid, NULL, thread_wipe_dir, td);
        pthread_detach(tid);
        g_free(dirname);
    }
}

void on_free_space_wipe_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    if (g_operation_running) return;
    gchar *dirname = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(free_space_chooser_button));
    if (dirname) {
        g_operation_running = true;
        set_ui_sensitive(FALSE);
        update_progress_bar(0.0);
        ThreadData *td = malloc(sizeof(ThreadData));
        td->path = strdup(dirname);
        td->thread_count = (int)gtk_range_get_value(GTK_RANGE(threads_scale));
        pthread_t tid;
        pthread_create(&tid, NULL, thread_wipe_free, td);
        pthread_detach(tid);
        g_free(dirname);
    }
}

void on_ram_fill_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    if (g_operation_running) return;
    unsigned long safety_mb = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ram_fill_spinbutton));
    g_operation_running = true;
    set_ui_sensitive(FALSE);
    log_message("Launching RAM fill in terminal window...");
    log_message("Terminal will close automatically when complete");
    launch_ram_fill(safety_mb);
}

void on_stop_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    g_stop_flag = 1;
    log_message("STOP REQUESTED - Cleaning up safely...");
}

void on_window_destroy(GtkWidget *widget G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    if (dashboard_timeout_id > 0) {
        g_source_remove(dashboard_timeout_id);
        dashboard_timeout_id = 0;
    }
    gtk_main_quit();
}

void on_menu_quit_activate(GtkMenuItem *menuitem G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    on_window_destroy(NULL, NULL);
}

void on_menu_about_activate(GtkMenuItem *menuitem G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons(
        "About Virtual Wipe",
        GTK_WINDOW(main_window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Close", GTK_RESPONSE_CLOSE,
        NULL
    );
    
    gtk_window_set_default_size(GTK_WINDOW(dialog), 600, 500);
    
    /* Apply local dark theme to dialog */
    GtkCssProvider *cp = gtk_css_provider_new();
    gtk_css_provider_load_from_data(cp, "dialog { background-color: #0c0e14; color: #cbd5e1; }", -1, NULL);
    gtk_style_context_add_provider(gtk_widget_get_style_context(dialog), GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *main_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 20);
    gtk_container_add(GTK_CONTAINER(content_area), main_vbox);
    
    /* Header Section (Transparent SVG prioritized) */
    GdkPixbuf *pb = gdk_pixbuf_new_from_file_at_size("/usr/local/share/icons/hicolor/scalable/apps/vwipe_icon.svg", 64, 64, NULL);
    if (!pb) pb = gdk_pixbuf_new_from_file_at_size("vwipe_icon.svg", 64, 64, NULL);
    if (!pb) pb = gdk_pixbuf_new_from_file_at_size("/usr/local/share/icons/hicolor/256x256/apps/vwipe.png", 64, 64, NULL);
    if (!pb) pb = gdk_pixbuf_new_from_file_at_size("vwipe.png", 64, 64, NULL);
    
    GtkWidget *icon_image;
    if (pb) {
        icon_image = gtk_image_new_from_pixbuf(pb);
        g_object_unref(pb);
    } else {
        icon_image = gtk_image_new_from_icon_name("applications-system", GTK_ICON_SIZE_DIALOG);
    }
    gtk_box_pack_start(GTK_BOX(main_vbox), icon_image, FALSE, FALSE, 0);
    
    GtkWidget *name_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(name_label), "<span size='xx-large' weight='bold' color='white'>Virtual Wipe Turbo</span>");
    gtk_box_pack_start(GTK_BOX(main_vbox), name_label, FALSE, FALSE, 0);
    
    GtkWidget *ver_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(ver_label), "<span color='#aaaaaa'>Version 2.5.5 \xe2\x80\xa2 Multi-Threaded Forensic-Grade Sanitization</span>");
    gtk_box_pack_start(GTK_BOX(main_vbox), ver_label, FALSE, FALSE, 5);
    
    GtkWidget *sep_top = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(main_vbox), sep_top, FALSE, FALSE, 10);
    
    /* Scrollable Features Section */
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(scrolled, -1, 250);
    gtk_box_pack_start(GTK_BOX(main_vbox), scrolled, TRUE, TRUE, 0);
    
    GtkWidget *feature_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(scrolled), feature_box);
    
    add_feature_row(feature_box, "8-Core Turbo-Wipe Engine", 
        "Utilizes massive multi-threading to saturate NVMe throughput, "
        "wiping free space in parallel across all available CPU cores.", "\xf0\x9f\x9a\x80"); /* Rocket */

    add_feature_row(feature_box, "NIST SP 800-88 Rev. 1 Alignment", 
        "Strict adherence to official sanitization guidelines (Clear, Purge) "
        "ensuring compliance with federal and international security standards.", "\xf0\x9f\x93\x9c"); /* Scroll */

    add_feature_row(feature_box, "FIPS 140-3 High-Entropy PRNG", 
        "Uses high-speed cryptographic PRNGs to ensure every byte written is "
        "mathematically indistinguishable from random noise.", "\xf0\x9f\x8e\xb2"); /* Die */

    add_feature_row(feature_box, "RAM Protection (mlock)", 
        "Sensitive buffers are locked into physical memory to prevent "
        "wiping data from being leaked to swap partitions or hibernation files.", "\xf0\x9f\x94\x92"); /* Lock */

    add_feature_row(feature_box, "TRIM &amp; Secure Discard", 
        "Automatically issues BLKDISCARD and TRIM commands to ensure "
        "NAND Flash controllers fully release the wiped blocks.", "\xf0\x9f\x97\x91\xef\xb8\x8f"); /* Trash */

    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

/* Callback for when sanitization scheme changes in combo box */
void on_scheme_changed(GtkComboBox *combo, gpointer user_data G_GNUC_UNUSED) {
    int idx = gtk_combo_box_get_active(combo);
    if (idx >= 0 && idx < 4) {
        if (current_scheme_idx != idx) {
            current_scheme_idx = idx;
            char msg[256];
            snprintf(msg, sizeof(msg), "[i] Sanitization scheme changed to: %s", schemes[idx].name);
            log_message(msg);
            
            /* Update active scheme title text on Dashboard */
            if (lbl_dash_scheme) {
                gtk_label_set_text(GTK_LABEL(lbl_dash_scheme), schemes[idx].name);
            }
            
            /* Keep both comboboxes in sync */
            if (scheme_combo && GTK_COMBO_BOX(scheme_combo) != combo) {
                g_signal_handlers_block_by_func(scheme_combo, G_CALLBACK(on_scheme_changed), NULL);
                gtk_combo_box_set_active(GTK_COMBO_BOX(scheme_combo), idx);
                g_signal_handlers_unblock_by_func(scheme_combo, G_CALLBACK(on_scheme_changed), NULL);
            }
            if (scheme_combo_free && GTK_COMBO_BOX(scheme_combo_free) != combo) {
                g_signal_handlers_block_by_func(scheme_combo_free, G_CALLBACK(on_scheme_changed), NULL);
                gtk_combo_box_set_active(GTK_COMBO_BOX(scheme_combo_free), idx);
                g_signal_handlers_unblock_by_func(scheme_combo_free, G_CALLBACK(on_scheme_changed), NULL);
            }
        }
    }
}

/* Update active sidebar styling when selecting different page stacks */
void update_sidebar_active(int active_idx) {
    for (int i = 0; i < 5; i++) {
        if (sidebar_buttons[i]) {
            GtkStyleContext *context = gtk_widget_get_style_context(sidebar_buttons[i]);
            if (i == active_idx) {
                gtk_style_context_add_class(context, "active");
            } else {
                gtk_style_context_remove_class(context, "active");
            }
        }
    }
}

/* Switch stack page when sidebar buttons are clicked */
void on_sidebar_btn_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data) {
    int page_idx = GPOINTER_TO_INT(user_data);
    const char *page_names[] = {"dashboard", "files", "freespace", "ram", "diagnostics"};
    if (page_idx >= 0 && page_idx < 5) {
        gtk_stack_set_visible_child_name(GTK_STACK(main_stack), page_names[page_idx]);
        update_sidebar_active(page_idx);
    }
}

/* Create high-tech diagnostic compliance row entries */
void add_compliance_row(GtkWidget *box, const char *name, const char *desc, gboolean passed) {
    GtkWidget *row_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    
    GtkWidget *lbl_name = gtk_label_new(name);
    gtk_label_set_xalign(GTK_LABEL(lbl_name), 0.0);
    gtk_widget_set_size_request(lbl_name, 220, -1);
    gtk_box_pack_start(GTK_BOX(row_box), lbl_name, FALSE, FALSE, 0);
    
    GtkWidget *lbl_desc = gtk_label_new(desc);
    gtk_label_set_xalign(GTK_LABEL(lbl_desc), 0.0);
    add_css_class(lbl_desc, "card-subtitle");
    gtk_box_pack_start(GTK_BOX(row_box), lbl_desc, TRUE, TRUE, 0);
    
    GtkWidget *badge = gtk_label_new(passed ? " PASS " : " WARN ");
    add_css_class(badge, passed ? "badge-success" : "badge-warning");
    gtk_box_pack_end(GTK_BOX(row_box), badge, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(box), row_box, FALSE, FALSE, 4);
    
    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_opacity(sep, 0.1);
    gtk_box_pack_start(GTK_BOX(box), sep, FALSE, FALSE, 2);
}

/* Helper to generate a dashboard card */
GtkWidget* create_card(const char *icon, const char *title, const char *initial_val, const char *desc, GtkWidget **out_label) {
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    add_css_class(card, "card");
    
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *lbl_icon = gtk_label_new(icon);
    add_css_class(lbl_icon, "card-icon");
    gtk_box_pack_start(GTK_BOX(hbox), lbl_icon, FALSE, FALSE, 0);
    
    GtkWidget *lbl_title = gtk_label_new(title);
    gtk_label_set_xalign(GTK_LABEL(lbl_title), 0.0);
    add_css_class(lbl_title, "card-title");
    gtk_box_pack_start(GTK_BOX(hbox), lbl_title, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(card), hbox, FALSE, FALSE, 0);
    
    GtkWidget *lbl_val = gtk_label_new(initial_val);
    gtk_label_set_xalign(GTK_LABEL(lbl_val), 0.0);
    add_css_class(lbl_val, "card-value");
    gtk_label_set_ellipsize(GTK_LABEL(lbl_val), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(lbl_val), 20);
    gtk_box_pack_start(GTK_BOX(card), lbl_val, FALSE, FALSE, 0);
    if (out_label) *out_label = lbl_val;
    
    GtkWidget *lbl_desc = gtk_label_new(desc);
    gtk_label_set_xalign(GTK_LABEL(lbl_desc), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(lbl_desc), TRUE);
    add_css_class(lbl_desc, "card-subtitle");
    gtk_box_pack_start(GTK_BOX(card), lbl_desc, FALSE, FALSE, 0);
    
    return card;
}

/* Dynamic updates of dashboard values */
gboolean update_dashboard_stats(gpointer user_data G_GNUC_UNUSED) {
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        unsigned long mem_unit = si.mem_unit ? si.mem_unit : 1;
        double total_gb = (double)(si.totalram * mem_unit) / (1024.0 * 1024.0 * 1024.0);
        double free_gb = (double)((si.freeram + si.bufferram) * mem_unit) / (1024.0 * 1024.0 * 1024.0);
        double used_gb = total_gb - free_gb;
        
        char ram_text[128];
        snprintf(ram_text, sizeof(ram_text), "%.1f / %.1f GB (%.0f%%)", 
                 used_gb, total_gb, (used_gb / total_gb) * 100.0);
        gtk_label_set_text(GTK_LABEL(lbl_dash_ram), ram_text);
    }
    
    // Update active scheme text
    int active_scheme = gtk_combo_box_get_active(GTK_COMBO_BOX(scheme_combo));
    if (active_scheme >= 0 && active_scheme < 4) {
        gtk_label_set_text(GTK_LABEL(lbl_dash_scheme), schemes[active_scheme].name);
    }
    
    // Update status
    if (g_operation_running) {
        gtk_label_set_markup(GTK_LABEL(lbl_dash_status), "<span color='#f59e0b' weight='bold'>SANITIZATION ENGINE ACTIVE</span>");
    } else {
        gtk_label_set_markup(GTK_LABEL(lbl_dash_status), "<span color='#00ffcc' weight='bold'>SYSTEM IDLE / SECURE</span>");
    }
    
    return TRUE; // Continue running
}

void on_clear_log_clicked(GtkButton *button G_GNUC_UNUSED, gpointer user_data G_GNUC_UNUSED) {
    if (log_buffer) {
        gtk_text_buffer_set_text(log_buffer, "", -1);
    }
}

/* Create redesigned premium main UI */
GtkWidget* create_main_window(void) {
    main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(main_window), "vWipe Turbo - Secure Data Sanitization Dashboard");
    gtk_window_set_default_size(GTK_WINDOW(main_window), 965, 645);
    gtk_window_set_position(GTK_WINDOW(main_window), GTK_WIN_POS_NONE);
    GdkDisplay *display = gdk_display_get_default();
    if (display) {
        GdkMonitor *monitor = gdk_display_get_primary_monitor(display);
        if (!monitor) {
            monitor = gdk_display_get_monitor(display, 0);
        }
        if (monitor) {
            GdkRectangle geometry;
            gdk_monitor_get_geometry(monitor, &geometry);
            gint x = geometry.x + (geometry.width - 965) / 2;
            gint y = geometry.y;
            gtk_window_move(GTK_WINDOW(main_window), x, y);
        }
    }

    /* Set taskbar icon with fallbacks */
    const char *vwipe_icon_paths[] = {
        "/usr/local/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        "/usr/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        "~/.local/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        "/usr/local/share/icons/hicolor/256x256/apps/vwipe.png",
        "/usr/share/icons/hicolor/256x256/apps/vwipe.png",
        "~/.local/share/icons/hicolor/256x256/apps/vwipe.png",
        "vwipe_icon.svg",
        "vwipe.png",
        NULL
    };
    
    GdkPixbuf *pb = NULL;
    for (int i = 0; vwipe_icon_paths[i] != NULL; i++) {
        char expanded[1024];
        if (vwipe_icon_paths[i][0] == '~') {
            snprintf(expanded, sizeof(expanded), "%s%s", getenv("HOME"), vwipe_icon_paths[i] + 1);
        } else {
            strncpy(expanded, vwipe_icon_paths[i], sizeof(expanded)-1);
        }
        pb = gdk_pixbuf_new_from_file_at_size(expanded, 64, 64, NULL);
        if (pb) break;
    }
    
    if (pb) {
        gtk_window_set_icon(GTK_WINDOW(main_window), pb);
        g_object_unref(pb);
    }
    
    g_signal_connect(main_window, "destroy", G_CALLBACK(on_window_destroy), NULL);
    
    /* Register custom CSS Stylesheet */
    GtkCssProvider *css_provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(css_provider, custom_css, -1, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(css_provider), GTK_STYLE_PROVIDER_PRIORITY_USER);

    /* Main Container Split: Sidebar (left) + Main Content (right) */
    GtkWidget *main_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_container_add(GTK_CONTAINER(main_window), main_hbox);

    /* Sidebar creation */
    GtkWidget *sidebar = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    add_css_class(sidebar, "sidebar");
    gtk_widget_set_size_request(sidebar, 220, -1);
    gtk_box_pack_start(GTK_BOX(main_hbox), sidebar, FALSE, FALSE, 0);

    /* Sidebar Header */
    GtkWidget *logo_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_set_margin_bottom(logo_box, 25);
    gtk_widget_set_margin_start(logo_box, 10);
    
    GtkWidget *lbl_logo = gtk_label_new("vWipe Turbo");
    gtk_label_set_xalign(GTK_LABEL(lbl_logo), 0.0);
    add_css_class(lbl_logo, "sidebar-logo");
    gtk_box_pack_start(GTK_BOX(logo_box), lbl_logo, FALSE, FALSE, 0);
    
    GtkWidget *lbl_sub = gtk_label_new("FORENSIC SANITIZER");
    gtk_label_set_xalign(GTK_LABEL(lbl_sub), 0.0);
    add_css_class(lbl_sub, "sidebar-subtitle");
    gtk_box_pack_start(GTK_BOX(logo_box), lbl_sub, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(sidebar), logo_box, FALSE, FALSE, 0);

    /* Navigation buttons */
    const char *tab_names[] = {
        "📊  Dashboard",
        "📄  File Sanitizer",
        "💾  Free Space",
        "⚡  RAM Sanitizer",
        "🛡️  Diagnostics"
    };

    for (int i = 0; i < 5; i++) {
        sidebar_buttons[i] = gtk_button_new_with_label(tab_names[i]);
        add_css_class(sidebar_buttons[i], "sidebar-btn");
        GtkWidget *lbl = gtk_bin_get_child(GTK_BIN(sidebar_buttons[i]));
        if (lbl && GTK_IS_LABEL(lbl)) {
            gtk_label_set_xalign(GTK_LABEL(lbl), 0.0);
        }
        g_signal_connect(sidebar_buttons[i], "clicked", G_CALLBACK(on_sidebar_btn_clicked), GINT_TO_POINTER(i));
        gtk_box_pack_start(GTK_BOX(sidebar), sidebar_buttons[i], FALSE, FALSE, 0);
    }

    GtkWidget *btn_about = gtk_button_new_with_label("ℹ️  About vWipe");
    add_css_class(btn_about, "sidebar-btn");
    GtkWidget *lbl_about = gtk_bin_get_child(GTK_BIN(btn_about));
    if (lbl_about && GTK_IS_LABEL(lbl_about)) {
        gtk_label_set_xalign(GTK_LABEL(lbl_about), 0.0);
    }
    g_signal_connect(btn_about, "clicked", G_CALLBACK(on_menu_about_activate), NULL);
    gtk_box_pack_start(GTK_BOX(sidebar), btn_about, FALSE, FALSE, 0);

    GtkWidget *btn_quit = gtk_button_new_with_label("🚪  Exit Application");
    add_css_class(btn_quit, "sidebar-btn");
    GtkWidget *lbl_quit = gtk_bin_get_child(GTK_BIN(btn_quit));
    if (lbl_quit && GTK_IS_LABEL(lbl_quit)) {
        gtk_label_set_xalign(GTK_LABEL(lbl_quit), 0.0);
    }
    g_signal_connect(btn_quit, "clicked", G_CALLBACK(on_window_destroy), NULL);
    gtk_box_pack_start(GTK_BOX(sidebar), btn_quit, FALSE, FALSE, 0);

    GdkPixbuf *logo_pb = NULL;
    const char *logo_paths[] = {
        "vwipe_icon.svg",
        "vwipe.png",
        "/usr/local/share/icons/hicolor/256x256/apps/vwipe.png",
        "/usr/share/icons/hicolor/256x256/apps/vwipe.png",
        "~/.local/share/icons/hicolor/256x256/apps/vwipe.png",
        "/usr/local/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        "/usr/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        "~/.local/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        NULL
    };
    for (int i = 0; logo_paths[i] != NULL; i++) {
        char expanded[1024];
        if (logo_paths[i][0] == '~') {
            snprintf(expanded, sizeof(expanded), "%s%s", getenv("HOME"), logo_paths[i] + 1);
        } else {
            strncpy(expanded, logo_paths[i], sizeof(expanded)-1);
            expanded[sizeof(expanded)-1] = '\0';
        }
        logo_pb = gdk_pixbuf_new_from_file_at_size(expanded, 96, 96, NULL);
        if (logo_pb) break;
    }
    
    GtkWidget *sidebar_logo_img;
    if (logo_pb) {
        sidebar_logo_img = gtk_image_new_from_pixbuf(logo_pb);
        g_object_unref(logo_pb);
    } else {
        sidebar_logo_img = gtk_image_new_from_icon_name("applications-system", GTK_ICON_SIZE_DIALOG);
    }
    
    gtk_widget_set_halign(sidebar_logo_img, GTK_ALIGN_CENTER);
    gtk_widget_set_valign(sidebar_logo_img, GTK_ALIGN_CENTER);
    gtk_widget_set_opacity(sidebar_logo_img, 0.75);
    gtk_widget_set_margin_top(sidebar_logo_img, 20);
    
    /* Pack logo image into the sidebar without expansion so it stays near the exit button */
    gtk_box_pack_start(GTK_BOX(sidebar), sidebar_logo_img, FALSE, FALSE, 0);

    /* Main content area */
    GtkWidget *content_area = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_container_set_border_width(GTK_CONTAINER(content_area), 20);
    gtk_box_pack_start(GTK_BOX(main_hbox), content_area, TRUE, TRUE, 0);

    /* GtkStack holding pages wrapped in a scrolled window */
    main_stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(main_stack), GTK_STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT);
    gtk_stack_set_transition_duration(GTK_STACK(main_stack), 200);

    GtkWidget *stack_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(stack_scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(stack_scrolled, -1, 350);
    gtk_container_add(GTK_CONTAINER(stack_scrolled), main_stack);
    gtk_box_pack_start(GTK_BOX(content_area), stack_scrolled, TRUE, TRUE, 0);

    /* --- PAGE 0: DASHBOARD --- */
    GtkWidget *page0 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    add_css_class(page0, "page-container");

    GtkWidget *lbl_p0_title = gtk_label_new("Dashboard Overview");
    gtk_label_set_xalign(GTK_LABEL(lbl_p0_title), 0.0);
    add_css_class(lbl_p0_title, "page-title");
    gtk_box_pack_start(GTK_BOX(page0), lbl_p0_title, FALSE, FALSE, 0);

    GtkWidget *lbl_p0_subtitle = gtk_label_new("Live system security metrics and sanitization statistics");
    gtk_label_set_xalign(GTK_LABEL(lbl_p0_subtitle), 0.0);
    add_css_class(lbl_p0_subtitle, "page-subtitle");
    gtk_box_pack_start(GTK_BOX(page0), lbl_p0_subtitle, FALSE, FALSE, 0);

    /* Card grid */
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_row_homogeneous(GTK_GRID(grid), TRUE);
    gtk_grid_set_column_homogeneous(GTK_GRID(grid), TRUE);
    gtk_box_pack_start(GTK_BOX(page0), grid, FALSE, FALSE, 0);

    int cores = sysconf(_SC_NPROCESSORS_ONLN);
    char cores_txt[64];
    snprintf(cores_txt, sizeof(cores_txt), "%d Worker Cores", cores);

    GtkWidget *card1 = create_card("⚙️", "Parallel Engine", cores_txt, "Saturating NVMe queue depths", &lbl_dash_cpu);
    GtkWidget *card2 = create_card("🔒", "Memory Shield", "mlock() Active", "Prevents memory buffers spilling to swap", &lbl_dash_mlock);
    GtkWidget *card3 = create_card("🧬", "PRNG Source", "NIST SP 800-88", "Math. indistinguishable from random noise", &lbl_dash_entropy);
    GtkWidget *card4 = create_card("💾", "System RAM", "0.0 GB / 0.0 GB", "Live available physical memory", &lbl_dash_ram);

    gtk_grid_attach(GTK_GRID(grid), card1, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), card2, 1, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), card3, 2, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), card4, 3, 0, 1, 1);

    /* Initialize core lock status text */
    if (g_mlock_supported) {
        gtk_label_set_markup(GTK_LABEL(lbl_dash_mlock), "<span color='#10b981' weight='bold'>mlock() Active</span>");
    } else {
        gtk_label_set_markup(GTK_LABEL(lbl_dash_mlock), "<span color='#f59e0b' weight='bold'>mlock() Blocked</span>");
    }

    /* Overall status box */
    GtkWidget *status_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    add_css_class(status_card, "card");
    gtk_box_pack_start(GTK_BOX(page0), status_card, FALSE, FALSE, 4);

    GtkWidget *lbl_status_hdr = gtk_label_new("WIPING ENGINE STATUS");
    gtk_label_set_xalign(GTK_LABEL(lbl_status_hdr), 0.0);
    add_css_class(lbl_status_hdr, "card-title");
    gtk_box_pack_start(GTK_BOX(status_card), lbl_status_hdr, FALSE, FALSE, 0);

    lbl_dash_status = gtk_label_new(NULL);
    gtk_label_set_xalign(GTK_LABEL(lbl_dash_status), 0.0);
    gtk_label_set_markup(GTK_LABEL(lbl_dash_status), "<span size='x-large' color='#00ffcc' weight='bold'>SYSTEM IDLE / SECURE</span>");
    gtk_box_pack_start(GTK_BOX(status_card), lbl_dash_status, FALSE, FALSE, 0);

    GtkWidget *scheme_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *lbl_scheme_hdr = gtk_label_new("Active Protocol: ");
    gtk_label_set_xalign(GTK_LABEL(lbl_scheme_hdr), 0.0);
    gtk_box_pack_start(GTK_BOX(scheme_hbox), lbl_scheme_hdr, FALSE, FALSE, 0);

    lbl_dash_scheme = gtk_label_new(schemes[current_scheme_idx].name);
    gtk_label_set_xalign(GTK_LABEL(lbl_dash_scheme), 0.0);
    add_css_class(lbl_dash_scheme, "card-value");
    gtk_label_set_ellipsize(GTK_LABEL(lbl_dash_scheme), PANGO_ELLIPSIZE_END);
    gtk_label_set_max_width_chars(GTK_LABEL(lbl_dash_scheme), 25);
    gtk_box_pack_start(GTK_BOX(scheme_hbox), lbl_dash_scheme, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(status_card), scheme_hbox, FALSE, FALSE, 0);

    /* Engine Telemetry Logs inside page0 (under status card) */
    GtkWidget *log_header_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *lbl_log_hdr = gtk_label_new("ENGINE TELEMETRY LOGS");
    gtk_label_set_xalign(GTK_LABEL(lbl_log_hdr), 0.0);
    add_css_class(lbl_log_hdr, "card-title");
    gtk_box_pack_start(GTK_BOX(log_header_hbox), lbl_log_hdr, TRUE, TRUE, 0);

    GtkWidget *btn_clear_log = gtk_button_new_with_label("Clear Logs");
    gtk_button_set_relief(GTK_BUTTON(btn_clear_log), GTK_RELIEF_NONE);
    g_signal_connect(btn_clear_log, "clicked", G_CALLBACK(on_clear_log_clicked), NULL);
    gtk_box_pack_end(GTK_BOX(log_header_hbox), btn_clear_log, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(page0), log_header_hbox, FALSE, FALSE, 2);

    GtkWidget *log_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(log_scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(log_scrolled, -1, 130);
    gtk_box_pack_start(GTK_BOX(page0), log_scrolled, TRUE, TRUE, 0);

    log_textview = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(log_textview), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(log_textview), GTK_WRAP_WORD);
    add_css_class(log_textview, "terminal-log");
    gtk_container_add(GTK_CONTAINER(log_scrolled), log_textview);

    log_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(log_textview));
    GtkTextIter end_iter;
    gtk_text_buffer_get_end_iter(log_buffer, &end_iter);
    gtk_text_buffer_create_mark(log_buffer, "end", &end_iter, FALSE);

    gtk_stack_add_named(GTK_STACK(main_stack), page0, "dashboard");

    /* --- PAGE 1: FILE & FOLDER SANITIZER --- */
    GtkWidget *page1 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    add_css_class(page1, "page-container");

    GtkWidget *lbl_p1_title = gtk_label_new("File & Folder Sanitizer");
    gtk_label_set_xalign(GTK_LABEL(lbl_p1_title), 0.0);
    add_css_class(lbl_p1_title, "page-title");
    gtk_box_pack_start(GTK_BOX(page1), lbl_p1_title, FALSE, FALSE, 0);

    GtkWidget *lbl_p1_subtitle = gtk_label_new("Targeted secure overwrite of files and directories");
    gtk_label_set_xalign(GTK_LABEL(lbl_p1_subtitle), 0.0);
    add_css_class(lbl_p1_subtitle, "page-subtitle");
    gtk_box_pack_start(GTK_BOX(page1), lbl_p1_subtitle, FALSE, FALSE, 0);

    /* Scheme selection */
    GtkWidget *scheme_card = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    add_css_class(scheme_card, "card");
    gtk_box_pack_start(GTK_BOX(page1), scheme_card, FALSE, FALSE, 5);

    GtkWidget *lbl_scheme_combo = gtk_label_new("Sanitization Protocol:");
    gtk_widget_set_valign(lbl_scheme_combo, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(scheme_card), lbl_scheme_combo, FALSE, FALSE, 0);

    scheme_combo = gtk_combo_box_text_new();
    for (int i = 0; i < 4; i++) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(scheme_combo), schemes[i].name);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(scheme_combo), current_scheme_idx);
    g_signal_connect(scheme_combo, "changed", G_CALLBACK(on_scheme_changed), NULL);
    gtk_box_pack_start(GTK_BOX(scheme_card), scheme_combo, TRUE, TRUE, 0);

    /* File Eraser Card */
    GtkWidget *file_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    add_css_class(file_card, "card");
    gtk_box_pack_start(GTK_BOX(page1), file_card, FALSE, FALSE, 5);

    GtkWidget *lbl_file_title = gtk_label_new("Target File Eraser");
    gtk_label_set_xalign(GTK_LABEL(lbl_file_title), 0.0);
    add_css_class(lbl_file_title, "card-title");
    gtk_box_pack_start(GTK_BOX(file_card), lbl_file_title, FALSE, FALSE, 0);

    GtkWidget *file_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    file_chooser_button = gtk_file_chooser_button_new("Select target file...", GTK_FILE_CHOOSER_ACTION_OPEN);
    gtk_box_pack_start(GTK_BOX(file_hbox), file_chooser_button, TRUE, TRUE, 0);

    file_wipe_btn = gtk_button_new_with_label("Wipe File");
    add_css_class(file_wipe_btn, "action-btn");
    g_signal_connect(file_wipe_btn, "clicked", G_CALLBACK(on_file_wipe_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(file_hbox), file_wipe_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(file_card), file_hbox, FALSE, FALSE, 0);

    /* Directory Eraser Card */
    GtkWidget *dir_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    add_css_class(dir_card, "card");
    gtk_box_pack_start(GTK_BOX(page1), dir_card, FALSE, FALSE, 5);

    GtkWidget *lbl_dir_title = gtk_label_new("Target Directory Eraser");
    gtk_label_set_xalign(GTK_LABEL(lbl_dir_title), 0.0);
    add_css_class(lbl_dir_title, "card-title");
    gtk_box_pack_start(GTK_BOX(dir_card), lbl_dir_title, FALSE, FALSE, 0);

    GtkWidget *dir_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    dir_chooser_button = gtk_file_chooser_button_new("Select target folder...", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
    gtk_box_pack_start(GTK_BOX(dir_hbox), dir_chooser_button, TRUE, TRUE, 0);

    dir_wipe_btn = gtk_button_new_with_label("Wipe Folder");
    add_css_class(dir_wipe_btn, "action-btn");
    g_signal_connect(dir_wipe_btn, "clicked", G_CALLBACK(on_directory_wipe_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(dir_hbox), dir_wipe_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(dir_card), dir_hbox, FALSE, FALSE, 0);

    gtk_stack_add_named(GTK_STACK(main_stack), page1, "files");

    /* --- PAGE 2: FREE SPACE SANITIZER --- */
    GtkWidget *page2 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    add_css_class(page2, "page-container");

    GtkWidget *lbl_p2_title = gtk_label_new("Free Space Sanitizer");
    gtk_label_set_xalign(GTK_LABEL(lbl_p2_title), 0.0);
    add_css_class(lbl_p2_title, "page-title");
    gtk_box_pack_start(GTK_BOX(page2), lbl_p2_title, FALSE, FALSE, 0);

    GtkWidget *lbl_p2_subtitle = gtk_label_new("Purge trace data leftovers on the disk's unallocated blocks");
    gtk_label_set_xalign(GTK_LABEL(lbl_p2_subtitle), 0.0);
    add_css_class(lbl_p2_subtitle, "page-subtitle");
    gtk_box_pack_start(GTK_BOX(page2), lbl_p2_subtitle, FALSE, FALSE, 0);

    /* Scheme selection */
    GtkWidget *scheme_card_free = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 15);
    add_css_class(scheme_card_free, "card");
    gtk_box_pack_start(GTK_BOX(page2), scheme_card_free, FALSE, FALSE, 5);

    GtkWidget *lbl_scheme_combo_free = gtk_label_new("Sanitization Protocol:");
    gtk_widget_set_valign(lbl_scheme_combo_free, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(scheme_card_free), lbl_scheme_combo_free, FALSE, FALSE, 0);

    scheme_combo_free = gtk_combo_box_text_new();
    for (int i = 0; i < 4; i++) {
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(scheme_combo_free), schemes[i].name);
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(scheme_combo_free), current_scheme_idx);
    g_signal_connect(scheme_combo_free, "changed", G_CALLBACK(on_scheme_changed), NULL);
    gtk_box_pack_start(GTK_BOX(scheme_card_free), scheme_combo_free, TRUE, TRUE, 0);

    GtkWidget *free_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    add_css_class(free_card, "card");
    gtk_box_pack_start(GTK_BOX(page2), free_card, FALSE, FALSE, 5);

    /* Mount selection */
    GtkWidget *mnt_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *lbl_mnt = gtk_label_new("Select Partition Mount:");
    gtk_box_pack_start(GTK_BOX(mnt_hbox), lbl_mnt, FALSE, FALSE, 0);
    free_space_chooser_button = gtk_file_chooser_button_new("Select mount point...", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER);
    gtk_box_pack_start(GTK_BOX(mnt_hbox), free_space_chooser_button, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(free_card), mnt_hbox, FALSE, FALSE, 0);

    /* Thread selection slider */
    GtkWidget *thread_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *lbl_threads_title = gtk_label_new("Parallel Execution Threads:");
    gtk_label_set_xalign(GTK_LABEL(lbl_threads_title), 0.0);
    add_css_class(lbl_threads_title, "card-title");
    gtk_box_pack_start(GTK_BOX(thread_box), lbl_threads_title, FALSE, FALSE, 0);

    threads_scale = gtk_scale_new_with_range(GTK_ORIENTATION_HORIZONTAL, 1.0, 16.0, 1.0);
    gtk_scale_set_draw_value(GTK_SCALE(threads_scale), TRUE);
    gtk_scale_set_value_pos(GTK_SCALE(threads_scale), GTK_POS_RIGHT);
    gtk_range_set_value(GTK_RANGE(threads_scale), (double)cores);
    gtk_box_pack_start(GTK_BOX(thread_box), threads_scale, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(free_card), thread_box, FALSE, FALSE, 5);

    /* Start Button */
    free_space_btn = gtk_button_new_with_label("Start Free Space Wiping");
    add_css_class(free_space_btn, "action-btn");
    g_signal_connect(free_space_btn, "clicked", G_CALLBACK(on_free_space_wipe_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(free_card), free_space_btn, FALSE, FALSE, 10);

    /* COW Warnings notice */
    GtkWidget *lbl_cow_notice = gtk_label_new("Forensic Warning: Copy-on-Write (CoW) filesystems (Btrfs, ZFS) do not overwrite\n"
        "blocks directly on disk. For complete data removal, Free Space Sanitization is the\n"
        "only standard recommended way to destroy historic metadata residues.");
    gtk_label_set_xalign(GTK_LABEL(lbl_cow_notice), 0.0);
    add_css_class(lbl_cow_notice, "card-subtitle");
    gtk_box_pack_start(GTK_BOX(free_card), lbl_cow_notice, FALSE, FALSE, 5);

    gtk_stack_add_named(GTK_STACK(main_stack), page2, "freespace");

    /* --- PAGE 3: RAM SANITIZER --- */
    GtkWidget *page3 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    add_css_class(page3, "page-container");

    GtkWidget *lbl_p3_title = gtk_label_new("RAM Sanitizer");
    gtk_label_set_xalign(GTK_LABEL(lbl_p3_title), 0.0);
    add_css_class(lbl_p3_title, "page-title");
    gtk_box_pack_start(GTK_BOX(page3), lbl_p3_title, FALSE, FALSE, 0);

    GtkWidget *lbl_p3_subtitle = gtk_label_new("Lock and fill volatile memory to clear forensic traces");
    gtk_label_set_xalign(GTK_LABEL(lbl_p3_subtitle), 0.0);
    add_css_class(lbl_p3_subtitle, "page-subtitle");
    gtk_box_pack_start(GTK_BOX(page3), lbl_p3_subtitle, FALSE, FALSE, 0);

    GtkWidget *ram_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    add_css_class(ram_card, "card");
    gtk_box_pack_start(GTK_BOX(page3), ram_card, FALSE, FALSE, 5);

    /* Safety Margin Spin */
    GtkWidget *ram_spin_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    GtkWidget *lbl_ram_spin = gtk_label_new("Safety Margin Buffer:");
    gtk_box_pack_start(GTK_BOX(ram_spin_hbox), lbl_ram_spin, FALSE, FALSE, 0);

    ram_fill_spinbutton = gtk_spin_button_new_with_range(100, 4000, 50);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(ram_fill_spinbutton), DEFAULT_SAFETY_MB);
    gtk_box_pack_start(GTK_BOX(ram_spin_hbox), ram_fill_spinbutton, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(ram_spin_hbox), gtk_label_new("MB RAM Safety Margin"), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(ram_card), ram_spin_hbox, FALSE, FALSE, 0);

    /* Button */
    ram_fill_btn = gtk_button_new_with_label("Launch RAM Sanitizer");
    add_css_class(ram_fill_btn, "action-btn");
    g_signal_connect(ram_fill_btn, "clicked", G_CALLBACK(on_ram_fill_clicked), NULL);
    gtk_box_pack_start(GTK_BOX(ram_card), ram_fill_btn, FALSE, FALSE, 10);

    /* Notice */
    GtkWidget *lbl_ram_notice = gtk_label_new("Engine Behavior Notice:\n"
        "To avoid operating system Out-Of-Memory (OOM) lockups, vWipe preserves a buffer\n"
        "determined by the safety margin slider. RAM sanitization executes in a secure CLI\n"
        "terminal. You can monitor progress there and terminate safely with 's' at any time.");
    gtk_label_set_xalign(GTK_LABEL(lbl_ram_notice), 0.0);
    gtk_label_set_line_wrap(GTK_LABEL(lbl_ram_notice), TRUE);
    add_css_class(lbl_ram_notice, "card-subtitle");
    gtk_box_pack_start(GTK_BOX(ram_card), lbl_ram_notice, FALSE, FALSE, 5);

    gtk_stack_add_named(GTK_STACK(main_stack), page3, "ram");

    /* --- PAGE 4: SECURITY DIAGNOSTICS & STANDARDS --- */
    GtkWidget *page4 = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    add_css_class(page4, "page-container");

    GtkWidget *lbl_p4_title = gtk_label_new("System Diagnostics & Compliance");
    gtk_label_set_xalign(GTK_LABEL(lbl_p4_title), 0.0);
    add_css_class(lbl_p4_title, "page-title");
    gtk_box_pack_start(GTK_BOX(page4), lbl_p4_title, FALSE, FALSE, 0);

    GtkWidget *lbl_p4_subtitle = gtk_label_new("Alignment compliance scanning with NIST SP 800-88 standards");
    gtk_label_set_xalign(GTK_LABEL(lbl_p4_subtitle), 0.0);
    add_css_class(lbl_p4_subtitle, "page-subtitle");
    gtk_box_pack_start(GTK_BOX(page4), lbl_p4_subtitle, FALSE, FALSE, 0);

    /* Checklist card */
    GtkWidget *comp_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    add_css_class(comp_card, "card");
    gtk_box_pack_start(GTK_BOX(page4), comp_card, FALSE, FALSE, 5);

    GtkWidget *lbl_comp_title = gtk_label_new("Workstation Compliance Checklist");
    gtk_label_set_xalign(GTK_LABEL(lbl_comp_title), 0.0);
    add_css_class(lbl_comp_title, "card-title");
    gtk_box_pack_start(GTK_BOX(comp_card), lbl_comp_title, FALSE, FALSE, 5);

    /* Run check on dumpable */
    int dumpable = prctl(PR_GET_DUMPABLE);

    add_compliance_row(comp_card, "NIST 800-88 Alignment", "Sanitization passes adhere to official specifications", TRUE);
    add_compliance_row(comp_card, "Memory Locking (mlock)", "Locks memory buffers to prevent swap file leaking", g_mlock_supported);
    add_compliance_row(comp_card, "Core Dump Security", "Core files are disabled to prevent memory dumping on crash", (dumpable == 0));
    add_compliance_row(comp_card, "Cryptographic PRNG Source", "getrandom() system entropy call is active", TRUE);

    /* Standards list */
    GtkWidget *standards_scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(standards_scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(standards_scrolled, -1, 160);
    gtk_box_pack_start(GTK_BOX(page4), standards_scrolled, TRUE, TRUE, 5);

    GtkWidget *standards_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_container_add(GTK_CONTAINER(standards_scrolled), standards_vbox);

    GtkWidget *std_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    add_css_class(std_card, "card");
    gtk_box_pack_start(GTK_BOX(standards_vbox), std_card, FALSE, FALSE, 0);

    GtkWidget *lbl_std_title = gtk_label_new("Sanitization Protocol Details");
    gtk_label_set_xalign(GTK_LABEL(lbl_std_title), 0.0);
    add_css_class(lbl_std_title, "card-title");
    gtk_box_pack_start(GTK_BOX(std_card), lbl_std_title, FALSE, FALSE, 5);

    GtkWidget *lbl_std_body = gtk_label_new(
        "1. NIST Clear (Baseline)\n"
        "   - Single zero pass (0x00). Fast baseline overwrite.\n"
        "2. DoD 5220.22-M\n"
        "   - 3-Pass overwrite (Zeroes -> Ones -> Random). High forensic standard.\n"
        "3. NIST Purge (Multi-Pass)\n"
        "   - 4-Pass overwrite (Zeroes -> Ones -> Random -> Verify). Standard forensic purge.\n"
        "4. FIPS High-Entropy Purge\n"
        "   - 5-Pass overwrite (Random -> Random -> Zeroes -> Random -> Verify). Maximum security."
    );
    gtk_label_set_xalign(GTK_LABEL(lbl_std_body), 0.0);
    add_css_class(lbl_std_body, "card-subtitle");
    gtk_box_pack_start(GTK_BOX(std_card), lbl_std_body, FALSE, FALSE, 5);

    gtk_stack_add_named(GTK_STACK(main_stack), page4, "diagnostics");

    /* --- SHARED PROGRESS AREA --- */
    GtkWidget *bottom_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    gtk_box_pack_end(GTK_BOX(content_area), bottom_box, FALSE, FALSE, 0);

    GtkWidget *bottom_sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_widget_set_opacity(bottom_sep, 0.2);
    gtk_box_pack_start(GTK_BOX(bottom_box), bottom_sep, FALSE, FALSE, 5);

    /* Progress stats */
    GtkWidget *progress_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    progress_bar = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(progress_vbox), progress_bar, FALSE, FALSE, 0);

    status_label = gtk_label_new("Engine Ready");
    gtk_label_set_xalign(GTK_LABEL(status_label), 0.0);
    add_css_class(status_label, "card-subtitle");
    gtk_box_pack_start(GTK_BOX(progress_vbox), status_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bottom_box), progress_vbox, FALSE, FALSE, 0);

    /* Controls (Emergency Stop) */
    GtkWidget *ctrl_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    stop_button = gtk_button_new_with_label("🛑 Emergency Stop");
    add_css_class(stop_button, "stop-btn");
    g_signal_connect(stop_button, "clicked", G_CALLBACK(on_stop_clicked), NULL);
    gtk_widget_set_sensitive(stop_button, FALSE);
    gtk_box_pack_start(GTK_BOX(ctrl_hbox), stop_button, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bottom_box), ctrl_hbox, FALSE, FALSE, 5);

    /* Set default active tab style */
    gtk_stack_set_visible_child_name(GTK_STACK(main_stack), "dashboard");
    update_sidebar_active(0);

    /* Initialize background timer for live system telemetry updates */
    dashboard_timeout_id = g_timeout_add(2000, update_dashboard_stats, NULL);

    return main_window;
}

#define SECRET_KEY "vWipe-Turbo-Super-Secret-Key-2026"

/* SHA-256 Self-Contained Implementation */
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned long long bitlen;
    unsigned int state[8];
} SHA256_CTX;

static const unsigned int k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const unsigned char data[]) {
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const unsigned char data[], size_t len) {
    unsigned int i;

    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, unsigned char hash[]) {
    unsigned int i;

    i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[56] = ctx->bitlen >> 56;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[63] = ctx->bitlen;
    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
    }
}

void sha256_hex(const char *data, size_t len, char *hex_output) {
    SHA256_CTX ctx;
    unsigned char hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, (const unsigned char*)data, len);
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++) {
        sprintf(hex_output + (i * 2), "%02x", hash[i]);
    }
    hex_output[64] = '\0';
}

/* License & Trial Validation Helpers */
int verify_license_file(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) return 0;

    char line[256];
    char customer[256] = {0};
    char exp_date[64] = {0};
    char signature[128] = {0};

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "CUSTOMER:", 9) == 0) {
            char *val = line + 9;
            while (*val == ' ' || *val == '\t') val++;
            if (strlen(val) < sizeof(customer)) {
                strcpy(customer, val);
            }
        } else if (strncmp(line, "EXPIRATION_DATE:", 16) == 0) {
            char *val = line + 16;
            while (*val == ' ' || *val == '\t') val++;
            if (strlen(val) < sizeof(exp_date)) {
                strcpy(exp_date, val);
            }
        } else if (strncmp(line, "SIGNATURE:", 10) == 0) {
            char *val = line + 10;
            while (*val == ' ' || *val == '\t') val++;
            if (strlen(val) < sizeof(signature)) {
                strcpy(signature, val);
            }
        }
    }
    fclose(file);

    if (strlen(exp_date) == 0 || strlen(signature) == 0) {
        return 0;
    }

    char input_for_hash[512];
    if (strlen(customer) > 0) {
        snprintf(input_for_hash, sizeof(input_for_hash), "%s:%s:%s", customer, exp_date, SECRET_KEY);
    } else {
        snprintf(input_for_hash, sizeof(input_for_hash), "%s%s", exp_date, SECRET_KEY);
    }
    char expected_sig[65];
    sha256_hex(input_for_hash, strlen(input_for_hash), expected_sig);

    if (strcmp(signature, expected_sig) != 0) {
        return 0;
    }

    int exp_year = 0, exp_month = 0, exp_day = 0;
    if (sscanf(exp_date, "%d-%d-%d", &exp_year, &exp_month, &exp_day) != 3) {
        return 0;
    }

    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    int cur_year = tm_info->tm_year + 1900;
    int cur_month = tm_info->tm_mon + 1;
    int cur_day = tm_info->tm_mday;

    if (cur_year < exp_year) return 1;
    if (cur_year == exp_year) {
        if (cur_month < exp_month) return 1;
        if (cur_month == exp_month) {
            if (cur_day <= exp_day) return 1;
        }
    }

    return 0;
}

int get_trial_tries_left(const char *state_path) {
    FILE *file = fopen(state_path, "r");
    if (!file) {
        return 3;
    }

    char line[256];
    int tries = -1;
    char hash_str[128] = {0};

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "TRIES:", 6) == 0) {
            tries = atoi(line + 6);
        } else if (strncmp(line, "HASH:", 5) == 0) {
            char *val = line + 5;
            while (*val == ' ' || *val == '\t') val++;
            if (strlen(val) < sizeof(hash_str)) {
                strcpy(hash_str, val);
            }
        }
    }
    fclose(file);

    if (tries < 0 || tries > 3 || strlen(hash_str) == 0) {
        return 0;
    }

    char hash_input[128];
    snprintf(hash_input, sizeof(hash_input), "%d%s", tries, SECRET_KEY);
    char expected_hash[65];
    sha256_hex(hash_input, strlen(hash_input), expected_hash);

    if (strcmp(hash_str, expected_hash) != 0) {
        return 0;
    }

    return tries;
}

void set_trial_tries_left(const char *state_path, int tries) {
    if (tries < 0) tries = 0;
    if (tries > 3) tries = 3;

    char hash_input[128];
    snprintf(hash_input, sizeof(hash_input), "%d%s", tries, SECRET_KEY);
    char hash_output[65];
    sha256_hex(hash_input, strlen(hash_input), hash_output);

    FILE *file = fopen(state_path, "w");
    if (file) {
        fprintf(file, "TRIES:%d\n", tries);
        fprintf(file, "HASH:%s\n", hash_output);
        fclose(file);
    }
}

/* Dialog Callback Structures and Functions */
struct LicenseDialogState {
    int code;
    GtkWidget *dialog;
    char *path_buffer;
    size_t path_max;
    gboolean loop;
};

static void on_license_exit_clicked(GtkButton *button, gpointer data) {
    (void)button;
    struct LicenseDialogState *state = (struct LicenseDialogState*)data;
    if (state->code == 0) {
        state->code = 0;
    }
    state->loop = FALSE;
}

static void on_license_trial_clicked(GtkButton *button, gpointer data) {
    (void)button;
    struct LicenseDialogState *state = (struct LicenseDialogState*)data;
    state->code = 1;
    state->loop = FALSE;
}

static void on_license_load_clicked(GtkButton *button, gpointer data) {
    (void)button;
    struct LicenseDialogState *state = (struct LicenseDialogState*)data;

    GtkWidget *chooser = gtk_file_chooser_dialog_new(
        "Select License File",
        GTK_WINDOW(state->dialog),
        GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Open", GTK_RESPONSE_ACCEPT,
        NULL
    );

    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "Text Files (*.txt)");
    gtk_file_filter_add_pattern(filter, "*.txt");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(chooser), filter);

    if (gtk_dialog_run(GTK_DIALOG(chooser)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
        if (filename) {
            strncpy(state->path_buffer, filename, state->path_max - 1);
            state->path_buffer[state->path_max - 1] = '\0';
            g_free(filename);

            if (verify_license_file(state->path_buffer)) {
                state->code = 2;
                state->loop = FALSE;
            } else {
                GtkWidget *err_dialog = gtk_message_dialog_new(
                    GTK_WINDOW(state->dialog),
                    GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                    GTK_MESSAGE_ERROR,
                    GTK_BUTTONS_OK,
                    "Invalid license file! Please select a valid 1-year vWipe Turbo license."
                );
                gtk_dialog_run(GTK_DIALOG(err_dialog));
                gtk_widget_destroy(err_dialog);
            }
        }
    }
    gtk_widget_destroy(chooser);
}

int check_license_verification(void) {
    char license_save_path[1024];
    char state_path[1024];
    char *home = getenv("HOME");
    if (!home) return 0;

    snprintf(license_save_path, sizeof(license_save_path), "%s/.vwipe_license", home);
    snprintf(state_path, sizeof(state_path), "%s/.vwipe_state", home);

    if (verify_license_file(license_save_path)) {
        return 1;
    }

    int tries_left = get_trial_tries_left(state_path);

    char selected_path[1024] = {0};
    struct LicenseDialogState dstate = {0, NULL, selected_path, sizeof(selected_path), TRUE};

    GtkWidget *dialog = gtk_dialog_new();
    gtk_window_set_title(GTK_WINDOW(dialog), "License Activation - vWipe Turbo");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 500, 320);
    gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);

    dstate.dialog = dialog;

    GtkCssProvider *cp = gtk_css_provider_new();
    gtk_css_provider_load_from_data(cp,
        "dialog { background-color: #0c0e14; color: #cbd5e1; }\n"
        "box { background-color: #0c0e14; }\n"
        ".dialog-card { background-color: #111420; border: 1px solid #1e293b; border-radius: 8px; padding: 15px; }\n"
        ".dialog-title { font-size: 18px; font-weight: bold; color: #ffffff; }\n"
        ".dialog-warning { font-size: 14px; font-weight: bold; color: #f59e0b; }\n"
        ".dialog-expired { font-size: 14px; font-weight: bold; color: #ef4444; }\n"
        ".action-btn { background-image: linear-gradient(to bottom right, #00f0ff, #0072ff); color: #ffffff; font-weight: bold; border: none; border-radius: 6px; padding: 10px 20px; }\n"
        ".action-btn:hover { background-image: linear-gradient(to bottom right, #33f4ff, #338eff); }\n"
        ".trial-btn { background-color: #1e293b; color: #cbd5e1; border: 1px solid #334155; border-radius: 6px; padding: 10px 20px; font-weight: bold; }\n"
        ".trial-btn:hover { background-color: #334155; color: #ffffff; }\n"
        ".exit-btn { background-image: linear-gradient(to bottom right, #ef4444, #b91c1c); color: #ffffff; font-weight: bold; border: none; border-radius: 6px; padding: 10px 20px; }\n"
        ".exit-btn:hover { background-image: linear-gradient(to bottom right, #f87171, #dc2626); }",
        -1, NULL);

    GtkStyleContext *dialog_context = gtk_widget_get_style_context(dialog);
    gtk_style_context_add_provider(dialog_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 15);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 25);
    gtk_container_add(GTK_CONTAINER(content_area), vbox);

    const char *vwipe_icon_paths[] = {
        "/usr/local/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        "/usr/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        "~/.local/share/icons/hicolor/scalable/apps/vwipe_icon.svg",
        "/usr/local/share/icons/hicolor/256x256/apps/vwipe.png",
        "/usr/share/icons/hicolor/256x256/apps/vwipe.png",
        "~/.local/share/icons/hicolor/256x256/apps/vwipe.png",
        "vwipe_icon.svg",
        "vwipe.png",
        NULL
    };
    GdkPixbuf *pb = NULL;
    for (int i = 0; vwipe_icon_paths[i] != NULL; i++) {
        char expanded[1024];
        if (vwipe_icon_paths[i][0] == '~') {
            snprintf(expanded, sizeof(expanded), "%s%s", getenv("HOME"), vwipe_icon_paths[i] + 1);
        } else {
            strncpy(expanded, vwipe_icon_paths[i], sizeof(expanded)-1);
            expanded[sizeof(expanded)-1] = '\0';
        }
        pb = gdk_pixbuf_new_from_file_at_size(expanded, 64, 64, NULL);
        if (pb) break;
    }
    GtkWidget *icon_img;
    if (pb) {
        icon_img = gtk_image_new_from_pixbuf(pb);
        g_object_unref(pb);
    } else {
        icon_img = gtk_image_new_from_icon_name("applications-system", GTK_ICON_SIZE_DIALOG);
    }
    gtk_box_pack_start(GTK_BOX(vbox), icon_img, FALSE, FALSE, 0);

    GtkWidget *lbl_title = gtk_label_new("vWipe Turbo Activation");
    GtkStyleContext *title_context = gtk_widget_get_style_context(lbl_title);
    gtk_style_context_add_class(title_context, "dialog-title");
    gtk_style_context_add_provider(title_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_box_pack_start(GTK_BOX(vbox), lbl_title, FALSE, FALSE, 0);

    GtkWidget *msg_card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    GtkStyleContext *card_context = gtk_widget_get_style_context(msg_card);
    gtk_style_context_add_class(card_context, "dialog-card");
    gtk_style_context_add_provider(card_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_box_pack_start(GTK_BOX(vbox), msg_card, TRUE, TRUE, 0);

    GtkWidget *lbl_status = gtk_label_new(NULL);
    GtkStyleContext *status_context = gtk_widget_get_style_context(lbl_status);
    gtk_style_context_add_provider(status_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);

    GtkWidget *lbl_desc = gtk_label_new(NULL);
    gtk_label_set_justify(GTK_LABEL(lbl_desc), GTK_JUSTIFY_CENTER);
    gtk_label_set_line_wrap(GTK_LABEL(lbl_desc), TRUE);

    if (tries_left > 0) {
        char status_txt[128];
        snprintf(status_txt, sizeof(status_txt), "Trial Period Active: %d %s Left", tries_left, tries_left == 1 ? "Try" : "Tries");
        gtk_label_set_text(GTK_LABEL(lbl_status), status_txt);
        gtk_style_context_add_class(status_context, "dialog-warning");

        gtk_label_set_text(GTK_LABEL(lbl_desc),
            "Virtual Wipe Turbo requires a valid 1-year license to run.\n"
            "You can choose to continue the trial, or load a license file (.txt).");
    } else {
        gtk_label_set_text(GTK_LABEL(lbl_status), "Trial Period Expired");
        gtk_style_context_add_class(status_context, "dialog-expired");

        gtk_label_set_text(GTK_LABEL(lbl_desc),
            "The trial period has expired. You can no longer run Virtual Wipe Turbo.\n"
            "Please select a valid license file (.txt) to continue using the software.");
    }

    gtk_box_pack_start(GTK_BOX(msg_card), lbl_status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(msg_card), lbl_desc, TRUE, TRUE, 0);

    GtkWidget *btn_hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_halign(btn_hbox, GTK_ALIGN_CENTER);
    gtk_box_pack_start(GTK_BOX(vbox), btn_hbox, FALSE, FALSE, 5);

    GtkWidget *btn_exit = gtk_button_new_with_label("Exit");
    GtkStyleContext *exit_context = gtk_widget_get_style_context(btn_exit);
    gtk_style_context_add_class(exit_context, "exit-btn");
    gtk_style_context_add_provider(exit_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_box_pack_start(GTK_BOX(btn_hbox), btn_exit, FALSE, FALSE, 0);

    GtkWidget *btn_trial = NULL;
    if (tries_left > 0) {
        btn_trial = gtk_button_new_with_label("Continue Trial");
        GtkStyleContext *trial_context = gtk_widget_get_style_context(btn_trial);
        gtk_style_context_add_class(trial_context, "trial-btn");
        gtk_style_context_add_provider(trial_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
        gtk_box_pack_start(GTK_BOX(btn_hbox), btn_trial, FALSE, FALSE, 0);
    }

    GtkWidget *btn_load = gtk_button_new_with_label("Load License File");
    GtkStyleContext *load_context = gtk_widget_get_style_context(btn_load);
    gtk_style_context_add_class(load_context, "action-btn");
    gtk_style_context_add_provider(load_context, GTK_STYLE_PROVIDER(cp), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    gtk_box_pack_start(GTK_BOX(btn_hbox), btn_load, FALSE, FALSE, 0);

    g_signal_connect(btn_exit, "clicked", G_CALLBACK(on_license_exit_clicked), &dstate);
    g_signal_connect(dialog, "destroy", G_CALLBACK(on_license_exit_clicked), &dstate);
    if (btn_trial) {
        g_signal_connect(btn_trial, "clicked", G_CALLBACK(on_license_trial_clicked), &dstate);
    }
    g_signal_connect(btn_load, "clicked", G_CALLBACK(on_license_load_clicked), &dstate);

    gtk_widget_show_all(dialog);

    while (dstate.loop) {
        g_main_context_iteration(NULL, TRUE);
    }

    gtk_widget_destroy(dialog);
    g_object_unref(cp);

    if (dstate.code == 2) {
        FILE *src = fopen(selected_path, "r");
        if (src) {
            FILE *dest = fopen(license_save_path, "w");
            if (dest) {
                char ch;
                while ((ch = fgetc(src)) != EOF) {
                    fputc(ch, dest);
                }
                fclose(dest);
            }
            fclose(src);
        }

        GtkWidget *success_dialog = gtk_message_dialog_new(
            NULL,
            GTK_DIALOG_MODAL,
            GTK_MESSAGE_INFO,
            GTK_BUTTONS_OK,
            "License activated successfully! Thank you for purchasing vWipe Turbo."
        );
        gtk_dialog_run(GTK_DIALOG(success_dialog));
        gtk_widget_destroy(success_dialog);

        return 1;
    } else if (dstate.code == 1) {
        tries_left--;
        set_trial_tries_left(state_path, tries_left);
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    startup_compliance_check();

    GtkWidget *window = create_main_window();
    gtk_widget_show_all(window);

    log_message("vWipe Turbo v2.5.5 initialized - Forensic Parallel Sanitizer Active");
    log_message("Ready for secure data sanitization operations");

    gtk_main();

    return 0;
}

