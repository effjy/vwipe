/* vwipe_ram.c */
/*
 * Virtual Wipe - Command-line RAM operations module
 * NIST SP 800-88 Rev. 1 aligned
 * Safer terminal-based RAM filling with 's' to stop
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <signal.h>
#include <stdint.h>
#include <sys/sysinfo.h>
#include <termios.h>
#include <poll.h>
#include <errno.h>
#include <time.h>

/* Configuration constants */
#define DEFAULT_SAFETY_MB 250
#define CHUNK_SIZE_MB     32UL  /* Conservative 32MB chunks */
#define PAGE_SIZE         4096
#define GUI_UPDATE_INTERVAL 16   /* Update every 16 allocations */

/* Global state */
void **allocated_blocks = NULL;
size_t block_count = 0;
size_t block_capacity = 0;
volatile sig_atomic_t fill_keep_running = 1;
volatile sig_atomic_t g_stop_flag = 0;
int g_mlock_supported = 0;

/* Terminal settings */
struct termios g_original_termios;
int g_termios_saved = 0;

/* Function prototypes */
void secure_memzero(void *ptr, size_t len);
void restore_terminal(void);
int check_for_stop_interrupt(void);
void startup_compliance_check(void);
void fill_ram(unsigned long safety_mb);
void release_ram(void);
void signal_handler(int sig);

/* Secure memory zeroing */
void secure_memzero(void *ptr, size_t len) {
    if (!ptr) return;
    explicit_bzero(ptr, len);
}

/* Signal handler for graceful shutdown */
void signal_handler(int sig) {
    (void)sig;
    g_stop_flag = 1;
    fill_keep_running = 0;
}

/* Restore terminal settings */
void restore_terminal(void) {
    if (g_termios_saved) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_original_termios);
        g_termios_saved = 0;
    }
}

/* Check for stop interrupt ('s' key) */
int check_for_stop_interrupt(void) {
    if (g_stop_flag) return 1;
    
    /* Use non-blocking check with small timeout for responsiveness */
    struct pollfd pfd = {STDIN_FILENO, POLLIN, 0};
    if (poll(&pfd, 1, 10) > 0) {  /* 10ms timeout */
        int ch;
        if ((ch = getchar()) == 's' || ch == 'S') {
            printf("\n\n[!] STOP REQUESTED - Cleaning up safely...\n");
            fflush(stdout);  /* Ensure message is displayed immediately */
            g_stop_flag = 1;
            fill_keep_running = 0;
            return 1;
        }
        /* Clear any other input */
        while (ch != '\n' && ch != EOF) {
            ch = getchar();
        }
    }
    return g_stop_flag;
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
    
    prctl(PR_SET_DUMPABLE, 0);
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);
}

/* Fill RAM with memory blocks - conservative approach */
void fill_ram(unsigned long safety_mb) {
    struct sysinfo si;
    if (sysinfo(&si) != 0) return;
    
    unsigned long mem_unit = si.mem_unit ? si.mem_unit : 1;
    unsigned long total_mb = (si.totalram * mem_unit) / (1024 * 1024);
    unsigned long available_mb = ((si.freeram + si.bufferram) * mem_unit) / (1024 * 1024);
    unsigned long usable_mb = available_mb > safety_mb ? available_mb - safety_mb : available_mb / 2;
    
    /* Be very conservative - limit to 75% of usable memory */
    usable_mb = (usable_mb * 3) / 4;
    
    size_t chunk_size = CHUNK_SIZE_MB * 1024 * 1024ULL;
    
    printf("\n=== Virtual Wipe - RAM Fill Module ===\n");
    printf("System Memory: %lu MB\n", total_mb);
    printf("Safety Margin: %lu MB\n", safety_mb);
    printf("Target Allocation: %lu MB (conservative)\n", usable_mb);
    printf("Chunk Size: %lu MB\n", CHUNK_SIZE_MB);
    printf("\n[*] Starting RAM allocation...\n");
    printf("[i] Press 's' then Enter to stop safely\n\n");
    
    block_capacity = (usable_mb * 1024 * 1024) / chunk_size + 1;
    allocated_blocks = calloc(block_capacity, sizeof(void *));
    if (!allocated_blocks) {
        printf("[!] Error: Cannot allocate memory for block tracking\n");
        return;
    }
    
    size_t allocated = 0;
    size_t target_bytes = usable_mb * 1024 * 1024;
    time_t start_time = time(NULL);
    
    /* Set up terminal for non-blocking input with better settings */
    tcgetattr(STDIN_FILENO, &g_original_termios);
    struct termios newt = g_original_termios;
    newt.c_lflag &= ~(ICANON | ECHO);  /* Non-canonical mode, no echo */
    newt.c_cc[VMIN] = 0;   /* Non-blocking read */
    newt.c_cc[VTIME] = 1; /* 0.1 second timeout */
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    g_termios_saved = 1;
    
    printf("\n[i] Terminal configured for interactive control\n");
    fflush(stdout);
    
    /* Allocation phase */
    printf("[*] Allocating memory blocks...\n");
    for (size_t i = 0; i < block_capacity && fill_keep_running && allocated < target_bytes; i++) {
        if (check_for_stop_interrupt()) break;
        
        void *block = aligned_alloc(PAGE_SIZE, chunk_size);
        if (!block) break;
        
        if (g_mlock_supported && mlock(block, chunk_size) != 0) g_mlock_supported = 0;
        
        allocated_blocks[i] = block;
        block_count++;
        allocated += chunk_size;
        
        if (i % 8 == 0) {
            printf("\r[+] Allocating: %.2f GB / %.2f GB", 
                   allocated / (1024.0 * 1024.0 * 1024.0),
                   target_bytes / (1024.0 * 1024.0 * 1024.0));
            fflush(stdout);
        }
    }
    printf("\n");

    if (block_count == 0) {
        printf("[!] Failed to allocate any memory blocks.\n");
        free(allocated_blocks);
        allocated_blocks = NULL;
        restore_terminal();
        return;
    }

    /* Sanitization passes */
    const char *pass_names[] = {"Zeros (0x00)", "Ones (0xFF)", "Random Pattern"};
    uint64_t secure_seed = 0;
    if (getrandom(&secure_seed, sizeof(secure_seed), 0) < 0) {
        secure_seed = (uint64_t)time(NULL);
    }
    
    for (int p = 0; p < 3 && fill_keep_running; p++) {
        printf("[*] Pass %d/3: %s\n", p + 1, pass_names[p]);
        
        for (size_t i = 0; i < block_count && fill_keep_running; i++) {
            unsigned char *ptr = (unsigned char *)allocated_blocks[i];
            
            if (p == 0) memset(ptr, 0x00, chunk_size);
            else if (p == 1) memset(ptr, 0xFF, chunk_size);
            else {
                /* Random pass using splitmix64 for speed, seeded securely */
                uint64_t state = secure_seed ^ (uint64_t)i ^ (uintptr_t)ptr;
                uint64_t *ptr64 = (uint64_t *)ptr;
                for (size_t j = 0; j < chunk_size / 8; j++) {
                    uint64_t z = (state += 0x9e3779b97f4a7c15);
                    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
                    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
                    ptr64[j] = z ^ (z >> 31);
                }
            }

            if (i % 4 == 0) {
                printf("\r[+] Progress: %.1f%%  ", (double)(i + 1) * 100.0 / block_count);
                fflush(stdout);
                if (check_for_stop_interrupt()) break;
            }
        }
        printf("\n");
        if (check_for_stop_interrupt()) break;
    }
    
    restore_terminal();
    
    if (fill_keep_running) {
        time_t elapsed = time(NULL) - start_time;
        printf("\n[+] RAM sanitization complete: %.2f GB processed in %lu seconds\n", 
               allocated / (1024.0 * 1024.0 * 1024.0), (unsigned long)elapsed);
               
        /* Clear any leftover input in STDIN without blocking */
        struct pollfd pfd = {STDIN_FILENO, POLLIN, 0};
        while (poll(&pfd, 1, 0) > 0) {
            int ch = getchar();
            if (ch == '\n' || ch == EOF) break;
        }
        
        printf("[i] Press Enter to release memory and exit...\n");
        fflush(stdout);
        getchar();
    } else {
        printf("\n[!] RAM fill stopped by user request\n");
        fflush(stdout);
    }
    
    /* Clean up automatically */
    release_ram();
}

/* Release allocated RAM */
void release_ram(void) {
    if (allocated_blocks && block_count > 0) {
        printf("\n[*] Releasing allocated RAM...\n");
        size_t chunk_size = CHUNK_SIZE_MB * 1024 * 1024ULL;
        
        for (size_t i = 0; i < block_count; i++) {
            if (allocated_blocks[i]) {
                /* Clear memory in smaller chunks */
                unsigned char *ptr = (unsigned char *)allocated_blocks[i];
                const size_t clear_chunk = 1024 * 1024;  /* 1MB clear chunks */
                
                for (size_t offset = 0; offset < chunk_size; offset += clear_chunk) {
                    size_t current_clear = (chunk_size - offset > clear_chunk) ? clear_chunk : (chunk_size - offset);
                    secure_memzero(ptr + offset, current_clear);
                }
                
                if (g_mlock_supported) munlock(allocated_blocks[i], chunk_size);
                free(allocated_blocks[i]);
                allocated_blocks[i] = NULL;
                
                /* Show progress for large releases */
                if (block_count > 20 && i % (block_count / 10) == 0) {
                    printf("\r[-] Released %zu/%zu blocks", i + 1, block_count);
                    fflush(stdout);
                }
            }
        }
        
        free(allocated_blocks);
        allocated_blocks = NULL;
        block_count = 0;
        block_capacity = 0;
        printf("\n[+] RAM released and cleared successfully\n");
    }
}

int main(int argc, char *argv[]) {
    unsigned long safety_mb = DEFAULT_SAFETY_MB;
    
    /* Parse command line arguments */
    if (argc > 1) {
        char *endptr;
        long val = strtol(argv[1], &endptr, 10);
        if (*endptr == '\0' && val >= 100 && val <= 4000) {
            safety_mb = (unsigned long)val;
        } else {
            printf("Usage: %s [safety_margin_mb]\n", argv[0]);
            printf("Safety margin: 100-4000 MB (default: %u)\n", DEFAULT_SAFETY_MB);
            return 1;
        }
    }
    
    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    startup_compliance_check();
    
    printf("Virtual Wipe - RAM Fill Module\n");
    printf("Safety Margin: %lu MB\n", safety_mb);
    printf("This will allocate memory to fill available RAM.\n");
    printf("\n[i] IMPORTANT: Press 's' then Enter at ANY TIME to stop safely\n");
    printf("Press Enter to begin or Ctrl+C to cancel...\n");
    fflush(stdout);
    
    if (getchar() != '\n') {
        return 0;
    }
    
    fill_ram(safety_mb);
    
    return 0;
}
