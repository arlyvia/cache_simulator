#include <getopt.h>  // getopt, optarg
#include <stdlib.h>  // exit, atoi, malloc, free
#include <stdio.h>   // printf, fprintf, stderr, fopen, fclose, FILE
#include <limits.h>  // ULONG_MAX
#include <string.h>  // strcmp, strerror
#include <errno.h>   // errno
#include <math.h>
#include <float.h>
#include <fenv.h>

/* fast base-2 integer logarithm */
#define INT_LOG2(x) (31 - __builtin_clz(x))
#define NOT_POWER2(x) (__builtin_clz(x) + __builtin_ctz(x) != 31)

#define pow(two, shift) (1 << (shift))

/* tag_bits = ADDRESS_LENGTH - set_bits - block_bits */
#define ADDRESS_LENGTH 64

/**
 * Print program usage (no need to modify).
 */
static void print_usage() {
    printf("Usage: csim [-hv] -S <num> -K <num> -B <num> -p <policy> -t <file>\n");
    printf("Options:\n");
    printf("  -h           Print this help message.\n");
    printf("  -v           Optional verbose flag.\n");
    printf("  -S <num>     Number of sets.           (must be > 0)\n");
    printf("  -K <num>     Number of lines per set.  (must be > 0)\n");
    printf("  -B <num>     Number of bytes per line. (must be > 0)\n");
    printf("  -p <policy>  Eviction policy. (one of 'FIFO', 'LRU')\n");
    printf("  -t <file>    Trace file.\n\n");
    printf("Examples:\n");
    printf("$ ./csim    -S 16  -K 1 -B 16 -p LRU -t traces/yi2.trace\n");
    printf("$ ./csim -v -S 256 -K 2 -B 16 -p LRU -t traces/yi2.trace\n");
}

/* Parameters set by command-line args (no need to modify) */
int verbose = 0;   // print trace if 1
int S = 0;         // number of sets
int K = 0;         // lines per set
int B = 0;         // bytes per line

typedef enum { FIFO = 1, LRU = 2 } Policy;
Policy policy;     // 0 (undefined) by default

FILE *trace_fp = NULL;

/**
 * Parse input arguments and set verbose, S, K, B, policy, trace_fp.
 *
 * TODO: Finish implementation
 */
static void parse_arguments(int argc, char **argv) {
    
    char* trace_file;
    char c;
    while ((c = getopt(argc, argv, "S:K:B:p:t:vh")) != -1) {
        switch(c) {
            case 'S':
                S = atoi(optarg);
                if (NOT_POWER2(S)) {
                    fprintf(stderr, "ERROR: S must be a power of 2\n");
                    exit(1);
                }
                break;
            case 'K':
                // TODO
                K = atoi(optarg);
                break;
            case 'B':
                // TODO
                B = atoi(optarg);
                break;
            case 'p':
                if (!strcmp(optarg, "FIFO")) {
                    policy = FIFO;
                }
                // TODO: parse LRU, exit with error for unknown policy
                else if (!strcmp(optarg, "LRU")) {
                    policy = LRU;
                } else {
                    fprintf(stderr, "ERROR: unknown policy");
                    exit(1);
                }
                break;
            case 't':
                // TODO: open file trace_fp for reading
                trace_file = optarg;
                trace_fp = fopen(trace_file, "r");
                if (!trace_fp) {
                    fprintf(stderr, "ERROR: %s: %s\n", optarg, strerror(errno));
                    exit(1);
                }
                break;
            case 'v':
                // TODO
                verbose = 1;
                break;
            case 'h':
                // TODO
                print_usage(argv);
                exit(0);
            default:
                print_usage();
                exit(1);
        }
    }

    /* Make sure that all required command line args were specified and valid */
    if (S <= 0 || K <= 0 || B <= 0 || policy == 0 || !trace_fp) {
        printf("ERROR: Negative or missing command line arguments\n");
        print_usage();
        if (trace_fp) {
            fclose(trace_fp);
        }
        exit(1);
    }

    /* Other setup if needed */

}

/**
 * Cache data structures
 * TODO: Define your own!
 */

//mem addy
typedef unsigned long long int mem_addr_t;

//struct for cache
typedef struct cache_line {
    char valid;
    mem_addr_t tag;
    unsigned long long int lru;
} cache_line_t;

typedef cache_line_t* cache_set_t;

typedef cache_set_t* cache_t;

//simulated cache
cache_t cache;

mem_addr_t set_index_mask;

unsigned long long int lru_counter = 1;


/**
 * Allocate cache data structures.
 *
 * This function dynamically allocates (with malloc) data structures for each of
 * the `S` sets and `K` lines per set.
 *
 * TODO: Implement
 */
static void allocate_cache() {

    cache = (cache_set_t*)malloc(sizeof(cache_set_t) * S);
    for (int i = 0; i < S; i++) {
        cache[i] = (cache_line_t*)malloc(sizeof(cache_line_t) * K);
        for (int j = 0; j < K; j++) {
            cache[i][j].valid = 0;
            cache[i][j].tag = 0;
            cache[i][j].lru = 0;
        }
    }
  
    set_index_mask = (mem_addr_t)(S - 1);
}

/**
 * Deallocate cache data structures.
 *
 * This function deallocates (with free) the cache data structures of each
 * set and line.
 *
 * TODO: Implement
 */
static void free_cache() {

    for (int i = 0; i < S; i++) {
        free(cache[i]);
    }

    free(cache);

}

/* Counters used to record cache statistics */
int miss_count     = 0;
int hit_count      = 0;
int eviction_count = 0;

/**
 * Simulate a memory access.
 *
 * If the line is already in the cache, increase `hit_count`; otherwise,
 * increase `miss_count`; increase `eviction_count` if another line must be
 * evicted. This function also updates the metadata used to implement eviction
 * policies (LRU, FIFO).
 *
 * TODO: Implement
 */
static void access_data(unsigned long addr) {
    //printf("Access to %016lx\n", addr);

    if(policy == LRU || policy == FIFO){

        int s = INT_LOG2(S);
        int b = INT_LOG2(B);

        unsigned long long int eviction_lru = ULONG_MAX;
        unsigned int eviction_line = 0;
        mem_addr_t set_index = (addr >> b) & set_index_mask;
        mem_addr_t tag = addr >> (s + b);

        cache_set_t cache_set = cache[set_index];

        //hit
        for (int i = 0; i < K; i++) {
            if (cache_set[i].valid) {
                if (cache_set[i].tag == tag) {
                    cache_set[i].lru = lru_counter++;
                    hit_count++;
                    if (verbose) printf("hit ");
                    return;
                }
            }
        }

        //miss
        miss_count++;
        if (verbose) printf("miss ");

        for (int i = 0; i < K; i++) {
            if (eviction_lru > cache_set[i].lru) {
                eviction_line = i;
                eviction_lru = cache_set[i].lru;
            }
        }

        //evict
        if (cache_set[eviction_line].valid) {
            eviction_count++;
            if (verbose) printf("eviction ");
        }

        cache_set[eviction_line].lru = lru_counter++;
        cache_set[eviction_line].valid = 1;
        cache_set[eviction_line].tag = tag;
        
    } else if (policy == FIFO) {
        
    }
}

/**
 * Replay the input trace.
 *
 * This function:
 * - reads lines (e.g., using fgets) from the file handle `trace_fp` (a global variable)
 * - skips lines not starting with ` S`, ` L` or ` M`
 * - parses the memory address (unsigned long, in hex) and len (unsigned int, in decimal)
 *   from each input line
 * - calls `access_data(address)` for each access to a cache line
 *
 * TODO: Implement
 */
static void replay_trace() {

    char buf[1000];

    while(fgets(buf, 1000, trace_fp)){
		unsigned long long address = 0;
		unsigned length = 0;
		if (buf[1] == 'S' || buf[1] == 'L' || buf[1] == 'M'){
			sscanf(buf+2, "%llx,%u", &address , &length);

            if (verbose) putchar('\n');
			if (verbose) printf("%c %llx,%u ", buf[1], address, length);
			access_data(address);
		}
		if (buf[1] == 'M')
			access_data(address);
	}
}

/**
 * Print cache statistics (DO NOT MODIFY).
 */
static void print_summary(int hits, int misses, int evictions) {
    if (verbose) putchar('\n');
    printf("hits:%d misses:%d evictions:%d\n", hits, misses, evictions);
}

int main(int argc, char **argv) {
    parse_arguments(argc, argv);  // set global variables used by simulation
    allocate_cache();             // allocate data structures of cache
    replay_trace();               // simulate the trace and update counts
    free_cache();                 // deallocate data structures of cache
    fclose(trace_fp);             // close trace file
    print_summary(hit_count, miss_count, eviction_count);  // print counts
    return 0;
}