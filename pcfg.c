/*
 * pcfg.c - Probabilistic Context-Free Grammar password generator
 *
 * C reimplementation of pcfg-go (cyclone-github/pcfg-go)
 *
 * Usage:
 *   pcfg -t <wordlist> <rules_dir>     Train on passwords
 *   pcfg -g <rules_dir>                Generate guesses
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <inttypes.h>

#include "pcfg.h"
#include "yarn.h"

#define VERSION "1.03"

/* ---- Memory usage reporting ---- */
#ifdef MACOSX
#include <mach/mach.h>
static int64_t get_mem_usage(void) {
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
                  (task_info_t)&info, &count) == KERN_SUCCESS)
        return (int64_t)info.resident_size;
    return 0;
}
#elif defined(__linux__)
static int64_t get_mem_usage(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    int64_t rss = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            rss = atoll(line + 6) * 1024;  /* kB → bytes */
            break;
        }
    }
    fclose(f);
    return rss;
}
#else
static int64_t get_mem_usage(void) { return 0; }
#endif

void print_mem(const char *label) {
    int64_t mem = get_mem_usage();
    if (mem > 0) {
        if (mem >= 1024*1024*1024)
            fprintf(stderr, "pcfg: %s: %.1f GB RSS\n", label, mem / (1024.0*1024*1024));
        else
            fprintf(stderr, "pcfg: %s: %.1f MB RSS\n", label, mem / (1024.0*1024));
    }
}

/* ---- Thread workspace ---- */
WorkSpace *ws_alloc(void) {
    WorkSpace *ws = calloc(1, sizeof(WorkSpace));
    ws->tag = malloc(PCFG_MAXLINE);
    ws->lower = malloc(PCFG_MAXLINE);
    ws->val = malloc(PCFG_MAXLINE);
    ws->base_str = malloc(PCFG_MAXLINE);
    ws->mask = malloc(PCFG_MAXLINE);
    ws->lowered = malloc(PCFG_MAXLINE);
    ws->decoded = malloc(PCFG_MAXLINE);
    ws->sects = malloc(PCFG_MAXSECTIONS * sizeof(Section));
    return ws;
}

void ws_free(WorkSpace *ws) {
    if (!ws) return;
    free(ws->tag); free(ws->lower); free(ws->val);
    free(ws->base_str); free(ws->mask); free(ws->lowered);
    free(ws->decoded); free(ws->sects);
    free(ws);
}

/* Globals */
volatile int Interrupted = 0;

static void sigint_handler(int sig) {
    (void)sig;
    Interrupted = 1;
}

/* ---- get_nprocs ---- */
#ifdef _SC_NPROCESSORS_ONLN
#ifdef MACOSX
#include <sys/sysctl.h>
int get_nprocs(void) {
    int n;
    size_t len = sizeof(n);
    int mib[2] = { CTL_HW, HW_NCPU };
    if (sysctl(mib, 2, &n, &len, NULL, 0))
        return 1;
    return n;
}
#else
int get_nprocs(void) {
    int n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? n : 1;
}
#endif
#endif

#ifdef _WIN32
#include <windows.h>
int get_nprocs(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}
#endif

/* ---- findeol (from mdxfind.c) ---- */
#ifdef INTEL
#include <emmintrin.h>
#include <tmmintrin.h>  /* SSSE3: _mm_shuffle_epi8 */
inline char *findeol(char *s, int64_t l) {
    unsigned int align, res, f;
    __m128i cur, seek;

    if (l < 16) {
        while (l-- > 0) {
            if (*s == '\n') return s;
            s++;
        }
        return NULL;
    }
    seek = _mm_set1_epi8('\n');
    align = ((unsigned long long)s) & 0xf;
    s = (char *)(((unsigned long long)s) & 0xfffffffffffffff0L);
    cur = _mm_load_si128((__m128i const *)s);
    res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur)) >> align;

    f = ffs(res);
    res <<= align;
    if (f && (f <= l))
        return s + ffs(res) - 1;
    s += 16;
    l -= (16 - align);

    while (l >= 16) {
        cur = _mm_load_si128((__m128i const *)s);
        res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur));
        f = ffs(res);
        if (f) return s + f - 1;
        s += 16;
        l -= 16;
    }
    if (l > 0) {
        cur = _mm_load_si128((__m128i const *)s);
        res = _mm_movemask_epi8(_mm_cmpeq_epi8(seek, cur));
        f = ffs(res);
        if (f && (f <= l))
            return s + f - 1;
    }
    return NULL;
}
#endif

/* ---- Arena allocator ---- */
void arena_init(Arena *a, size_t block_size) {
    a->head = NULL;
    a->block_size = block_size ? block_size : (1024 * 1024);
}

static ArenaBlock *arena_new_block(Arena *a, size_t min_size) {
    size_t sz = a->block_size;
    if (min_size > sz) sz = min_size;
    ArenaBlock *b = malloc(sizeof(ArenaBlock));
    if (!b) { fprintf(stderr, "pcfg: arena OOM\n"); exit(1); }
    b->base = malloc(sz);
    if (!b->base) { fprintf(stderr, "pcfg: arena OOM\n"); exit(1); }
    b->size = sz;
    b->used = 0;
    b->next = a->head;
    a->head = b;
    return b;
}

char *arena_alloc(Arena *a, size_t nbytes) {
    /* Align to 8 bytes */
    nbytes = (nbytes + 7) & ~(size_t)7;
    ArenaBlock *b = a->head;
    if (!b || b->used + nbytes > b->size)
        b = arena_new_block(a, nbytes);
    char *p = b->base + b->used;
    b->used += nbytes;
    return p;
}

char *arena_strdup(Arena *a, const char *s) {
    size_t len = strlen(s) + 1;
    char *p = arena_alloc(a, len);
    memcpy(p, s, len);
    return p;
}

char *arena_strndup(Arena *a, const char *s, size_t n) {
    char *p = arena_alloc(a, n + 1);
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

void arena_free(Arena *a) {
    ArenaBlock *b = a->head;
    while (b) {
        ArenaBlock *next = b->next;
        free(b->base);
        free(b);
        b = next;
    }
    a->head = NULL;
}

/* ---- $HEX[] decode (from mdxfind get32) ----
 * Uses trhex[256] lookup table — no branches in hot loop.
 * Values 0-15 = valid hex nibble, 16 = invalid, 17 = terminator (\0, \n, \r).
 * SSSE3 vectorized path processes 8 output bytes per iteration on Intel.
 */
static unsigned char trhex[] = {
    17, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 16, 16, 17, 16, 16, /* 00-0f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 10-1f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 20-2f */
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 16, 16, 16, 16, 16,           /* 30-3f */
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 40-4f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 50-5f */
    16, 10, 11, 12, 13, 14, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 60-6f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 70-7f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 80-8f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* 90-9f */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* a0-af */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* b0-bf */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* c0-cf */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* d0-df */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, /* e0-ef */
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16};/* f0-ff */

int decode_hex(const char *hex, char *out, int hexlen) {
    unsigned char c1, c2, *line = (unsigned char *)hex;
    unsigned char *dest = (unsigned char *)out;
    int cnt = 0;

#ifdef INTEL
    /* SSSE3: pshufb LUT nibble conversion + two-LUT Mula validation */
    const __m128i sub_lut = _mm_setr_epi8(
        0, 0, 0, 0x30, 0x37, 0, 0x57, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    const __m128i hi_valid = _mm_setr_epi8(
        0, 0, 0, 1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    const __m128i lo_valid = _mm_setr_epi8(
        1, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 1, 1, 1, 0, 0, 0, 0, 0, 0);
    const __m128i lomask = _mm_set1_epi8(0x0F);
    const __m128i pack_hi = _mm_set1_epi16(0x00F0);
    const __m128i pack_lo = _mm_set1_epi16(0x0F00);
    const __m128i compact = _mm_setr_epi8(
        0, 2, 4, 6, 8, 10, 12, 14, -1,-1,-1,-1,-1,-1,-1,-1);

    while (cnt + 8 <= hexlen / 2) {
        __m128i input = _mm_loadu_si128((const __m128i *)line);

        __m128i hi = _mm_and_si128(_mm_srli_epi16(input, 4), lomask);
        __m128i lo = _mm_and_si128(input, lomask);

        __m128i nibbles = _mm_sub_epi8(input, _mm_shuffle_epi8(sub_lut, hi));

        __m128i vcheck = _mm_and_si128(
            _mm_shuffle_epi8(hi_valid, hi),
            _mm_shuffle_epi8(lo_valid, lo));
        int inv_mask = _mm_movemask_epi8(
            _mm_cmpeq_epi8(vcheck, _mm_setzero_si128()));

        __m128i packed = _mm_or_si128(
            _mm_and_si128(_mm_slli_epi16(nibbles, 4), pack_hi),
            _mm_srli_epi16(_mm_and_si128(nibbles, pack_lo), 8));
        __m128i result = _mm_shuffle_epi8(packed, compact);

        if (inv_mask == 0) {
            _mm_storel_epi64((__m128i *)dest, result);
            cnt += 8; dest += 8; line += 16;
        } else {
            int valid_bytes = __builtin_ctz(inv_mask) / 2;
            uint64_t r;
            _mm_storel_epi64((__m128i *)&r, result);
            memcpy(dest, &r, valid_bytes);
            cnt += valid_bytes;
            dest += valid_bytes;
            line += valid_bytes * 2;
            break;
        }
    }
#endif /* INTEL */

    /* Scalar tail (or entire decode on non-Intel) */
    while (1) {
        c1 = trhex[line[0]];
        c2 = trhex[line[1]];
        if (c1 > 15 || c2 > 15)
            break;
        *dest++ = (c1 << 4) + c2;
        cnt++;
        line += 2;
    }

    out[cnt] = '\0';
    return cnt;
}

/* ---- Probability formatting ----
 * Store count and total as integers in TSV. Compute probability at load time.
 * Format: value\tcount/total  (e.g., "password\t1234/5678")
 * This avoids all float-to-string conversion during save.
 *
 * For compatibility with pcfg-go, format_prob() can also emit float format.
 * Use format_prob_ratio() for fast integer output, format_prob() for float.
 */

/* Fast: write "count/total" — inline integer-to-ASCII, no snprintf */
static inline int i64toa(int64_t v, char *buf) {
    char tmp[24];
    int i = 0;
    if (v == 0) { buf[0] = '0'; return 1; }
    if (v < 0) { buf[0] = '-'; buf++; v = -v; }
    while (v > 0) { tmp[i++] = '0' + (v % 10); v /= 10; }
    int len = i;
    while (i > 0) *buf++ = tmp[--i];
    return len;
}

void format_prob_ratio(int64_t count, int64_t total, char *buf, int buflen) {
    (void)buflen;
    int pos = i64toa(count, buf);
    buf[pos++] = '/';
    pos += i64toa(total, buf + pos);
    buf[pos] = '\0';
}

/* Compatible: write float probability (for pcfg-go interop) */
#ifdef __APPLE__
#include <xlocale.h>
static locale_t c_locale_val;
static int c_locale_init;
static locale_t get_c_locale(void) {
    if (!c_locale_init) {
        c_locale_val = newlocale(LC_ALL_MASK, "C", NULL);
        c_locale_init = 1;
    }
    return c_locale_val;
}
#endif

void format_prob(double prob, char *buf, int buflen) {
    if (prob == 0.0) { buf[0] = '0'; buf[1] = '\0'; return; }
    if (prob == 1.0) { buf[0] = '1'; buf[1] = '\0'; return; }

    int n;
#ifdef __APPLE__
    n = snprintf_l(buf, buflen, get_c_locale(), "%.17g", prob);
#else
    n = snprintf(buf, buflen, "%.17g", prob);
#endif
    if (n <= 0 || n >= buflen) return;

    /* Trim trailing zeros after decimal point (not in exponent) */
    char *e = memchr(buf, 'e', n);
    if (!e) e = memchr(buf, 'E', n);
    char *dot = memchr(buf, '.', n);
    if (dot) {
        char *end = e ? e : buf + n;
        char *p = end - 1;
        while (p > dot && *p == '0') p--;
        if (p == dot) p--;
        p++;
        if (e) {
            memmove(p, e, strlen(e) + 1);
        } else {
            *p = '\0';
        }
    }
}

/* ---- mkdir -p ---- */
static int mkdirp(const char *path, mode_t mode) {
    char tmp[PCFG_MAXPATH];
    char *p;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
#ifdef _WIN32
            mkdir(tmp);
#else
            mkdir(tmp, mode);
#endif
            *p = '/';
        }
    }
#ifdef _WIN32
    return mkdir(tmp);
#else
    return mkdir(tmp, mode);
#endif
}

/* ---- Usage ---- */
static void usage(const char *prog) {
    fprintf(stderr,
        "pcfg v%s - Probabilistic Context-Free Grammar password generator\n"
        "\n"
        "Training:\n"
        "  %s -t <wordlist> -g <grammar_dir> [options]\n"
        "    -g <dir>    Grammar directory (created by training, read by generation)\n"
        "    -w          Weighted input: lines are count:password format\n"
        "    -f <int>    Admission filter: min occurrence count (default 0=off)\n"
        "    -F          Filter junk lines (base64, hex hashes, JSON)\n"
        "    -S          Save sensitive data (emails, full URLs)\n"
        "    -c <float>  PCFG vs OMEN coverage 0.0-1.0 (default 0.6)\n"
        "    -n <int>    OMEN n-gram size 2-5 (default 4)\n"
        "    -a <int>    Alphabet size for Markov (default 100)\n"
        "    -C <str>    Comments for config\n"
        "    -T <int>    Max threads (default: auto)\n"
        "\n"
        "Merge:\n"
        "  %s -M <grammar1> -M <grammar2> -g <output_dir>\n"
        "\n"
        "AHF (synthetic generation):\n"
        "  %s -A -g <grammar_dir> [-n count]\n"
        "\n"
        "Info:\n"
        "  %s -i -g <grammar_dir>\n"
        "\n"
        "Generation:\n"
        "  %s -G -g <grammar_dir> [options]\n"
        "    -g <dir>    Grammar directory (previously created by -t training)\n"
        "    -n <int>    Max number of guesses (0 = unlimited)\n"
        "    -b          Skip OMEN/Markov guesses\n"
        "    -a          No case mangling\n"
        "    -d          Debug output instead of guesses\n"
        "    -T <int>    Max threads (default: auto)\n"
        "\n", VERSION, prog, prog, prog, prog, prog);
}

/* ---- Main ---- */
int main(int argc, char **argv) {
    char *infile = NULL;
    char *grammardir = NULL;
    int opt;

    /* Training defaults */
    TrainCtx tctx;
    memset(&tctx, 0, sizeof(tctx));
    tctx.coverage = 0.6;
    tctx.ngram_size = 4;
    tctx.alphabet_size = 100;

    /* Generation defaults */
    GenCtx gctx;
    memset(&gctx, 0, sizeof(gctx));
    gctx.nthreads = get_nprocs();
    int max_threads = 0;

    int mode_gen = 0;
    int mode_info = 0;
    int mode_ahf = 0;
    char *merge_dirs[2] = {NULL, NULL};
    int n_merge = 0;

    while ((opt = getopt(argc, argv, "t:g:r:GiASwf:Fc:n:a:C:M:bdT:hV")) != -1) {
        switch (opt) {
        case 't':
            infile = optarg;
            break;
        case 'G':
            mode_gen = 1;
            break;
        case 'i':
            mode_info = 1;
            break;
        case 'A':
            mode_ahf = 1;
            break;
        case 'g':
        case 'r':
            grammardir = optarg;
            break;
        case 'S':
            tctx.save_sensitive = 1;
            break;
        case 'w':
            tctx.weighted = 1;
            break;
        case 'f':
            tctx.admit_threshold = atoi(optarg);
            break;
        case 'F':
            tctx.filter_junk = 1;
            break;
        case 'M':
            if (n_merge < 2) merge_dirs[n_merge++] = optarg;
            break;
        case 'p':
            tctx.weighted = 1;  /* -p is legacy alias for -w */
            break;
        case 'c':
            tctx.coverage = atof(optarg);
            if (tctx.coverage < 0.0 || tctx.coverage > 1.0) {
                fprintf(stderr, "pcfg: coverage must be 0.0-1.0\n");
                return 1;
            }
            break;
        case 'n':
            /* Overloaded: ngram size (training) or max guesses (generation).
             * Resolved after parsing: if -t present, it's ngram; else guesses. */
            tctx.ngram_size = atoi(optarg);
            gctx.guess_limit = atoll(optarg);
            break;
        case 'a':
            /* Overloaded: alphabet size (training) or skip case (generation) */
            gctx.skip_case = 1;
            tctx.alphabet_size = atoi(optarg);
            break;
        case 'C':
            tctx.comments = optarg;
            break;
        case 'm':
            /* multiword pre-training file - TODO */
            break;
        case 'b':
            gctx.skip_brute = 1;
            break;
        case 'd':
            gctx.debug = 1;
            break;
        case 'T':
            max_threads = atoi(optarg);
            if (max_threads < 1) max_threads = 1;
            gctx.nthreads = max_threads;
            break;
        case 'V':
            printf("pcfg v%s\n", VERSION);
            return 0;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    /* Info mode: -i -g <grammar_dir> */
    if (mode_info && grammardir) {
        /* Load grammar and print stats */
        GenCtx ictx;
        memset(&ictx, 0, sizeof(ictx));
        if (pcfg_load(grammardir, &ictx) < 0) return 1;

        printf("Grammar: %s\n", grammardir);
        printf("Base structures: %d\n", ictx.nbases);

        /* Count entries per type by scanning directories */
        const char *dirs[] = {"Alpha","Digits","Other","Keyboard",
                              "Capitalization","Years","Context",
                              "Emails","Websites",NULL};
        int64_t total_entries = 0;
        for (int d = 0; dirs[d]; d++) {
            char path[PCFG_MAXPATH];
            snprintf(path, sizeof(path), "%s/%s", grammardir, dirs[d]);
            DIR *dp = opendir(path);
            if (!dp) continue;
            int64_t dir_entries = 0;
            struct dirent *ent;
            while ((ent = readdir(dp)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char fpath[PCFG_MAXPATH];
                snprintf(fpath, sizeof(fpath), "%s/%s", path, ent->d_name);
                FILE *fp = fopen(fpath, "r");
                if (!fp) continue;
                int64_t lines = 0;
                char buf[4096];
                while (fgets(buf, sizeof(buf), fp)) lines++;
                fclose(fp);
                dir_entries += lines;
            }
            closedir(dp);
            if (dir_entries > 0)
                printf("  %-16s %'" PRId64 " entries\n", dirs[d], dir_entries);
            total_entries += dir_entries;
        }
        printf("Total entries: %'" PRId64 "\n", total_entries);

        /* Top 20 base structures */
        printf("\nTop 20 base structures:\n");
        int top = ictx.nbases < 20 ? ictx.nbases : 20;
        for (int i = 0; i < top; i++) {
            printf("  %6.2f%%  ", ictx.bases[i].prob * 100.0);
            for (int j = 0; j < ictx.bases[i].nreplace; j++)
                printf("%s", ictx.bases[i].replacements[j]);
            printf("\n");
        }

        /* Password length distribution from base structures */
        printf("\nEstimated password length distribution (from top structures):\n");
        int len_hist[64];
        memset(len_hist, 0, sizeof(len_hist));
        int counted = ictx.nbases < 1000 ? ictx.nbases : 1000;
        for (int i = 0; i < counted; i++) {
            int pwlen = 0;
            for (int j = 0; j < ictx.bases[i].nreplace; j++) {
                char *r = ictx.bases[i].replacements[j];
                if (r[0] == 'M') continue;
                int n = atoi(r + 1);
                if (r[0] == 'C') continue;  /* case mask doesn't add length */
                pwlen += n;
            }
            if (pwlen > 0 && pwlen < 64) len_hist[pwlen]++;
        }
        for (int i = 1; i < 32; i++) {
            if (len_hist[i] > 0)
                printf("  len %2d: %d structures\n", i, len_hist[i]);
        }

        return 0;
    }

    /* Merge mode: -M <dir1> -M <dir2> -g <output> */
    if (n_merge == 2 && grammardir) {
        mkdirp(grammardir, 0755);
        return pcfg_merge(merge_dirs[0], merge_dirs[1], grammardir);
    }
    if (n_merge > 0 && n_merge < 2) {
        fprintf(stderr, "pcfg: -M requires exactly two grammar directories\n");
        return 1;
    }

    if (!grammardir) {
        fprintf(stderr, "pcfg: -g <grammar_dir> is required\n");
        usage(argv[0]);
        return 1;
    }

    /* Determine mode: -t = training, -G = generation, -A = AHF */
    int mode_train = (infile != NULL);
    if (!mode_train && !mode_gen && !mode_ahf) {
        fprintf(stderr, "pcfg: specify -t (train), -G (generate), or -A (AHF)\n");
        return 1;
    }
    if (mode_train && mode_gen) {
        fprintf(stderr, "pcfg: cannot use -t and -G together\n");
        return 1;
    }

    if (max_threads > 0)
        tctx.max_threads = max_threads;

    /* SIGINT: use default handler (terminate). Don't catch it. */

    /* AHF mode: -A -g <grammar> [-n count] */
    if (mode_ahf && grammardir) {
        int64_t ahf_count = gctx.guess_limit > 0 ? gctx.guess_limit : 1000000;
        return pcfg_ahf_generate(grammardir, &gctx, ahf_count);
    }

    if (mode_train) {
        tctx.filename = infile;

        /* Create output directory */
        mkdirp(grammardir, 0755);

        fprintf(stderr, "pcfg: training on \"%s\" → \"%s\"\n", infile, grammardir);
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        int rc = pcfg_train(infile, grammardir, &tctx);

        clock_gettime(CLOCK_MONOTONIC, &t1);
        double elapsed = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
        fprintf(stderr, "pcfg: training complete. %" PRId64 " passwords in %.2fs\n",
                tctx.total_passwords, elapsed);
        print_mem("final");
        return rc;
    }

    /* Generation mode */
    fprintf(stderr, "pcfg: generating from \"%s\"\n", grammardir);
    return pcfg_generate(grammardir, &gctx);
}
