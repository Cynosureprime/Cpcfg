/*
 * pcfg_infer.c - Derivation graph inference for procedurally mangled wordlists
 *
 * Given a wordlist produced by an unknown mangling generator (basewords with
 * prefixes, suffixes, deletions, case/leet transforms, and word-to-word
 * combination, applied stepwise so that the output of one stage feeds the
 * next), reconstructs the generator's structure:
 *
 *   1. Every distinct word becomes a node; user-supplied basewords are roots.
 *   2. Single-step derivations between words are inferred by hash lookups
 *      (no pairwise comparison):
 *        AFFIX   B = pre + f(A) + post, f = case and/or leet variant of A
 *                (core of B, after stripping non-alpha ends, folds to A)
 *        DEL     B = A with one contiguous substring deleted
 *        CONCAT  B = X + Y, both X and Y observed words
 *   3. Edges form a derivation DAG; depth = longest path from a root, so the
 *      generator's pipeline shows up as graph strata.
 *   4. Report: rule inventory with frequencies, strata distribution, longest
 *      derivation chains, and suggested basewords (in-degree-0 alpha words
 *      the user did not supply).
 *   5. Generation (-n): sample derivation chains from the DAG and replay the
 *      edge transformations onto a *different* root, producing candidates
 *      the generator could have made but that are not in the input.
 *
 * Standalone tool: no grammar directory, no libJudy.  Build: make pcfg_infer
 *
 * Usage:
 *   pcfg_infer -i <wordlist> [-b <basewords>] [-n <count>] [-s <seed>]
 *              [-d <maxdepth>] [-u <show>] [-v]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>

#define MAX_WORD 256
#define MAX_EDGES (1 << 22)
#define HASH_SEED 1469598103u

/* ------------------------------------------------------------------ */
/* Word table                                                          */
/* ------------------------------------------------------------------ */

/* alpha for core-span purposes: ASCII letters plus UTF-8 bytes */
static int span_alpha(unsigned char c) { return c >= 0x80 || isalpha(c); }

typedef struct {
    char     *s;        /* full word */
    int       len;
    uint32_t  count;    /* occurrences in input (dups collapse) */
    int       core_off; /* first alpha byte after stripping non-alpha ends */
    int       core_len;
    int       is_base;  /* user-supplied baseword */
    int       depth;    /* longest derivation chain from any root */
    int       in_deg;
    int       edge_start; /* adjacency, filled after edge build */
    int       edge_count;
} Word;

static Word *words;
static int   nwords, capwords;
static uint32_t total_lines;

/* exact-word hash (open addressing) */
static int   *word_slots;      /* word index + 1, 0 = empty */
static int    word_mask;

/* folded-core hash: case+leet folded core -> best all-core word id + 1 */
static int   *fold_slots;
static int    fold_mask;

static uint32_t hash_bytes(const char *s, int len)
{
    uint32_t h = HASH_SEED;
    for (int i = 0; i < len; i++) { h ^= (unsigned char)s[i]; h *= 16777619u; }
    return h;
}

static void word_grow(void)
{
    int newmask = (word_mask << 1) | 1;
    int *ns = calloc(newmask + 1, sizeof(int));
    for (int i = 0; i <= word_mask; i++) {
        if (!word_slots[i]) continue;
        uint32_t h = hash_bytes(words[word_slots[i] - 1].s,
                                words[word_slots[i] - 1].len) & newmask;
        while (ns[h]) h = (h + 1) & newmask;
        ns[h] = word_slots[i];
    }
    free(word_slots);
    word_slots = ns;
    word_mask = newmask;
}

static int word_find(const char *s, int len)
{
    uint32_t h = hash_bytes(s, len) & word_mask;
    while (word_slots[h]) {
        Word *w = &words[word_slots[h] - 1];
        if (w->len == len && !memcmp(w->s, s, len)) return word_slots[h] - 1;
        h = (h + 1) & word_mask;
    }
    return -1;
}

/* insert or return existing; new words get core computed */
static int word_intern(const char *s, int len, int is_base)
{
    int id = word_find(s, len);
    if (id >= 0) {
        words[id].count++;
        if (is_base) words[id].is_base = 1;
        return id;
    }
    if (nwords == capwords) {
        capwords = capwords ? capwords * 2 : 1024;
        words = realloc(words, capwords * sizeof(Word));
    }
    if ((nwords + 1) * 3 / 2 > word_mask) word_grow();
    Word *w = &words[nwords];
    memset(w, 0, sizeof(*w));
    w->s = malloc(len + 1);
    memcpy(w->s, s, len);
    w->s[len] = 0;
    w->len = len;
    w->count = 1;
    w->is_base = is_base;
    w->depth = -1;
    /* core: span from first to last alpha/UTF-8 byte.  Trailing/leading
     * digits and symbols are affixes; interior bytes (incl. leet chars) stay,
     * so "t3st1" keeps core "t3st" and "test123" keeps core "test" */
    int lo = 0, hi = len;
    while (lo < hi && !span_alpha((unsigned char)s[lo])) lo++;
    while (hi > lo && !span_alpha((unsigned char)s[hi - 1])) hi--;
    w->core_off = lo;
    w->core_len = hi - lo;

    uint32_t h = hash_bytes(s, len) & word_mask;
    while (word_slots[h]) h = (h + 1) & word_mask;
    word_slots[h] = nwords + 1;
    return nwords++;
}

/* ------------------------------------------------------------------ */
/* Leet / case folding                                                 */
/* ------------------------------------------------------------------ */

static char leet_fold(unsigned char c);

static char leet_fold(unsigned char c)
{
    switch (c) {
    case '4': case '@': return 'a';
    case '3':           return 'e';
    case '1': case '!': return 'i';
    case '0':           return 'o';
    case '5': case '$': return 's';
    case '7':           return 't';
    case '8':           return 'b';
    case '9': case '6': return 'g';
    case '2':           return 'z';
    default:            return (char)tolower(c);
    }
}

/* fold src into dst (dst >= len+1); returns folded length */
static int fold_core(const char *s, int off, int len, char *dst)
{
    int n = 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[off + i];
        dst[n++] = (c >= 0x80) ? (char)c : leet_fold(c);
    }
    dst[n] = 0;
    return n;
}

/* find best all-core word whose folded core equals folded (off..off+len of s) */
static int fold_find(const char *s, int off, int len)
{
    char buf[MAX_WORD];
    int fl = fold_core(s, off, len, buf);
    uint32_t h = hash_bytes(buf, fl) & fold_mask;
    while (fold_slots[h]) {
        Word *w = &words[fold_slots[h] - 1];
        char wbuf[MAX_WORD];
        fold_core(w->s, w->core_off, w->core_len, wbuf);
        if (w->core_len == fl && !strcmp(wbuf, buf)) return fold_slots[h] - 1;
        h = (h + 1) & fold_mask;
    }
    return -1;
}

static void fold_add(int id)
{
    Word *w = &words[id];
    if (w->core_off != 0 || w->core_len != w->len) return; /* only pure cores */
    char buf[MAX_WORD];
    int fl = fold_core(w->s, 0, w->len, buf);
    uint32_t h = hash_bytes(buf, fl) & fold_mask;
    while (fold_slots[h]) {
        int cur = fold_slots[h] - 1;
        Word *cw = &words[cur];
        char cbuf[MAX_WORD];
        fold_core(cw->s, cw->core_off, cw->core_len, cbuf);
        int same_fold = cw->core_len == fl && !strcmp(cbuf, buf);
        if (same_fold) {
            /* prefer baseword, then higher count */
            int replace = (w->is_base && !cw->is_base) ||
                          (w->is_base == cw->is_base && w->count > cw->count);
            if (replace) fold_slots[h] = id + 1;
            return;
        }
        h = (h + 1) & fold_mask;
    }
    fold_slots[h] = id + 1;
}

/* ------------------------------------------------------------------ */
/* Edges                                                               */
/* ------------------------------------------------------------------ */

enum {
    E_AFFIX    = 1, /* pre/post strings, optional case mask / leet subs   */
    E_CASE     = 2, /* pure case change                                    */
    E_LEET     = 3, /* pure leet substitution                              */
    E_DEL      = 4, /* contiguous substring deletion                       */
    E_CONCAT   = 5, /* concatenation of two observed words                 */
};
static const char *edge_type_name(int t)
{
    switch (t) { case E_AFFIX: return "affix"; case E_CASE: return "case";
        case E_LEET: return "leet"; case E_DEL: return "deletion";
        default: return "concat"; }
}

typedef struct {
    int      from, to;
    uint8_t  type;
    char    *pre, *post;   /* interned affix strings ("" allowed)        */
    char    *mask;         /* case mask of target core: 'L' lower 'U' upper */
    int16_t  leet_pos[MAX_WORD / 4]; /* positions where leet replaced char  */
    char     leet_chr[MAX_WORD / 4];
    int      nleet;
    int16_t  del_off, del_len; /* relative to source word length          */
    int      partner;      /* CONCAT second word id                        */
    uint32_t cnt;          /* how many times this rule shape was seen      */
} Edge;

static Edge *edges;
static int   nedges;
static int  *edges_order; /* out-edges grouped by source node */

static char *str_pool(const char *s, int len)
{
    char *p = malloc(len + 1);
    memcpy(p, s, len);
    p[len] = 0;
    return p;
}

static void edge_add(int from, int to, int type, const char *pre, int prelen,
                     const char *post, int postlen)
{
    if (nedges >= MAX_EDGES) return;
    Edge *e = &edges[nedges++];
    memset(e, 0, sizeof(*e));
    e->from = from;
    e->to = to;
    e->type = (uint8_t)type;
    e->pre = prelen ? str_pool(pre, prelen) : str_pool("", 0);
    e->post = postlen ? str_pool(post, postlen) : str_pool("", 0);
    words[to].in_deg++;

    Word *src = &words[from], *dst = &words[to];
    /* case mask over the target core */
    int mlen = dst->core_len;
    if (mlen > 0 && mlen < MAX_WORD / 2) {
        e->mask = malloc(mlen + 1);
        for (int i = 0; i < mlen; i++) {
            unsigned char c = (unsigned char)dst->s[dst->core_off + i];
            e->mask[i] = (c >= 0x80 || isalpha(c)) && isupper(c) ? 'U' : 'L';
        }
        e->mask[mlen] = 0;
    }
    /* leet positions: target core char differs from folded source char */
    if (src->core_len == dst->core_len && dst->core_len < MAX_WORD / 4) {
        for (int i = 0; i < dst->core_len; i++) {
            char a = leet_fold((unsigned char)dst->s[dst->core_off + i]);
            char b = leet_fold((unsigned char)src->s[src->core_off + i]);
            (void)b;
            char orig = dst->s[dst->core_off + i];
            if ((unsigned char)orig < 0x80 && !isalpha((unsigned char)orig) &&
                a != orig) {
                e->leet_pos[e->nleet] = (int16_t)i;
                e->leet_chr[e->nleet] = orig;
                e->nleet++;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Inference                                                           */
/* ------------------------------------------------------------------ */

static int cnt_desc(const void *a, const void *b)
{
    uint32_t x = words[*(const int *)a].count, y = words[*(const int *)b].count;
    return y < x ? -1 : y > x;
}

static void infer_affix(void)
{
    char key[MAX_WORD];
    for (int b = 0; b < nwords; b++) {
        Word *B = &words[b];
        if (B->core_len <= 0) continue;
        int a = fold_find(B->s, B->core_off, B->core_len);
        if (a < 0 || a == b) continue;
        Word *A = &words[a];
        /* require the source to be an unaffixed core word */
        if (A->core_off != 0 || A->core_len != A->len) continue;
        int prelen = B->core_off, postlen = B->len - B->core_off - B->core_len;
        int type = E_AFFIX;
        if (!prelen && !postlen)
            type = B->core_len && memcmp(B->s, A->s, B->len)
                     ? (A->len == B->len &&
                        !strncasecmp(A->s, B->s, B->len) ? E_CASE : E_LEET)
                     : E_LEET;
        edge_add(a, b, type, B->s, prelen, B->s + B->core_off + B->core_len, postlen);
    }
    (void)key;
}

static void infer_deletion(void)
{
    /* for each word A, every single contiguous deletion whose result is an
     * observed word becomes edge A -> B */
    char buf[MAX_WORD];
    for (int a = 0; a < nwords; a++) {
        Word *A = &words[a];
        int len = A->len;
        if (len < 2 || len > 48) continue;
        int variants = 0;
        for (int i = 0; i < len && variants < 256; i++) {
            memcpy(buf, A->s, i);
            for (int l = 1; i + l <= len && variants < 256; l++, variants++) {
                if (nedges >= MAX_EDGES) return;
                memcpy(buf + i, A->s + i + l, len - i - l);
                int b = word_find(buf, len - l);
                if (b >= 0 && b != a) {
                    Edge *e = &edges[nedges++];
                    memset(e, 0, sizeof(*e));
                    e->from = a;
                    e->to = b;
                    e->type = E_DEL;
                    e->del_off = (int16_t)i;
                    e->del_len = (int16_t)l;
                    words[b].in_deg++;
                }
            }
        }
    }
}

static void infer_concat(void)
{
    for (int b = 0; b < nwords; b++) {
        Word *B = &words[b];
        int len = B->len;
        if (len < 4 || len > 96) continue;
        int best_x = -1, best_y = -1;
        uint32_t best_score = 0;
        for (int split = 2; split <= len - 2; split++) {
            int x = word_find(B->s, split);
            if (x < 0) continue;
            int y = word_find(B->s + split, len - split);
            if (y < 0) continue;
            uint32_t score = words[x].count < words[y].count
                               ? words[x].count : words[y].count;
            if (score > best_score) {
                best_score = score;
                best_x = x; best_y = y;
            }
        }
        if (best_x >= 0 && best_x != b && best_y != b && nedges < MAX_EDGES) {
            Edge *e = &edges[nedges++];
            memset(e, 0, sizeof(*e));
            e->from = best_x;
            e->to = b;
            e->type = E_CONCAT;
            e->partner = best_y;
            words[b].in_deg++;
        }
    }
}

/* strata via layered BFS from roots: depth = minimum number of derivation
 * steps from a baseword; immune to cycles in the inferred edge set */
static void compute_depths(void)
{
    for (int b = 0; b < nwords; b++)
        words[b].depth = words[b].is_base ? 0 : -1;
    for (int layer = 0; layer < 16; layer++) {
        int assigned = 0;
        for (int e = 0; e < nedges; e++) {
            if (words[edges[e].from].depth != layer) continue;
            int v = edges[e].to;
            if (words[v].depth < 0) { words[v].depth = layer + 1; assigned++; }
        }
        if (!assigned) break;
    }
}

static void build_adjacency(void)
{
    int *start = calloc(nwords + 1, sizeof(int));
    for (int e = 0; e < nedges; e++) start[edges[e].from + 1]++;
    for (int b = 0; b < nwords; b++) start[b + 1] += start[b];
    int *fill = malloc((nwords + 1) * sizeof(int));
    memcpy(fill, start, (nwords + 1) * sizeof(int));
    int *order = malloc(nedges * sizeof(int));
    for (int e = 0; e < nedges; e++) order[fill[edges[e].from]++] = e;
    for (int b = 0; b < nwords; b++) {
        words[b].edge_start = start[b];
        words[b].edge_count = start[b + 1] - start[b];
    }
    edges_order = order;
    free(start);
    free(fill);
}

/* ------------------------------------------------------------------ */
/* Report                                                              */
/* ------------------------------------------------------------------ */

typedef struct { char *s; uint32_t c; } StrFreq;

static int sf_desc(const void *a, const void *b)
{
    const StrFreq *x = a, *y = b;
    return y->c < x->c ? -1 : y->c > x->c;
}

static void top_strings(const char *label, StrFreq *arr, int n, int show)
{
    qsort(arr, n, sizeof(StrFreq), sf_desc);
    printf("%s (top %d of %d distinct)\n", label, show > n ? n : show, n);
    for (int i = 0; i < n && i < show; i++) {
        char disp[65];
        int j = 0;
        for (const char *p = arr[i].s; *p && j < 60; p++)
            disp[j++] = isprint((unsigned char)*p) ? *p : '?';
        disp[j] = 0;
        printf("  %-8u x '%s'\n", arr[i].c, disp);
    }
}

static void report(const char *infile, int verbose, int show_unexplained)
{
    printf("=== pcfg_infer: %s ===\n", infile);
    printf("lines read:        %u\n", total_lines);
    printf("distinct words:    %d\n", nwords);
    printf("edges inferred:    %d\n", nedges);
    int type_cnt[6] = {0};
    for (int e = 0; e < nedges; e++) type_cnt[edges[e].type]++;
    printf("  affix:           %d\n", type_cnt[E_AFFIX]);
    printf("  case:            %d\n", type_cnt[E_CASE]);
    printf("  leet:            %d\n", type_cnt[E_LEET]);
    printf("  deletion:        %d\n", type_cnt[E_DEL]);
    printf("  concat:          %d\n", type_cnt[E_CONCAT]);

    int nbase = 0, nsugg = 0, nunatt = 0, depth_hist[18] = {0};
    for (int b = 0; b < nwords; b++) {
        if (words[b].is_base) nbase++;
        if (words[b].depth >= 0 && words[b].depth <= 16) depth_hist[words[b].depth]++;
        else nunatt++;
        if (!words[b].is_base && words[b].in_deg == 0 && words[b].edge_count > 0)
            nsugg++;
    }
    printf("basewords given:   %d\n", nbase);
    printf("suggested bases:   %d (in-degree-0, derive others, not supplied)\n", nsugg);

    printf("\nderivation depth strata (generator pipeline stages):\n");
    printf("  depth 0 (roots):      %d\n", depth_hist[0]);
    for (int d = 1; d <= 16; d++)
        if (depth_hist[d]) printf("  depth %d:              %d\n", d, depth_hist[d]);
    if (nunatt) printf("  unattached:           %d\n", nunatt);

    /* affix distribution */
    int cap = nedges * 2 + 16;
    StrFreq *pre = malloc(cap * sizeof(StrFreq)), *post = malloc(cap * sizeof(StrFreq));
    int npre = 0, npost = 0;
    StrFreq *delshape = malloc(nedges * sizeof(StrFreq));
    int ndel = 0;
    for (int e = 0; e < nedges; e++) {
        Edge *ed = &edges[e];
        if (ed->type == E_AFFIX) {
            if (ed->pre && ed->pre[0]) {
                int f = -1;
                for (int i = 0; i < npre; i++) if (!strcmp(pre[i].s, ed->pre)) { f = i; break; }
                if (f < 0) { pre[npre].s = ed->pre; pre[npre].c = 0; f = npre++; }
                pre[f].c += words[ed->to].count;
            }
            if (ed->post && ed->post[0]) {
                int f = -1;
                for (int i = 0; i < npost; i++) if (!strcmp(post[i].s, ed->post)) { f = i; break; }
                if (f < 0) { post[npost].s = ed->post; post[npost].c = 0; f = npost++; }
                post[f].c += words[ed->to].count;
            }
        } else if (ed->type == E_DEL) {
            char shape[32];
            snprintf(shape, sizeof shape, "len %d @ pos %d", ed->del_len, ed->del_off);
            int f = -1;
            for (int i = 0; i < ndel; i++) if (!strcmp(delshape[i].s, shape)) { f = i; break; }
            if (f < 0) { delshape[ndel].s = str_pool(shape, (int)strlen(shape)); delshape[ndel].c = 0; f = ndel++; }
            delshape[f].c += words[ed->to].count;
        }
    }
    if (npre)  { printf("\n"); top_strings("prefixes", pre, npre, 20); }
    if (npost) { printf("\n"); top_strings("suffixes", post, npost, 20); }
    if (ndel)  { printf("\n"); top_strings("deletion shapes", delshape, ndel, 10); }

    /* longest chains */
    printf("\nlongest derivation chains:\n");
    int shown = 0;
    for (int d = 15; d >= 1 && shown < 5; d--) {
        for (int e = 0; e < nedges && shown < 5; e++) {
            if (words[edges[e].to].depth != d) continue;
            /* print the chain up from this edge */
            int chain[20], n = 0;
            chain[n++] = edges[e].to;
            int cur = edges[e].from;
            while (cur >= 0 && n < 20) {
                chain[n++] = cur;
                if (words[cur].depth <= 0) break;
                int nxt = -1;
                for (int e2 = 0; e2 < nedges; e2++)
                    if (edges[e2].to == cur && words[edges[e2].from].depth == words[cur].depth - 1) { nxt = edges[e2].from; break; }
                cur = nxt;
            }
            printf("  ");
            for (int i = n - 1; i >= 0; i--) printf("%s%s", words[chain[i]].s, i ? " -> " : "");
            printf("\n");
            shown++;
        }
    }

    if (show_unexplained > 0) {
        printf("\nunexplained words (no derivation, not basewords; top by count):\n");
        int *idx = malloc(nwords * sizeof(int)), n = 0;
        for (int b = 0; b < nwords; b++)
            if (!words[b].is_base && words[b].in_deg == 0) idx[n++] = b;
        qsort(idx, n, sizeof(int), cnt_desc);
        for (int i = 0; i < n && i < show_unexplained; i++)
            printf("  %u x %s\n", words[idx[i]].count, words[idx[i]].s);
        free(idx);
    }
    if (verbose) {
        printf("\nall edges:\n");
        for (int e = 0; e < nedges; e++) {
            Edge *ed = &edges[e];
            printf("  %s -> %s  [%s", words[ed->from].s, words[ed->to].s, edge_type_name(ed->type));
            if (ed->type == E_AFFIX) printf(" pre='%s' post='%s'", ed->pre, ed->post);
            if (ed->type == E_DEL) printf(" del %d@%d", ed->del_len, ed->del_off);
            if (ed->type == E_CONCAT) printf(" + %s", words[ed->partner].s);
            printf("]\n");
        }
    }
}

/* ------------------------------------------------------------------ */
/* Generation: replay sampled rule chains onto other roots             */
/* ------------------------------------------------------------------ */

static volatile int Interrupted;

static void sigint_handler(int sig)
{
    (void)sig;
    Interrupted = 1;
}

static uint64_t rng_state;
static uint32_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 16);
}

/* apply one edge's transformation to cur (in place, buf sized MAX_WORD*2) */
static int apply_edge(Edge *e, char *cur, int curlen)
{
    Word *A = &words[e->from];
    char tmp[MAX_WORD * 2];
    int n = 0;

    /* rebuild: pre + transform(cur core) + post, or deletion/concat */
    if (e->type == E_DEL) {
        if (curlen <= e->del_off + e->del_len || curlen - e->del_len < 2) return -1;
        memcpy(tmp, cur, e->del_off);
        memcpy(tmp + e->del_off, cur + e->del_off + e->del_len,
               curlen - e->del_off - e->del_len);
        n = curlen - e->del_len;
    } else if (e->type == E_CONCAT) {
        char *p = words[e->partner].s;
        int pl = words[e->partner].len;
        if (curlen + pl >= MAX_WORD) return -1;
        memcpy(tmp, cur, curlen);
        memcpy(tmp + curlen, p, pl);
        n = curlen + pl;
    } else {
        /* affix-family: strip cur's affixes conceptually, apply mask/leet to
         * the core only when it matches the source core length */
        int lo = 0, hi = curlen;
        while (lo < hi && !span_alpha((unsigned char)cur[lo])) lo++;
        while (hi > lo && !span_alpha((unsigned char)cur[hi - 1])) hi--;
        int prelen = (int)strlen(e->pre), postlen = (int)strlen(e->post);
        if (prelen + (hi - lo) + postlen >= MAX_WORD) return -1;
        memcpy(tmp, e->pre, prelen);
        n = prelen;
        for (int i = 0; i < hi - lo; i++) {
            char c = cur[lo + i];
            if ((unsigned char)c >= 0x80) { tmp[n++] = c; continue; }
            if (e->mask && i < A->core_len && e->mask[i] == 'U') c = (char)toupper((unsigned char)c);
            int leet_done = 0;
            for (int k = 0; k < e->nleet; k++)
                if (e->leet_pos[k] == i && tolower((unsigned char)c) == A->s[A->core_off + i])
                    { tmp[n++] = e->leet_chr[k]; leet_done = 1; break; }
            if (!leet_done) tmp[n++] = c;
        }
        memcpy(tmp + n, e->post, postlen);
        n += postlen;
    }
    memcpy(cur, tmp, n);
    return n;
}

static void generate(int count, int maxdepth, uint32_t seed)
{
    int endless = (count == 0);   /* -n 0: stream until interrupted */
    rng_state = seed ? seed : 0x9E3779B97F4A7C15ull;
    int *roots = malloc(nwords * sizeof(int)), nroots = 0;
    for (int b = 0; b < nwords; b++)
        if (words[b].is_base || words[b].in_deg == 0) roots[nroots++] = b;
    if (!nroots) { fprintf(stderr, "pcfg_infer: no roots to generate from\n"); free(roots); return; }

    /* no output dedup: constant memory; repeats are possible, filter
     * downstream (sort -u) if distinct candidates are required */
    int made = 0, tries = 0;
    while ((endless || made < count) && (endless || tries < count * 50)
           && !Interrupted) {
        tries++;
        int root = roots[rnd() % nroots];
        char cur[MAX_WORD * 2];
        int curlen = words[root].len;
        if (curlen >= MAX_WORD) continue;
        memcpy(cur, words[root].s, curlen);
        int steps = rnd() % maxdepth + 1;
        int node = root;
        for (int s = 0; s < steps; s++) {
            if (!words[node].edge_count) break;
            Edge *e = &edges[edges_order[words[node].edge_start + (rnd() % words[node].edge_count)]];
            /* replay the learned rule onto a different root for novelty */
            int r2 = roots[rnd() % nroots];
            char buf[MAX_WORD * 2];
            int bl = words[r2].len;
            memcpy(buf, words[r2].s, bl);
            int nl = apply_edge(e, buf, bl);
            if (nl < 0) { node = e->to; continue; }
            memcpy(cur, buf, nl);
            curlen = nl;
            node = e->to;
        }
        cur[curlen] = 0;
        if (word_find(cur, curlen) >= 0) continue; /* skip known words */
        printf("%s\n", cur);
        if (endless && fflush(stdout) == EOF) goto done; /* consumer closed pipe */
        made++;
    }
done:
    free(roots);
    fprintf(stderr, "pcfg_infer: generated %d candidates in %d attempts\n", made, tries);
}

/* ------------------------------------------------------------------ */
/* Driver                                                              */
/* ------------------------------------------------------------------ */

static void load_file(const char *path, int is_base)
{
    FILE *f = !strcmp(path, "-") ? stdin : fopen(path, "r");
    if (!f) { fprintf(stderr, "pcfg_infer: cannot open %s\n", path); exit(1); }
    char line[MAX_WORD];
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (!n) continue;
        total_lines++;
        int id = word_intern(line, (int)n, is_base);
        if ((nwords + 1) * 3 / 2 > fold_mask) {
            free(fold_slots);
            do { fold_mask = (fold_mask << 1) | 1; } while ((nwords + 1) * 3 / 2 > fold_mask);
            fold_slots = calloc(fold_mask + 1, sizeof(int));
            for (int b = 0; b < nwords; b++) fold_add(b);
        }
        fold_add(id);
    }
    if (f != stdin) fclose(f);
}

static void usage(void)
{
    fprintf(stderr,
        "usage: pcfg_infer -i <wordlist> [-b <basewords>] [options]\n"
        "  -i <file>  wordlist to analyse ('-' for stdin)\n"
        "  -b <file>  known basewords (roots)\n"
        "  -n <int>   generate N novel candidates from inferred rules\n"
        "             (use 0 to keep generating until interrupted; candidates\n"
        "              stream to stdout, so they can be piped straight into a\n"
        "              consumer like hashcat --stdin)\n"
        "  -s <int>   RNG seed for generation\n"
        "  -d <int>   max derivation depth for generation (default 4)\n"
        "  -u <int>   show top N unexplained words (candidate basewords)\n"
        "  -q         suppress the analysis report (candidates only; good for\n"
        "             piping, e.g. pcfg_infer ... -q -n 0 | hashcat --stdin)\n"
        "  -v         print every inferred edge\n");
}

int main(int argc, char **argv)
{
    const char *infile = NULL, *basefile = NULL;
    int gen_count = -1, show_unexplained = 0, verbose = 0, maxdepth = 4, quiet = 0;
    uint32_t seed = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) infile = argv[++i];
        else if (!strcmp(argv[i], "-b") && i + 1 < argc) basefile = argv[++i];
        else if (!strcmp(argv[i], "-n") && i + 1 < argc) gen_count = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-s") && i + 1 < argc) seed = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (!strcmp(argv[i], "-d") && i + 1 < argc) maxdepth = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-u") && i + 1 < argc) show_unexplained = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-v")) verbose = 1;
        else if (!strcmp(argv[i], "-q")) quiet = 1;
        else { usage(); return 1; }
    }
    if (!infile) { usage(); return 1; }

    word_mask = 1023;
    word_slots = calloc(word_mask + 1, sizeof(int));
    fold_mask = 1023;
    fold_slots = calloc(fold_mask + 1, sizeof(int));
    edges = malloc(MAX_EDGES * sizeof(Edge));

    if (basefile) load_file(basefile, 1);
    load_file(infile, 0);

    infer_affix();
    infer_deletion();
    infer_concat();
    compute_depths();
    build_adjacency();

    if (!quiet) report(infile, verbose, show_unexplained);
    if (gen_count >= 0) {
        if (!quiet) { printf("\n=== generated candidates ===\n"); fflush(stdout); }
        signal(SIGINT, sigint_handler);
        generate(gen_count, maxdepth, seed);
    }
    return 0;
}
