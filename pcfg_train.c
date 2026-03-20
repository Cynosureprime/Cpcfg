/*
 * pcfg_train.c - Single-pass parallel training with job-queue architecture
 *
 * Architecture:
 *   - cacheline() does double-buffered I/O with refcount locks
 *   - Main thread iterates each buffer: multiword trie, char freq, OMEN
 *   - Main thread dispatches PCFG parsing jobs to persistent workers
 *   - OMEN alphabet built after first buffer (25MB = plenty of data)
 *   - OMEN n-gram training runs on main thread for all subsequent lines
 *   - One pass through the file. No rewind.
 *   - After EOF: poison pill, join_all, single merge
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <errno.h>

#include "pcfg.h"
#include "yarn.h"

/* Inline ASCII tolower — avoids locale function call */
static inline unsigned char fast_lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* ---- Junk line detection ----
 * Returns 1 if line looks like base64, hex hash, JSON, or other non-password junk.
 */
static int is_junk_line(const char *pw, int pwlen) {
    if (pwlen < 4) return 0;

    /* JSON fragment: starts with { or [ */
    if (pw[0] == '{' || pw[0] == '[') return 1;

    /* XML/HTML tag */
    if (pw[0] == '<' && pwlen > 2 && ((pw[1] >= 'a' && pw[1] <= 'z') ||
        (pw[1] >= 'A' && pw[1] <= 'Z') || pw[1] == '/' || pw[1] == '!'))
        return 1;

    /* Pure hex string (32+ chars, all hex): likely a hash */
    if (pwlen >= 32) {
        int all_hex = 1;
        for (int i = 0; i < pwlen && all_hex; i++) {
            unsigned char c = (unsigned char)pw[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
                all_hex = 0;
        }
        if (all_hex) return 1;
    }

    /* Base64-only (40+ chars, only A-Za-z0-9+/=, ends with = or ==) */
    if (pwlen >= 40) {
        int all_b64 = 1;
        for (int i = 0; i < pwlen && all_b64; i++) {
            unsigned char c = (unsigned char)pw[i];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
                all_b64 = 0;
        }
        if (all_b64 && (pw[pwlen-1] == '=' || pw[pwlen-2] == '='))
            return 1;
    }

    return 0;
}

/* ---- Parse weighted input: "count:password" → returns count, advances *pw past count: ---- */
static int64_t parse_weight(char **pw, int *pwlen) {
    char *p = *pw;
    int len = *pwlen;

    /* Scan for digits followed by : */
    int i = 0;
    while (i < len && p[i] >= '0' && p[i] <= '9') i++;
    if (i == 0 || i >= len || p[i] != ':') return 1;  /* no weight found, default 1 */

    int64_t count = 0;
    for (int j = 0; j < i; j++)
        count = count * 10 + (p[j] - '0');
    if (count <= 0) count = 1;

    *pw = p + i + 1;
    *pwlen = len - i - 1;
    return count;
}

#define TRAIN_MAXLINE    PCFG_MAXLINE
#define TRAIN_CHUNK      (50*1024*1024)
#define TRAIN_HALFCHUNK  (TRAIN_CHUNK/2)
#define TRAIN_MAXLINES   (TRAIN_HALFCHUNK/8)
#define LINES_PER_JOB    131072
#define MAX_JOBS         256

/* ---- Job structure ---- */
#define JOB_TRAIN  1
#define JOB_DONE   99

typedef struct TrainJob {
    struct TrainJob *next;
    int              op;
    char            *readbuf;
    struct LineInfo *readindex;
    unsigned int     startline;
    unsigned int     numline;
} TrainJob;

/* Thread-local training context */
typedef struct {
    LenCounters cnt_alpha;
    LenCounters cnt_masks;
    LenCounters cnt_digits;
    LenCounters cnt_other;
    LenCounters cnt_keyboard;
    Counter cnt_years;
    Counter cnt_context;
    Counter cnt_base;
    Counter cnt_email_prov;
    Counter cnt_web_host;
    Counter cnt_web_pfx;
    int64_t total_passwords;
} ThreadCtx;

/* ---- Global state ---- */
static char *Readbuf;
static struct LineInfo *Readindex;
static lock *ReadBuf0, *ReadBuf1;
static int Cacheindex;
static char *CL_lastleft;
static int CL_lastcnt;

static TrainJob *JobPool;
static TrainJob *FreeHead, **FreeTail;
static TrainJob *WorkHead, **WorkTail;
static lock *FreeWaiting, *WorkWaiting;

static ThreadCtx *WorkerCtx;
static int ThreadCount;
static int Maxt;
static TrainCtx *GlobalTrainCtx;  /* for worker access to options */

/* ---- JudySL counter operations ---- */

void counter_inc(Counter *c, const char *key) {
    Word_t *pv;
    JSLI(pv, *c, (uint8_t *)key);
    if (pv == PJERR) { fprintf(stderr, "pcfg: Judy error\n"); exit(1); }
    (*pv)++;
}

void counter_inc_n(Counter *c, const char *key, int64_t n) {
    Word_t *pv;
    JSLI(pv, *c, (uint8_t *)key);
    if (pv == PJERR) { fprintf(stderr, "pcfg: Judy error\n"); exit(1); }
    *pv += n;
}

void lencounter_inc(LenCounters *lc, int len, const char *key) {
    Word_t *pv;
    JLI(pv, *lc, (Word_t)len);
    if (pv == PJERR) { fprintf(stderr, "pcfg: Judy error\n"); exit(1); }
    Counter *c = (Counter *)pv;
    counter_inc(c, key);
}

void counter_free(Counter *c) {
    Word_t bytes;
    JSLFA(bytes, *c);
    (void)bytes;
    *c = NULL;
}

void lencounter_free(LenCounters *lc) {
    Word_t idx = 0;
    Word_t *pv;
    JLF(pv, *lc, idx);
    while (pv) {
        Counter *c = (Counter *)pv;
        counter_free(c);
        JLN(pv, *lc, idx);
    }
    Word_t bytes;
    JLFA(bytes, *lc);
    (void)bytes;
    *lc = NULL;
}

/* ---- Merge counters ---- */
static void counter_merge(Counter *dst, Counter *src) {
    static uint8_t idx[PCFG_MAXLINE];  /* main thread only */
    Word_t *pv;
    idx[0] = '\0';
    JSLF(pv, *src, idx);
    while (pv) {
        counter_inc_n(dst, (const char *)idx, (int64_t)*pv);
        JSLN(pv, *src, idx);
    }
    counter_free(src);
}

static void lencounter_merge(LenCounters *dst, LenCounters *src) {
    Word_t idx = 0;
    Word_t *pv;
    JLF(pv, *src, idx);
    while (pv) {
        Counter *sc = (Counter *)pv;
        Word_t *dpv;
        JLI(dpv, *dst, idx);
        Counter *dc = (Counter *)dpv;
        counter_merge(dc, sc);
        JLN(pv, *src, idx);
    }
    Word_t bytes;
    JLFA(bytes, *src);
    (void)bytes;
    *src = NULL;
}

static void merge_thread_ctx(TrainCtx *global, ThreadCtx *tctx) {
    if (tctx->total_passwords == 0) return;
    lencounter_merge(&global->cnt_alpha, &tctx->cnt_alpha);
    lencounter_merge(&global->cnt_masks, &tctx->cnt_masks);
    lencounter_merge(&global->cnt_digits, &tctx->cnt_digits);
    lencounter_merge(&global->cnt_other, &tctx->cnt_other);
    lencounter_merge(&global->cnt_keyboard, &tctx->cnt_keyboard);
    counter_merge(&global->cnt_years, &tctx->cnt_years);
    counter_merge(&global->cnt_context, &tctx->cnt_context);
    counter_merge(&global->cnt_base, &tctx->cnt_base);
    counter_merge(&global->cnt_email_prov, &tctx->cnt_email_prov);
    counter_merge(&global->cnt_web_host, &tctx->cnt_web_host);
    counter_merge(&global->cnt_web_pfx, &tctx->cnt_web_pfx);
    global->total_passwords += tctx->total_passwords;
}

/* ---- Process one password into thread-local counters ---- */
static void train_password_tl(char *pw, int pwlen, ThreadCtx *tctx, WorkSpace *ws) {
    int nsects = pcfg_parse(pw, pwlen, ws->sects, PCFG_MAXSECTIONS,
                            ws->tag, ws->lower);
    if (nsects <= 0) return;

    tctx->total_passwords++;

    for (int i = 0; i < nsects; i++) {
        Section *s = &ws->sects[i];
        char *val = ws->val;
        int vlen = s->vlen;
        if (vlen >= PCFG_MAXLINE) vlen = PCFG_MAXLINE - 1;
        memcpy(val, s->value, vlen);
        val[vlen] = '\0';

        switch (s->type[0]) {
        case ST_ALPHA: {
            /* UTF-8 aware lowering */
            char *lowered = ws->lowered;
            int li = 0, si = 0;
            while (si < vlen && li < PCFG_MAXLINE - 4) {
                uint32_t cp;
                int n = utf8_decode(val + si, vlen - si, &cp);
                if (n == 0) break;
                li += utf8_encode(lowered + li, utf8_to_lower(cp));
                si += n;
            }
            lowered[li] = '\0';
            lencounter_inc(&tctx->cnt_alpha, s->tnum, lowered);
            build_case_mask(val, vlen, ws->mask);
            lencounter_inc(&tctx->cnt_masks, s->tnum, ws->mask);
            break;
        }
        case ST_DIGIT:
            lencounter_inc(&tctx->cnt_digits, s->tnum, val);
            break;
        case ST_OTHER:
            lencounter_inc(&tctx->cnt_other, s->tnum, val);
            break;
        case ST_YEAR:
            counter_inc(&tctx->cnt_years, val);
            break;
        case ST_CONTEXT:
            counter_inc(&tctx->cnt_context, val);
            break;
        case ST_KEYBOARD:
            lencounter_inc(&tctx->cnt_keyboard, s->tnum, val);
            break;
        case ST_EMAIL:
            {
                char *at = memchr(val, '@', vlen);
                if (at) {
                    char prov[256];
                    int plen = val + vlen - (at + 1);
                    if (plen > 0 && plen < 256) {
                        memcpy(prov, at + 1, plen);
                        prov[plen] = '\0';
                        for (int j = 0; j < plen; j++)
                            prov[j] = fast_lower((unsigned char)prov[j]);
                        counter_inc(&tctx->cnt_email_prov, prov);
                    }
                }
            }
            break;
        case ST_WEBSITE:
            {
                char *lval = ws->lowered;  /* reuse lowered buffer */
                for (int j = 0; j < vlen; j++)
                    lval[j] = fast_lower((unsigned char)val[j]);
                lval[vlen] = '\0';
                char *start = lval;
                char *pfx = "";
                if (strncmp(start, "http", 4) == 0) {
                    if (strncmp(start+4, "s://www.", 8) == 0) { pfx = "https://www."; start += 12; }
                    else if (strncmp(start+4, "://www.", 6) == 0) { pfx = "http://www."; start += 11; }
                    else if (strncmp(start+4, "s://", 4) == 0) { pfx = "https://"; start += 8; }
                    else if (strncmp(start+4, "://", 3) == 0) { pfx = "http://"; start += 7; }
                } else if (strncmp(start, "www.", 4) == 0) { pfx = "www."; start += 4; }
                char *h = start;
                while (*h && *h != '/' && *h != '?' && *h != '#' && *h != ' ') h++;
                char host[256];
                int hlen = h - start;
                if (hlen > 0 && hlen < 256) {
                    memcpy(host, start, hlen);
                    host[hlen] = '\0';
                    counter_inc(&tctx->cnt_web_host, host);
                }
                if (*pfx)
                    counter_inc(&tctx->cnt_web_pfx, pfx);
            }
            break;
        default:
            break;
        }
    }

    build_base_structure(ws->sects, nsects, ws->base_str, PCFG_MAXLINE);
    if (ws->base_str[0])
        counter_inc(&tctx->cnt_base, ws->base_str);
}

/* ---- Persistent worker thread ---- */
static void train_worker(void *arg) {
    int worker_id = (int)(intptr_t)arg;
    ThreadCtx *tctx = &WorkerCtx[worker_id];
    WorkSpace *ws = ws_alloc();

    while (1) {
        possess(WorkWaiting);
        wait_for(WorkWaiting, NOT_TO_BE, 0);
        TrainJob *job = WorkHead;
        if (!job) { release(WorkWaiting); continue; }
        if (job->op == JOB_DONE) { release(WorkWaiting); return; }
        WorkHead = job->next;
        if (!WorkHead) WorkTail = &WorkHead;
        twist(WorkWaiting, BY, -1);

        char *buf = job->readbuf;
        struct LineInfo *ridx = job->readindex;
        unsigned int end = job->startline + job->numline;

        for (unsigned int i = job->startline; i < end; i++) {
            char *pw = &buf[ridx[i].offset];
            int pwlen = ridx[i].len;
            if (pwlen <= 0 || pwlen >= PCFG_MAXLINE - 64) continue;
            /* Weighted: skip count: prefix */
            if (GlobalTrainCtx->weighted)
                (void)parse_weight(&pw, &pwlen);
            if (pwlen >= 5 && strncmp(pw, "$HEX[", 5) == 0) {
                int dlen = decode_hex(pw + 5, ws->decoded, pwlen - 5);
                pw = ws->decoded; pwlen = dlen;
            }
            if (pwlen <= 0) continue;
            /* Junk filter */
            if (GlobalTrainCtx->filter_junk && is_junk_line(pw, pwlen)) continue;
            train_password_tl(pw, pwlen, tctx, ws);
        }

        lock *buflock = (buf == Readbuf) ? ReadBuf0 : ReadBuf1;
        possess(buflock);
        twist(buflock, BY, -1);

        possess(FreeWaiting);
        job->next = NULL;
        *FreeTail = job;
        FreeTail = &(job->next);
        twist(FreeWaiting, BY, +1);
    }
}

/* ---- cacheline ---- */
static unsigned int cacheline(FILE *fi, char **mybuf,
                              struct LineInfo **myindex) {
    int half = Cacheindex;
    char *curpos = Readbuf + half * TRAIN_HALFCHUNK;
    struct LineInfo *ridx = Readindex + half * TRAIN_MAXLINES;

    lock *buflock = (half == 0) ? ReadBuf0 : ReadBuf1;
    possess(buflock);
    wait_for(buflock, TO_BE, 0);
    release(buflock);

    unsigned int linecount = 0;
    int curcnt = 0;

    if (CL_lastcnt > 0) {
        memmove(curpos, CL_lastleft, CL_lastcnt);
        curcnt = CL_lastcnt;
        CL_lastcnt = 0;
        CL_lastleft = NULL;
    }

    int x = 0;
    if (!feof(fi))
        x = fread(curpos + curcnt, 1, TRAIN_HALFCHUNK - curcnt - 1, fi);
    if (x <= 0) x = 0;
    curcnt += x;

    if (curcnt <= 0) return 0;

    memset(curpos + curcnt, 0, 16);

    int curindex = 0;
    while (curindex < curcnt) {
        ridx[linecount].offset = curindex;
        char *f = findeol(&curpos[curindex], curcnt - curindex);
        if (f) {
            int len = f - &curpos[curindex];
            int rlen = len;
            if (rlen > 0 && curpos[curindex + rlen - 1] == '\r') rlen--;
            if (rlen < 0) rlen = 0;
            ridx[linecount].len = rlen;
            curpos[curindex + rlen] = '\0';
            curindex += len + 1;
            if (len >= TRAIN_MAXLINE) continue;
            if (++linecount >= TRAIN_MAXLINES) {
                if (curindex < curcnt) {
                    CL_lastleft = &curpos[curindex];
                    CL_lastcnt = curcnt - curindex;
                }
                break;
            }
        } else {
            if (feof(fi)) {
                int rlen = curcnt - curindex;
                if (rlen > 0 && curpos[curindex + rlen - 1] == '\n') rlen--;
                if (rlen > 0 && curpos[curindex + rlen - 1] == '\r') rlen--;
                if (rlen < 0) rlen = 0;
                ridx[linecount].len = rlen;
                curpos[curindex + rlen] = '\0';
                if (rlen > 0 && rlen < TRAIN_MAXLINE) linecount++;
                break;
            }
            CL_lastleft = &curpos[curindex];
            CL_lastcnt = curcnt - curindex;
            if (CL_lastcnt >= TRAIN_MAXLINE) CL_lastcnt = 0;
            break;
        }
    }

    *mybuf = curpos;
    *myindex = ridx;
    Cacheindex ^= 1;
    return linecount;
}

/* ---- Main training entry point ---- */
int pcfg_train(const char *infile, const char *outdir, TrainCtx *ctx) {
    FILE *fin;
    Maxt = ctx->max_threads > 0 ? ctx->max_threads : get_nprocs();
    if (Maxt < 1) Maxt = 1;

    if (strcmp(infile, "stdin") == 0)
        fin = stdin;
    else {
        fin = fopen(infile, "rb");
        if (!fin) {
            fprintf(stderr, "pcfg: cannot open \"%s\": %s\n",
                    infile, strerror(errno));
            return 1;
        }
    }

    GlobalTrainCtx = ctx;
    fprintf(stderr, "pcfg: max %d threads, %d lines/job\n", Maxt, LINES_PER_JOB);

    /* Sequential state: multiword trie + OMEN (run on main thread) */
    MultiWordTrie *mwtrie = multiword_new(5, 4, 21);
    OmenTrainer *omen = omen_new(ctx->ngram_size, ctx->alphabet_size);
    Counter char_freq = NULL;
    int alphabet_built = 0;
    char *decoded_main = malloc(PCFG_MAXLINE);

    GlobalMultiTrie = mwtrie;

    /* Allocate double buffer + line index */
    Readbuf = malloc(TRAIN_CHUNK + 32);
    Readindex = malloc(TRAIN_MAXLINES * 2 * sizeof(struct LineInfo) + 16);
    if (!Readbuf || !Readindex) {
        fprintf(stderr, "pcfg: OOM\n");
        if (fin != stdin) fclose(fin);
        return 1;
    }
    memset(Readbuf + TRAIN_CHUNK, 0, 32);

    ReadBuf0 = new_lock(0);
    ReadBuf1 = new_lock(0);
    CL_lastleft = NULL;
    CL_lastcnt = 0;
    Cacheindex = 0;

    /* Allocate job pool */
    JobPool = calloc(MAX_JOBS, sizeof(TrainJob));
    FreeHead = NULL;
    FreeTail = &FreeHead;
    for (int i = 0; i < MAX_JOBS; i++) {
        *FreeTail = &JobPool[i];
        FreeTail = &(JobPool[i].next);
    }
    FreeWaiting = new_lock(MAX_JOBS);
    WorkHead = NULL;
    WorkTail = &WorkHead;
    WorkWaiting = new_lock(0);

    WorkerCtx = calloc(Maxt, sizeof(ThreadCtx));
    ThreadCount = 0;

    /* ---- Single-pass dispatch loop ---- */
    int64_t total_lines = 0;
    char *readbuf;
    struct LineInfo *readindex;
    unsigned int linecount;

    while ((linecount = cacheline(fin, &readbuf, &readindex)) > 0) {
        total_lines += linecount;
        /*
         * Main thread iterates this buffer's lines for sequential work:
         *   - Multiword trie training (all buffers)
         *   - Char frequency collection (first buffer only)
         *   - OMEN n-gram training (after alphabet built)
         *
         * The buffer is pinned (refcount not yet incremented by jobs),
         * so it's safe to read. Workers will process the same buffer
         * in parallel for PCFG parsing after we dispatch jobs below.
         */
        for (unsigned int li = 0; li < linecount; li++) {
            char *pw = &readbuf[readindex[li].offset];
            int pwlen = readindex[li].len;
            if (pwlen <= 0 || pwlen >= TRAIN_MAXLINE - 64) continue;

            /* Weighted input: extract count prefix */
            /* (weight is used for multiword/omen on main thread;
               workers see each line once regardless) */
            if (ctx->weighted)
                (void)parse_weight(&pw, &pwlen);

            /* $HEX[] decode */
            if (pwlen >= 5 && strncmp(pw, "$HEX[", 5) == 0) {
                int dlen = decode_hex(pw + 5, decoded_main, pwlen - 5);
                pw = decoded_main;
                pwlen = dlen;
            }
            if (pwlen <= 0) continue;

            /* Junk filter */
            if (ctx->filter_junk && is_junk_line(pw, pwlen)) continue;

            /* Multiword trie: always */
            multiword_train(mwtrie, pw, pwlen);

            if (!alphabet_built) {
                /* Collect char frequencies for OMEN alphabet */
                for (int ci = 0; ci < pwlen; ci++) {
                    char cs[2] = { pw[ci], '\0' };
                    counter_inc(&char_freq, cs);
                }
            } else {
                /* OMEN n-gram training */
                omen_train(omen, pw, pwlen);
            }
        }

        /* After first buffer: build OMEN alphabet */
        if (!alphabet_built) {
            omen_build_alphabet(omen, char_freq);
            counter_free(&char_freq);
            alphabet_built = 1;
            fprintf(stderr, "pcfg: alphabet built from first buffer\n");
        }

        /* Launch workers as needed */
        int jobs_needed = (linecount + LINES_PER_JOB - 1) / LINES_PER_JOB;
        int workers_needed = jobs_needed;
        if (workers_needed > Maxt) workers_needed = Maxt;
        while (ThreadCount < workers_needed) {
            launch(train_worker, (void *)(intptr_t)ThreadCount);
            ThreadCount++;
        }

        /* Dispatch PCFG jobs on this buffer */
        unsigned int curline = 0;
        while (curline < linecount) {
            unsigned int numline = LINES_PER_JOB;
            if (curline + numline > linecount)
                numline = linecount - curline;

            possess(FreeWaiting);
            wait_for(FreeWaiting, NOT_TO_BE, 0);
            TrainJob *job = FreeHead;
            FreeHead = job->next;
            if (!FreeHead) FreeTail = &FreeHead;
            twist(FreeWaiting, BY, -1);

            job->op = JOB_TRAIN;
            job->readbuf = readbuf;
            job->readindex = readindex;
            job->startline = curline;
            job->numline = numline;
            job->next = NULL;

            lock *buflock = (readbuf == Readbuf) ? ReadBuf0 : ReadBuf1;
            possess(buflock);
            twist(buflock, BY, +1);

            possess(WorkWaiting);
            *WorkTail = job;
            WorkTail = &(job->next);
            twist(WorkWaiting, BY, +1);

            curline += numline;
        }

        fprintf(stderr, "\rpcfg: %" PRId64 " passwords (%d threads)...",
                total_lines, ThreadCount);
    }

    /* Wait for all jobs to drain */
    possess(FreeWaiting);
    wait_for(FreeWaiting, TO_BE, MAX_JOBS);
    release(FreeWaiting);

    /* Smooth OMEN levels */
    omen_smooth(omen);

    /* Poison pill */
    if (ThreadCount > 0) {
        possess(FreeWaiting);
        wait_for(FreeWaiting, NOT_TO_BE, 0);
        TrainJob *job = FreeHead;
        FreeHead = job->next;
        if (!FreeHead) FreeTail = &FreeHead;
        twist(FreeWaiting, BY, -1);

        job->op = JOB_DONE;
        job->next = NULL;
        possess(WorkWaiting);
        *WorkTail = job;
        WorkTail = &(job->next);
        twist(WorkWaiting, BY, +1);

        int caught = join_all();
        fprintf(stderr, "\rpcfg: %d threads joined                   \n", caught);
    }

    /* Merge all worker contexts */
    print_mem("before merge");
    fprintf(stderr, "pcfg: merging counters...");
    for (int t = 0; t < ThreadCount; t++)
        merge_thread_ctx(ctx, &WorkerCtx[t]);
    fprintf(stderr, " done\n");
    print_mem("after merge");

    /* Inject M (Markov) entry */
    if (ctx->coverage < 1.0 && ctx->total_passwords > 0) {
        int64_t markov_count = (int64_t)((ctx->total_passwords / ctx->coverage)
                                          - ctx->total_passwords);
        if (markov_count > 0)
            counter_inc_n(&ctx->cnt_base, "M", markov_count);
    }

    /* Save OMEN files */
    {
        char omen_dir[PCFG_MAXPATH];
        snprintf(omen_dir, sizeof(omen_dir), "%s/Omen", outdir);
        omen_save(omen, omen_dir);
    }

    /* Skip multiword_free/omen_free — we're about to exit and the OS
     * will reclaim all memory. trie_free_node was 18% of runtime. */

    /* Cleanup */
    free(WorkerCtx);
    free(JobPool);
    free_lock(FreeWaiting);
    free_lock(WorkWaiting);
    free_lock(ReadBuf0);
    free_lock(ReadBuf1);
    free(Readbuf);
    free(Readindex);
    if (fin != stdin) fclose(fin);

    return pcfg_save(outdir, ctx);
}
