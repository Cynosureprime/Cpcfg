/*
 * pcfg_gen.c - Parallel guess generation
 *
 * Pipeline: popper (main thread) → workers (N threads)
 *
 * Popper: pops from priority queue, finds children, pushes PTItems
 *   to a work ring for expansion.
 * Workers: pull PTItems, expand into passwords in pre-allocated buffers,
 *   flush directly to stdout under a single write lock.
 *
 * All per-worker buffers are pre-allocated. No malloc in hot paths.
 * Guess count uses __sync atomic for -n limit enforcement.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>

#include "pcfg.h"
#include "yarn.h"

/* ---- Config ---- */
#define PT_RING_SIZE    1024
#define OUTBUF_SIZE     (1024 * 1024)

/* ---- Shared state ---- */
static GenCtx       *Gen;
static volatile int  gen_done;
static volatile int64_t guess_count;
static int64_t       guess_limit_val;

/* PT work ring: popper → workers */
static PTItem  *pt_ring;
static volatile int pt_head, pt_tail;
static lock    *pt_have;
static lock    *pt_space;

/* Single write lock for stdout */
static lock    *write_lock;

static const char hextab_lc[16] = "0123456789abcdef";

/* ---- $HEX[] check ---- */
static inline int needs_hex(const char *pass, int passlen) {
    for (int i = 0; i < passlen; i++) {
        if ((signed char)(pass[i] + 1) < '!')
            return 1;
        if (pass[i] == ':')
            return 1;
    }
    if (passlen >= 5 && strncmp(pass, "$HEX[", 5) == 0)
        return 1;
    return 0;
}

/* ---- Per-worker state (all pre-allocated) ---- */
typedef struct {
    char *outbuf;       /* OUTBUF_SIZE bytes for accumulated output */
    int   outpos;
    char *guessbuf;     /* PCFG_MAXLINE bytes for building guesses */
    char *saved;        /* PCFG_MAXLINE bytes for case mask save/restore */
    int64_t count;
} Worker;

static void worker_flush(Worker *w) {
    if (w->outpos > 0) {
        possess(write_lock);
        int remaining = w->outpos;
        char *p = w->outbuf;
        while (remaining > 0) {
            ssize_t n = write(STDOUT_FILENO, p, remaining);
            if (n <= 0) { gen_done = 1; break; }
            p += n;
            remaining -= n;
        }
        twist(write_lock, TO, 0);
        w->outpos = 0;
    }
}

static inline void worker_emit(Worker *w, const char *guess, int len) {
    if (needs_hex(guess, len)) {
        int need = 5 + len * 2 + 2;
        if (w->outpos + need >= OUTBUF_SIZE)
            worker_flush(w);
        memcpy(w->outbuf + w->outpos, "$HEX[", 5);
        w->outpos += 5;
        for (int i = 0; i < len; i++) {
            unsigned char c = (unsigned char)guess[i];
            w->outbuf[w->outpos++] = hextab_lc[(c >> 4) & 0xf];
            w->outbuf[w->outpos++] = hextab_lc[c & 0xf];
        }
        w->outbuf[w->outpos++] = ']';
        w->outbuf[w->outpos++] = '\n';
    } else {
        if (w->outpos + len + 1 >= OUTBUF_SIZE)
            worker_flush(w);
        memcpy(w->outbuf + w->outpos, guess, len);
        w->outpos += len;
        w->outbuf[w->outpos++] = '\n';
    }
    w->count++;
    if (guess_limit_val > 0 &&
        __sync_add_and_fetch(&guess_count, 1) >= guess_limit_val)
        gen_done = 1;
}

/* ---- Apply case mask (UTF-8) ---- */
static int apply_case_mask(const char *alpha, int alpha_bytelen,
                           const char *mask, char *out) {
    int oi = 0, ai = 0, mi = 0;
    while (ai < alpha_bytelen) {
        uint32_t cp;
        int n = utf8_decode(alpha + ai, alpha_bytelen - ai, &cp);
        if (n == 0) break;
        uint32_t mapped = (mask[mi] == 'U') ? utf8_to_upper(cp) : utf8_to_lower(cp);
        oi += utf8_encode(out + oi, mapped);
        ai += n;
        mi++;
    }
    return oi;
}

/* ---- Recursive guess expansion ---- */
static void expand_item(GenCtx *ctx, PTNode *nodes, int nnodes,
                        int node_idx, char *buf, int bufpos, Worker *w) {
    if (gen_done) return;
    if (node_idx >= nnodes) {
        worker_emit(w, buf, bufpos);
        return;
    }

    PTNode *node = &nodes[node_idx];
    char type_char = node->type[0];

    Word_t *pv;
    JSLG(pv, ctx->grammar, (uint8_t *)node->type);
    if (!pv) return;

    GrammarEntryList *gel = (GrammarEntryList *)*pv;
    if (node->index >= gel->nentries) return;
    GrammarEntry *ge = &gel->entries[node->index];

    if (type_char == ST_CASE) {
        for (int v = 0; v < ge->nvalues && !gen_done; v++) {
            char *mask = ge->values[v];
            int mlen = strlen(mask);
            int alpha_start = bufpos;
            int cps = 0;
            while (alpha_start > 0 && cps < mlen) {
                alpha_start--;
                while (alpha_start > 0 && ((unsigned char)buf[alpha_start] & 0xC0) == 0x80)
                    alpha_start--;
                cps++;
            }
            int alpha_bytelen = bufpos - alpha_start;
            memcpy(w->saved, buf + alpha_start, alpha_bytelen);
            int newlen = apply_case_mask(w->saved, alpha_bytelen, mask, buf + alpha_start);
            expand_item(ctx, nodes, nnodes, node_idx + 1, buf, alpha_start + newlen, w);
            memcpy(buf + alpha_start, w->saved, alpha_bytelen);
        }
    } else if (type_char == ST_MARKOV) {
        return;
    } else {
        for (int v = 0; v < ge->nvalues && !gen_done; v++) {
            int vlen = strlen(ge->values[v]);
            if (bufpos + vlen >= PCFG_MAXLINE) continue;
            memcpy(buf + bufpos, ge->values[v], vlen);
            expand_item(ctx, nodes, nnodes, node_idx + 1, buf, bufpos + vlen, w);
        }
    }
}

/* ---- Debug print ---- */
static void debug_print_pt(GenCtx *ctx, PTItem *item) {
    fprintf(stderr, "[%.6e] ", item->prob);
    for (int i = 0; i < item->nnodes; i++) {
        Word_t *pv;
        JSLG(pv, ctx->grammar, (uint8_t *)item->nodes[i].type);
        if (pv) {
            GrammarEntryList *gel = (GrammarEntryList *)*pv;
            if (item->nodes[i].index < gel->nentries) {
                GrammarEntry *ge = &gel->entries[item->nodes[i].index];
                fprintf(stderr, "%s[%d](p=%.4e,n=%d) ",
                        item->nodes[i].type, item->nodes[i].index,
                        ge->prob, ge->nvalues);
            }
        }
    }
    fprintf(stderr, "\n");
}

/* ---- Seed queue ---- */
static void seed_queue(GenCtx *ctx) {
    pq_init(&ctx->queue, ctx->nbases * 2);
    for (int i = 0; i < ctx->nbases; i++) {
        BaseStructure *bs = &ctx->bases[i];
        if (bs->nreplace <= 0) continue;
        int valid = 1;
        for (int j = 0; j < bs->nreplace; j++) {
            /* -b: skip structures containing Markov entries */
            if (ctx->skip_brute && bs->replacements[j][0] == 'M') {
                valid = 0; break;
            }
            Word_t *pv;
            JSLG(pv, ctx->grammar, (uint8_t *)bs->replacements[j]);
            if (!pv) { valid = 0; break; }
            GrammarEntryList *gel = (GrammarEntryList *)*pv;
            if (gel->nentries <= 0) { valid = 0; break; }
        }
        if (!valid) continue;
        PTNode *nodes = malloc(bs->nreplace * sizeof(PTNode));
        for (int j = 0; j < bs->nreplace; j++) {
            strncpy(nodes[j].type, bs->replacements[j], PCFG_MAXTYPE - 1);
            nodes[j].type[PCFG_MAXTYPE - 1] = '\0';
            nodes[j].index = 0;
        }
        PTItem item;
        item.base_prob = bs->prob;
        item.nodes = nodes;
        item.nnodes = bs->nreplace;
        item.prob = find_prob(ctx, nodes, bs->nreplace, bs->prob);
        item.seq = 0;
        if (item.prob > 0.0)
            pq_push(&ctx->queue, &item);
        else
            free(nodes);
    }
    fprintf(stderr, "pcfg: queue seeded with %d items\n", ctx->queue.size);
}

/* ---- Add case mangling ---- */
static void add_case_mangling(BaseStructure *bases, int nbases) {
    for (int i = 0; i < nbases; i++) {
        BaseStructure *bs = &bases[i];
        int n_alpha = 0;
        for (int j = 0; j < bs->nreplace; j++)
            if (bs->replacements[j][0] == 'A') n_alpha++;
        if (n_alpha == 0) continue;
        int new_count = bs->nreplace + n_alpha;
        char **new_repl = malloc(new_count * sizeof(char *));
        int k = 0;
        for (int j = 0; j < bs->nreplace; j++) {
            new_repl[k++] = bs->replacements[j];
            if (bs->replacements[j][0] == 'A') {
                char cbuf[PCFG_MAXTYPE];
                cbuf[0] = 'C';
                strcpy(cbuf + 1, bs->replacements[j] + 1);
                new_repl[k++] = strdup(cbuf);
            }
        }
        free(bs->replacements);
        bs->replacements = new_repl;
        bs->nreplace = new_count;
    }
}

/* ---- Worker thread ---- */
static void gen_worker(void *arg) {
    Worker *w = (Worker *)arg;

    while (1) {
        possess(pt_have);
        wait_for(pt_have, NOT_TO_BE, 0);
        int slot = pt_tail % PT_RING_SIZE;
        PTItem item = pt_ring[slot];
        pt_tail++;
        twist(pt_have, BY, -1);

        possess(pt_space);
        twist(pt_space, BY, +1);

        if (item.nnodes == -1)  /* sentinel */
            break;

        expand_item(Gen, item.nodes, item.nnodes, 0, w->guessbuf, 0, w);
        free(item.nodes);
    }

    worker_flush(w);
}

/* ---- Main generation ---- */
int pcfg_generate(const char *grammardir, GenCtx *ctx) {
    if (pcfg_load(grammardir, ctx) < 0)
        return 1;

    add_case_mangling(ctx->bases, ctx->nbases);
    seed_queue(ctx);

    Gen = ctx;
    gen_done = 0;
    guess_count = 0;
    guess_limit_val = ctx->guess_limit;

    int nworkers = ctx->nthreads;
    if (nworkers < 1) nworkers = 1;

    /* Single-threaded path for debug or -T 1 */
    if (ctx->debug || nworkers == 1) {
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        Worker w;
        w.outbuf = malloc(OUTBUF_SIZE);
        w.outpos = 0;
        w.guessbuf = malloc(PCFG_MAXLINE);
        w.saved = malloc(PCFG_MAXLINE);
        w.count = 0;

        PTItem item;
        while (pq_pop(&ctx->queue, &item)) {
            if (ctx->debug) debug_print_pt(ctx, &item);
            expand_item(ctx, item.nodes, item.nnodes, 0, w.guessbuf, 0, &w);
            if (w.outpos > 0) {
                write(STDOUT_FILENO, w.outbuf, w.outpos);
                w.outpos = 0;
            }
            int nchildren;
            PTItem *children = find_children(ctx, &item, &nchildren);
            for (int i = 0; i < nchildren; i++)
                pq_push(&ctx->queue, &children[i]);
            free(children);
            free(item.nodes);
            if (ctx->guess_limit > 0 && w.count >= ctx->guess_limit)
                break;
        }
        if (w.outpos > 0)
            write(STDOUT_FILENO, w.outbuf, w.outpos);

        struct timespec tend;
        clock_gettime(CLOCK_MONOTONIC, &tend);
        double elapsed = (tend.tv_sec - t0.tv_sec) + (tend.tv_nsec - t0.tv_nsec) / 1e9;
        fprintf(stderr, "\rpcfg: done. %" PRId64 " guesses in %.2fs (%.1fM/s)\n",
                w.count, elapsed, elapsed > 0 ? w.count / elapsed / 1e6 : 0.0);
        free(w.outbuf); free(w.guessbuf); free(w.saved);
        pq_free(&ctx->queue);
        return 0;
    }

    /* ---- Parallel path ---- */
    fprintf(stderr, "pcfg: generating with %d worker threads\n", nworkers);

    /* Pre-allocate all worker state */
    Worker *workers = malloc(nworkers * sizeof(Worker));
    for (int i = 0; i < nworkers; i++) {
        workers[i].outbuf = malloc(OUTBUF_SIZE);
        workers[i].outpos = 0;
        workers[i].guessbuf = malloc(PCFG_MAXLINE);
        workers[i].saved = malloc(PCFG_MAXLINE);
        workers[i].count = 0;
    }

    /* Pre-allocate work ring */
    pt_ring = calloc(PT_RING_SIZE, sizeof(PTItem));
    pt_head = pt_tail = 0;
    pt_have = new_lock(0);
    pt_space = new_lock(PT_RING_SIZE);
    write_lock = new_lock(0);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* Launch workers */
    for (int i = 0; i < nworkers; i++)
        launch(gen_worker, &workers[i]);

    /* Popper: main thread */
    int64_t pt_count = 0;
    struct timespec tlast = t0;
    PTItem item;

    while (!gen_done && pq_pop(&ctx->queue, &item)) {
        pt_count++;

        /* Push to work ring */
        possess(pt_space);
        wait_for(pt_space, NOT_TO_BE, 0);
        int slot = pt_head % PT_RING_SIZE;
        pt_ring[slot] = item;  /* nodes pointer transferred to worker */
        pt_head++;
        twist(pt_space, BY, -1);
        possess(pt_have);
        twist(pt_have, BY, +1);

        /* Find children, push to queue */
        int nchildren;
        PTItem *children = find_children(ctx, &item, &nchildren);
        for (int i = 0; i < nchildren; i++)
            pq_push(&ctx->queue, &children[i]);
        free(children);

        /* Check limit */
        if (guess_limit_val > 0 &&
            __sync_fetch_and_add(&guess_count, 0) >= guess_limit_val) {
            gen_done = 1;
            break;
        }

        /* Progress */
        if ((pt_count & 0x3FFF) == 0) {
            struct timespec tnow;
            clock_gettime(CLOCK_MONOTONIC, &tnow);
            double elapsed = (tnow.tv_sec - tlast.tv_sec) +
                             (tnow.tv_nsec - tlast.tv_nsec) / 1e9;
            if (elapsed >= 2.0) {
                int64_t cur = __sync_fetch_and_add(&guess_count, 0);
                double total_elapsed = (tnow.tv_sec - t0.tv_sec) +
                                       (tnow.tv_nsec - t0.tv_nsec) / 1e9;
                fprintf(stderr, "\rpcfg: %" PRId64 " guesses (%" PRId64 " PTs) "
                        "%.1fM/s prob=%.4e q=%d  ",
                        cur, pt_count, cur / total_elapsed / 1e6,
                        item.prob, ctx->queue.size);
                tlast = tnow;
            }
        }
    }

    /* Send sentinel per worker */
    gen_done = 1;
    for (int i = 0; i < nworkers; i++) {
        possess(pt_space);
        wait_for(pt_space, NOT_TO_BE, 0);
        int slot = pt_head % PT_RING_SIZE;
        memset(&pt_ring[slot], 0, sizeof(PTItem));
        pt_ring[slot].nnodes = -1;
        pt_head++;
        twist(pt_space, BY, -1);
        possess(pt_have);
        twist(pt_have, BY, +1);
    }

    join_all();

    struct timespec tend;
    clock_gettime(CLOCK_MONOTONIC, &tend);
    double total_elapsed = (tend.tv_sec - t0.tv_sec) +
                           (tend.tv_nsec - t0.tv_nsec) / 1e9;
    int64_t final_count = __sync_fetch_and_add(&guess_count, 0);
    fprintf(stderr, "\rpcfg: done. %" PRId64 " guesses in %.2fs (%.1fM/s)\n",
            final_count, total_elapsed,
            total_elapsed > 0 ? final_count / total_elapsed / 1e6 : 0.0);

    /* Cleanup */
    for (int i = 0; i < nworkers; i++) {
        free(workers[i].outbuf);
        free(workers[i].guessbuf);
        free(workers[i].saved);
    }
    free(workers);
    free(pt_ring);
    free_lock(pt_have);
    free_lock(pt_space);
    free_lock(write_lock);
    pq_free(&ctx->queue);
    return 0;
}
