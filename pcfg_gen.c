/*
 * pcfg_gen.c - Parallel guess generation
 *
 * Pipeline: popper (1) → workers (N) → writer (1)
 *
 * Popper: pops from priority queue, finds children, pushes PTItems
 *   to a work ring for expansion.
 * Workers: pull PTItems, recursively expand into password strings,
 *   accumulate in thread-local 1MB output buffers, flush to output ring.
 * Writer: pulls filled output buffers, writes to stdout.
 *
 * Ring buffers use yarn locks for synchronization.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

#include "pcfg.h"
#include "yarn.h"

/* ---- Ring buffer sizes ---- */
#define PT_RING_SIZE    1024    /* PTItems: popper → workers */
#define OUT_RING_SIZE   64      /* output buffers: workers → writer */
#define OUTBUF_SIZE     (1024 * 1024)

/* ---- Output buffer for ring ---- */
typedef struct {
    char *buf;
    int   pos;
    int   cap;
} OutBatch;

/* ---- PT work ring ---- */
static PTItem  *pt_ring;
static int      pt_head, pt_tail;
static lock    *pt_have;    /* count of items available */
static lock    *pt_space;   /* count of slots free */

/* ---- Output ring ---- */
static OutBatch *out_ring;
static int       out_head, out_tail;
static lock     *out_have;
static lock     *out_space;

/* ---- Shared state ---- */
static GenCtx       *Gen;
static volatile int  gen_done;
static int64_t       total_guesses_atomic;
static lock         *guess_lock;
static lock         *workers_alive;  /* count of active workers */

static const char hextab_lc[16] = "0123456789abcdef";

/* ---- $HEX[] output encoding ---- */
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

/* Forward declaration */
static void signal_writer_done(void);

/* ---- Per-worker output accumulator ---- */
typedef struct {
    char *buf;
    int   pos;
    int   cap;
    int64_t count;
} WorkerOut;

static inline void worker_emit(WorkerOut *wo, const char *guess, int len) {
    if (needs_hex(guess, len)) {
        int need = 5 + len * 2 + 2;
        if (wo->pos + need >= wo->cap) {
            /* Flush to output ring */
            possess(out_space);
            wait_for(out_space, NOT_TO_BE, 0);
            int slot = out_head % OUT_RING_SIZE;
            out_ring[slot].buf = wo->buf;
            out_ring[slot].pos = wo->pos;
            out_head++;
            twist(out_space, BY, -1);
            possess(out_have);
            twist(out_have, BY, +1);
            /* Get a fresh buffer */
            wo->buf = malloc(OUTBUF_SIZE);
            wo->pos = 0;
        }
        memcpy(wo->buf + wo->pos, "$HEX[", 5);
        wo->pos += 5;
        for (int i = 0; i < len; i++) {
            unsigned char c = (unsigned char)guess[i];
            wo->buf[wo->pos++] = hextab_lc[(c >> 4) & 0xf];
            wo->buf[wo->pos++] = hextab_lc[c & 0xf];
        }
        wo->buf[wo->pos++] = ']';
        wo->buf[wo->pos++] = '\n';
    } else {
        if (wo->pos + len + 1 >= wo->cap) {
            possess(out_space);
            wait_for(out_space, NOT_TO_BE, 0);
            int slot = out_head % OUT_RING_SIZE;
            out_ring[slot].buf = wo->buf;
            out_ring[slot].pos = wo->pos;
            out_head++;
            twist(out_space, BY, -1);
            possess(out_have);
            twist(out_have, BY, +1);
            wo->buf = malloc(OUTBUF_SIZE);
            wo->pos = 0;
        }
        memcpy(wo->buf + wo->pos, guess, len);
        wo->pos += len;
        wo->buf[wo->pos++] = '\n';
    }
    wo->count++;
}

/* Check if generation limit reached (called periodically by workers) */
static inline int limit_reached(void) {
    if (!Gen || Gen->guess_limit <= 0) return 0;
    return gen_done;
}

/* Flush remaining output from worker */
static void worker_flush(WorkerOut *wo) {
    if (wo->pos > 0) {
        possess(out_space);
        wait_for(out_space, NOT_TO_BE, 0);
        int slot = out_head % OUT_RING_SIZE;
        out_ring[slot].buf = wo->buf;
        out_ring[slot].pos = wo->pos;
        out_head++;
        twist(out_space, BY, -1);
        possess(out_have);
        twist(out_have, BY, +1);
        wo->buf = NULL;
        wo->pos = 0;
    }
}

/* ---- Apply case mask ---- */
static inline void apply_case_mask(const char *alpha, const char *mask, int len,
                                   char *out) {
    for (int i = 0; i < len; i++) {
        if (mask[i] == 'U')
            out[i] = (alpha[i] >= 'a' && alpha[i] <= 'z') ? alpha[i] - 32 : alpha[i];
        else
            out[i] = (alpha[i] >= 'A' && alpha[i] <= 'Z') ? alpha[i] + 32 : alpha[i];
    }
}

/* ---- Recursive guess expansion ---- */
static void expand_item(GenCtx *ctx, PTNode *nodes, int nnodes,
                        int node_idx, char *buf, int bufpos, WorkerOut *wo) {
    if (node_idx >= nnodes) {
        worker_emit(wo, buf, bufpos);
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
        for (int v = 0; v < ge->nvalues; v++) {
            char *mask = ge->values[v];
            int mlen = strlen(mask);
            if (mlen > bufpos) mlen = bufpos;
            char saved[256];
            int slen = mlen < 256 ? mlen : 255;
            memcpy(saved, buf + bufpos - slen, slen);
            apply_case_mask(saved, mask, slen, buf + bufpos - slen);
            expand_item(ctx, nodes, nnodes, node_idx + 1, buf, bufpos, wo);
            memcpy(buf + bufpos - slen, saved, slen);
        }
    } else if (type_char == ST_MARKOV) {
        /* Skip M entries for now */
        return;
    } else {
        for (int v = 0; v < ge->nvalues; v++) {
            int vlen = strlen(ge->values[v]);
            if (bufpos + vlen >= PCFG_MAXLINE) continue;
            memcpy(buf + bufpos, ge->values[v], vlen);
            expand_item(ctx, nodes, nnodes, node_idx + 1, buf, bufpos + vlen, wo);
        }
    }
}

/* ---- Worker thread ---- */
static void gen_worker(void *arg) {
    (void)arg;
    char *buf = malloc(PCFG_MAXLINE);
    WorkerOut wo;
    wo.buf = malloc(OUTBUF_SIZE);
    wo.pos = 0;
    wo.cap = OUTBUF_SIZE;
    wo.count = 0;

    while (1) {
        possess(pt_have);
        wait_for(pt_have, NOT_TO_BE, 0);
        int slot = pt_tail % PT_RING_SIZE;
        PTItem item = pt_ring[slot];
        pt_tail++;
        twist(pt_have, BY, -1);

        possess(pt_space);
        twist(pt_space, BY, +1);

        /* Check sentinel */
        if (item.nnodes == -1)
            break;

        /* Expand into guesses */
        expand_item(Gen, item.nodes, item.nnodes, 0, buf, 0, &wo);

        free(item.nodes);
    }

    /* Flush remaining output */
    worker_flush(&wo);

    /* Add to total */
    possess(guess_lock);
    total_guesses_atomic += wo.count;
    twist(guess_lock, TO, peek_lock(guess_lock));

    /* If last worker, signal writer to stop */
    possess(workers_alive);
    long remaining = peek_lock(workers_alive) - 1;
    if (remaining <= 0) {
        twist(workers_alive, TO, 0);
        signal_writer_done();
    } else {
        twist(workers_alive, TO, remaining);
    }

    if (wo.buf) free(wo.buf);
    free(buf);
}

/* ---- Writer thread ---- */
static void gen_writer(void *arg) {
    (void)arg;
    while (1) {
        possess(out_have);
        wait_for(out_have, NOT_TO_BE, 0);
        int slot = out_tail % OUT_RING_SIZE;
        OutBatch *ob = &out_ring[slot];
        /* Sentinel: NULL buf means stop */
        if (ob->buf == NULL) {
            out_tail++;
            twist(out_have, BY, -1);
            break;
        }
        fwrite(ob->buf, 1, ob->pos, stdout);
        free(ob->buf);
        ob->buf = NULL;
        out_tail++;
        twist(out_have, BY, -1);

        possess(out_space);
        twist(out_space, BY, +1);
    }
}

/* Send sentinel to writer */
static void signal_writer_done(void) {
    possess(out_space);
    wait_for(out_space, NOT_TO_BE, 0);
    int slot = out_head % OUT_RING_SIZE;
    out_ring[slot].buf = NULL;
    out_ring[slot].pos = 0;
    out_head++;
    twist(out_space, BY, -1);
    possess(out_have);
    twist(out_have, BY, +1);
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

/* ---- Main generation ---- */
int pcfg_generate(const char *grammardir, GenCtx *ctx) {
    if (pcfg_load(grammardir, ctx) < 0)
        return 1;

    add_case_mangling(ctx->bases, ctx->nbases);
    seed_queue(ctx);

    Gen = ctx;
    gen_done = 0;
    total_guesses_atomic = 0;

    int nworkers = ctx->nthreads;
    if (nworkers < 1) nworkers = 1;

    /* Single-threaded mode for small runs or debug */
    if (ctx->debug || nworkers == 1) {
        struct timespec t0;
        clock_gettime(CLOCK_MONOTONIC, &t0);

        int64_t total = 0, pt_count = 0;
        static char buf[PCFG_MAXLINE];
        WorkerOut wo;
        wo.buf = malloc(OUTBUF_SIZE);
        wo.pos = 0;
        wo.cap = OUTBUF_SIZE;
        wo.count = 0;

        PTItem item;
        while (pq_pop(&ctx->queue, &item)) {
            pt_count++;
            if (ctx->debug) debug_print_pt(ctx, &item);

            expand_item(ctx, item.nodes, item.nnodes, 0, buf, 0, &wo);
            total += wo.count;
            wo.count = 0;

            /* Flush output */
            if (wo.pos > 0) {
                fwrite(wo.buf, 1, wo.pos, stdout);
                wo.pos = 0;
            }

            int nchildren;
            PTItem *children = find_children(ctx, &item, &nchildren);
            for (int i = 0; i < nchildren; i++)
                pq_push(&ctx->queue, &children[i]);
            free(children);
            free(item.nodes);

            if (ctx->guess_limit > 0 && total >= ctx->guess_limit)
                break;
        }
        if (wo.pos > 0)
            fwrite(wo.buf, 1, wo.pos, stdout);

        struct timespec tend;
        clock_gettime(CLOCK_MONOTONIC, &tend);
        double elapsed = (tend.tv_sec - t0.tv_sec) + (tend.tv_nsec - t0.tv_nsec) / 1e9;
        fprintf(stderr, "\rpcfg: done. %" PRId64 " guesses in %.2fs (%.1fM/s)\n",
                total, elapsed, elapsed > 0 ? total / elapsed / 1e6 : 0.0);
        pq_free(&ctx->queue);
        return 0;
    }

    /* ---- Parallel pipeline ---- */
    fprintf(stderr, "pcfg: generating with %d worker threads\n", nworkers);

    /* Allocate rings */
    pt_ring = calloc(PT_RING_SIZE, sizeof(PTItem));
    pt_head = pt_tail = 0;
    pt_have = new_lock(0);
    pt_space = new_lock(PT_RING_SIZE);

    out_ring = calloc(OUT_RING_SIZE, sizeof(OutBatch));
    out_head = out_tail = 0;
    out_have = new_lock(0);
    out_space = new_lock(OUT_RING_SIZE);

    guess_lock = new_lock(0);
    workers_alive = new_lock(nworkers);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    /* Launch writer */
    launch(gen_writer, NULL);

    /* Launch workers */
    for (int i = 0; i < nworkers; i++)
        launch(gen_worker, NULL);

    /* Popper: runs on main thread */
    int64_t pt_count = 0;
    PTItem item;
    struct timespec tlast = t0;

    while (pq_pop(&ctx->queue, &item)) {
        pt_count++;

        /* Push item to worker ring */
        possess(pt_space);
        wait_for(pt_space, NOT_TO_BE, 0);
        int slot = pt_head % PT_RING_SIZE;
        /* Copy nodes for the worker (worker will free) */
        pt_ring[slot] = item;
        pt_head++;
        twist(pt_space, BY, -1);

        possess(pt_have);
        twist(pt_have, BY, +1);

        /* Generate children and push to queue */
        int nchildren;
        PTItem *children = find_children(ctx, &item, &nchildren);
        for (int i = 0; i < nchildren; i++)
            pq_push(&ctx->queue, &children[i]);
        free(children);

        /* Check limit */
        if (ctx->guess_limit > 0) {
            possess(guess_lock);
            int64_t cur = total_guesses_atomic;
            release(guess_lock);
            if (cur >= ctx->guess_limit) break;
        }

        /* Progress */
        if ((pt_count & 0x3FFF) == 0) {
            struct timespec tnow;
            clock_gettime(CLOCK_MONOTONIC, &tnow);
            double elapsed = (tnow.tv_sec - tlast.tv_sec) +
                             (tnow.tv_nsec - tlast.tv_nsec) / 1e9;
            if (elapsed >= 2.0) {
                possess(guess_lock);
                int64_t cur = total_guesses_atomic;
                release(guess_lock);
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

    /* Signal workers we're done — send sentinel per worker */
    gen_done = 1;
    for (int i = 0; i < nworkers; i++) {
        possess(pt_space);
        wait_for(pt_space, NOT_TO_BE, 0);
        int slot = pt_head % PT_RING_SIZE;
        memset(&pt_ring[slot], 0, sizeof(PTItem));
        pt_ring[slot].nnodes = -1;  /* sentinel */
        pt_head++;
        twist(pt_space, BY, -1);
        possess(pt_have);
        twist(pt_have, BY, +1);
    }

    /* Workers exit on sentinel, last worker signals writer, writer exits.
     * join_all() waits for all of them. */
    join_all();

    struct timespec tend;
    clock_gettime(CLOCK_MONOTONIC, &tend);
    double total_elapsed = (tend.tv_sec - t0.tv_sec) +
                           (tend.tv_nsec - t0.tv_nsec) / 1e9;
    fprintf(stderr, "\rpcfg: done. %" PRId64 " guesses in %.2fs (%.1fM/s)\n",
            total_guesses_atomic, total_elapsed,
            total_elapsed > 0 ? total_guesses_atomic / total_elapsed / 1e6 : 0.0);

    free(pt_ring);
    free(out_ring);
    free_lock(pt_have);
    free_lock(pt_space);
    free_lock(out_have);
    free_lock(out_space);
    free_lock(guess_lock);
    free_lock(workers_alive);
    pq_free(&ctx->queue);
    return 0;
}
