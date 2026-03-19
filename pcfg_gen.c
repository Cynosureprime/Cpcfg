/*
 * pcfg_gen.c - Guess generation
 *
 * Phase 1: Single-threaded popper + inline expansion.
 * Phase 4 will add ring buffer pipeline with worker threads.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>

#include "pcfg.h"
#include "yarn.h"

/* ---- Output buffer ---- */
#define OUTBUF_SIZE (1024 * 1024)

typedef struct {
    char buf[OUTBUF_SIZE];
    int  pos;
} OutBuf;

static OutBuf outbuf;

static void flush_output(void) {
    if (outbuf.pos > 0) {
        fwrite(outbuf.buf, 1, outbuf.pos, stdout);
        outbuf.pos = 0;
    }
}

static inline void emit_guess(const char *guess, int len) {
    if (outbuf.pos + len + 1 >= OUTBUF_SIZE)
        flush_output();
    memcpy(outbuf.buf + outbuf.pos, guess, len);
    outbuf.pos += len;
    outbuf.buf[outbuf.pos++] = '\n';
}

/* ---- Apply case mask to alpha string ---- */
static void apply_case_mask(const char *alpha, const char *mask, int len,
                            char *out) {
    for (int i = 0; i < len; i++) {
        if (mask[i] == 'U')
            out[i] = toupper((unsigned char)alpha[i]);
        else
            out[i] = tolower((unsigned char)alpha[i]);
    }
}

/* ---- Recursive guess expansion ----
 * Expands a parse tree item into actual password guesses.
 * Returns number of guesses generated.
 */
static int64_t expand_item(GenCtx *ctx, PTNode *nodes, int nnodes,
                           int node_idx, char *buf, int bufpos) {
    if (node_idx >= nnodes) {
        /* All nodes consumed — emit the guess */
        if (ctx->debug) {
            /* Debug: print parse tree representation */
            /* Already printed before expand */
        }
        emit_guess(buf, bufpos);
        return 1;
    }

    PTNode *node = &nodes[node_idx];
    char type_char = node->type[0];

    /* Look up grammar entries */
    Word_t *pv;
    JSLG(pv, ctx->grammar, (uint8_t *)node->type);
    if (!pv) return 0;

    GrammarEntryList *gel = (GrammarEntryList *)*pv;
    if (node->index >= gel->nentries) return 0;
    GrammarEntry *ge = &gel->entries[node->index];

    int64_t count = 0;

    if (type_char == ST_CASE) {
        /* Capitalization: apply mask to the preceding alpha section already in buf */
        /* The mask is the first value in the entry */
        for (int v = 0; v < ge->nvalues; v++) {
            char *mask = ge->values[v];
            int mlen = strlen(mask);

            /* Apply mask to last mlen characters of buf */
            if (mlen > bufpos) mlen = bufpos;
            char saved[PCFG_MAXLINE];
            memcpy(saved, buf + bufpos - mlen, mlen);

            apply_case_mask(saved, mask, mlen, buf + bufpos - mlen);
            count += expand_item(ctx, nodes, nnodes, node_idx + 1, buf, bufpos);

            /* Restore original (for next mask value) */
            memcpy(buf + bufpos - mlen, saved, mlen);
        }
    } else if (type_char == ST_MARKOV) {
        /* OMEN/Markov — Phase 5 */
        return 0;
    } else {
        /* Normal terminal: A, D, O, K, X, Y, E, W — concatenate value */
        for (int v = 0; v < ge->nvalues; v++) {
            int vlen = strlen(ge->values[v]);
            if (bufpos + vlen >= PCFG_MAXLINE) continue;

            memcpy(buf + bufpos, ge->values[v], vlen);
            count += expand_item(ctx, nodes, nnodes, node_idx + 1,
                                 buf, bufpos + vlen);
        }
    }

    return count;
}

/* ---- Debug: print parse tree ---- */
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

/* ---- Seed the priority queue with initial parse trees ---- */
static void seed_queue(GenCtx *ctx) {
    pq_init(&ctx->queue, ctx->nbases * 2);

    for (int i = 0; i < ctx->nbases; i++) {
        BaseStructure *bs = &ctx->bases[i];
        if (bs->nreplace <= 0) continue;

        /* Check all types exist in grammar */
        int valid = 1;
        for (int j = 0; j < bs->nreplace; j++) {
            Word_t *pv;
            JSLG(pv, ctx->grammar, (uint8_t *)bs->replacements[j]);
            if (!pv) { valid = 0; break; }
            GrammarEntryList *gel = (GrammarEntryList *)*pv;
            if (gel->nentries <= 0) { valid = 0; break; }
        }
        if (!valid) continue;

        /* Create initial PTItem with all indices at 0 */
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

/* ---- Add case mangling: insert C{len} after each A{len} in base structures ---- */
static void add_case_mangling(BaseStructure *bases, int nbases) {
    for (int i = 0; i < nbases; i++) {
        BaseStructure *bs = &bases[i];
        /* Count how many A entries to know new size */
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
                /* Add C{len} with same length as A{len} */
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

/* ---- Main generation loop ---- */
int pcfg_generate(const char *ruledir, GenCtx *ctx) {
    /* Load grammar */
    if (pcfg_load(ruledir, ctx) < 0)
        return 1;

    /* Add C entries to base structures (matching Go's addCaseMangling) */
    add_case_mangling(ctx->bases, ctx->nbases);

    /* Seed priority queue */
    seed_queue(ctx);

    outbuf.pos = 0;
    struct timespec t0, tlast;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    tlast = t0;

    int64_t total_guesses = 0;
    int64_t pt_count = 0;
    static char buf[PCFG_MAXLINE];

    /* Pop loop */
    PTItem item;
    while (pq_pop(&ctx->queue, &item)) {
        pt_count++;

        if (ctx->debug)
            debug_print_pt(ctx, &item);

        /* Expand this parse tree into guesses */
        int64_t ng = expand_item(ctx, item.nodes, item.nnodes, 0, buf, 0);
        total_guesses += ng;

        /* Generate children and push to queue */
        int nchildren;
        PTItem *children = find_children(ctx, &item, &nchildren);
        for (int i = 0; i < nchildren; i++)
            pq_push(&ctx->queue, &children[i]);
        free(children);

        /* Free parent nodes */
        free(item.nodes);

        /* Check limit */
        if (ctx->guess_limit > 0 && total_guesses >= ctx->guess_limit)
            break;

        /* Progress reporting every ~2 seconds */
        if ((pt_count & 0x3FFF) == 0) {
            struct timespec tnow;
            clock_gettime(CLOCK_MONOTONIC, &tnow);
            double elapsed = (tnow.tv_sec - tlast.tv_sec) +
                             (tnow.tv_nsec - tlast.tv_nsec) / 1e9;
            if (elapsed >= 2.0) {
                double total_elapsed = (tnow.tv_sec - t0.tv_sec) +
                                       (tnow.tv_nsec - t0.tv_nsec) / 1e9;
                double rate = total_guesses / total_elapsed;
                fprintf(stderr, "\rpcfg: %" PRId64 " guesses (%" PRId64 " PTs) "
                        "%.1fM/s prob=%.4e q=%d  ",
                        total_guesses, pt_count, rate / 1e6,
                        item.prob, ctx->queue.size);
                tlast = tnow;
            }
        }
    }

    flush_output();

    struct timespec tend;
    clock_gettime(CLOCK_MONOTONIC, &tend);
    double total_elapsed = (tend.tv_sec - t0.tv_sec) +
                           (tend.tv_nsec - t0.tv_nsec) / 1e9;
    fprintf(stderr, "\rpcfg: done. %" PRId64 " guesses in %.2fs (%.1fM/s)\n",
            total_guesses, total_elapsed,
            total_elapsed > 0 ? total_guesses / total_elapsed / 1e6 : 0.0);

    pq_free(&ctx->queue);
    return 0;
}
