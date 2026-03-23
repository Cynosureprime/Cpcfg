/*
 * pcfg_queue.c - Priority queue (binary max-heap) for guess generation
 *
 * Implements the critical findChildren / areYouMyChild algorithm
 * that ensures each parse tree configuration is explored exactly once
 * in probability-descending order.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "pcfg.h"

/* ---- Priority Queue (binary max-heap) ---- */

void pq_init(PQueue *pq, int initial_cap) {
    pq->cap = initial_cap > 16 ? initial_cap : 16;
    pq->items = malloc(pq->cap * sizeof(PTItem));
    if (!pq->items) {
        fprintf(stderr, "pcfg: queue OOM\n");
        exit(1);
    }
    pq->size = 0;
    pq->next_seq = 0;
}

static inline int pq_cmp(PTItem *a, PTItem *b) {
    /* Max-heap: higher probability first. Tie-break by lower seq (earlier). */
    if (a->prob > b->prob) return -1;
    if (a->prob < b->prob) return 1;
    if (a->seq < b->seq) return -1;
    if (a->seq > b->seq) return 1;
    return 0;
}

static void pq_swap(PQueue *pq, int i, int j) {
    PTItem tmp = pq->items[i];
    pq->items[i] = pq->items[j];
    pq->items[j] = tmp;
}

static void pq_sift_up(PQueue *pq, int i) {
    while (i > 0) {
        int parent = (i - 1) / 2;
        if (pq_cmp(&pq->items[i], &pq->items[parent]) < 0) {
            pq_swap(pq, i, parent);
            i = parent;
        } else break;
    }
}

static void pq_sift_down(PQueue *pq, int i) {
    int n = pq->size;
    while (1) {
        int best = i;
        int left = 2 * i + 1;
        int right = 2 * i + 2;

        if (left < n && pq_cmp(&pq->items[left], &pq->items[best]) < 0)
            best = left;
        if (right < n && pq_cmp(&pq->items[right], &pq->items[best]) < 0)
            best = right;

        if (best == i) break;
        pq_swap(pq, i, best);
        i = best;
    }
}

void pq_push(PQueue *pq, PTItem *item) {
    if (pq->size >= pq->cap) {
        pq->cap *= 2;
        pq->items = realloc(pq->items, pq->cap * sizeof(PTItem));
        if (!pq->items) {
            fprintf(stderr, "pcfg: queue OOM\n");
            exit(1);
        }
    }

    item->seq = pq->next_seq++;
    pq->items[pq->size] = *item;
    pq_sift_up(pq, pq->size);
    pq->size++;
}

int pq_pop(PQueue *pq, PTItem *out) {
    if (pq->size <= 0) return 0;

    *out = pq->items[0];
    pq->size--;
    if (pq->size > 0) {
        pq->items[0] = pq->items[pq->size];
        pq_sift_down(pq, 0);
    }
    return 1;
}

int pq_empty(PQueue *pq) {
    return pq->size <= 0;
}

void pq_free(PQueue *pq) {
    if (pq->items) {
        for (int i = 0; i < pq->size; i++) {
            free(pq->items[i].nodes);
        }
        free(pq->items);
        pq->items = NULL;
    }
    pq->size = pq->cap = 0;
}

/* ---- Resolve cached GEL pointer ---- */
static inline GrammarEntryList *get_gel(GenCtx *ctx, PTNode *node) {
    if (node->gel_cache) return (GrammarEntryList *)node->gel_cache;
    Word_t *pv;
    JSLG(pv, ctx->grammar, (uint8_t *)node->type);
    if (!pv) return NULL;
    node->gel_cache = (void *)*pv;
    return (GrammarEntryList *)node->gel_cache;
}

/* ---- Compute probability for a parse tree ---- */
double find_prob(GenCtx *ctx, PTNode *nodes, int nnodes, double base_prob) {
    double prob = base_prob;
    for (int i = 0; i < nnodes; i++) {
        GrammarEntryList *gel = get_gel(ctx, &nodes[i]);
        if (!gel || nodes[i].index >= gel->nentries) return 0.0;
        prob *= gel->entries[nodes[i].index].prob;
    }
    return prob;
}

/* ---- areYouMyChild: pruning check ----
 * Uses scratch buffer (already a copy of parent nodes with index incremented).
 * Temporarily decrements other positions to check virtual parent probabilities.
 */
static int are_you_my_child(GenCtx *ctx, PTNode *child, int nnodes,
                     double base_prob, int parent_pos, double parent_prob) {
    for (int pos = 0; pos < nnodes; pos++) {
        if (pos == parent_pos) continue;
        if (child[pos].index == 0) continue;

        child[pos].index--;
        double vprob = find_prob(ctx, child, nnodes, base_prob);
        child[pos].index++;

        if (vprob < parent_prob)
            return 0;
        if (vprob == parent_prob && pos < parent_pos)
            return 0;
    }
    return 1;
}

/* ---- findChildren: generate successor parse trees ----
 * Uses caller-provided stack buffer to avoid malloc per call.
 * Only allocates (via malloc) for children that pass the pruning check.
 */
#define MAX_PT_NODES 64
int find_children(GenCtx *ctx, PTItem *parent, PTItem *children) {
    int nc = 0;
    int nn = parent->nnodes;
    PTNode scratch[MAX_PT_NODES];

    for (int pos = 0; pos < nn; pos++) {
        GrammarEntryList *gel = get_gel(ctx, &parent->nodes[pos]);
        if (!gel || parent->nodes[pos].index + 1 >= gel->nentries)
            continue;

        /* Build candidate in scratch buffer */
        memcpy(scratch, parent->nodes, nn * sizeof(PTNode));
        scratch[pos].index++;

        if (!are_you_my_child(ctx, scratch, nn,
                              parent->base_prob, pos, parent->prob))
            continue;

        double cprob = find_prob(ctx, scratch, nn, parent->base_prob);

        /* Only malloc for accepted children */
        PTNode *cnodes = malloc(nn * sizeof(PTNode));
        memcpy(cnodes, scratch, nn * sizeof(PTNode));

        children[nc].prob = cprob;
        children[nc].base_prob = parent->base_prob;
        children[nc].nodes = cnodes;
        children[nc].nnodes = nn;
        children[nc].seq = 0;
        nc++;
    }

    return nc;
}
