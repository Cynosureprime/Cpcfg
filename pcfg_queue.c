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

/* ---- Compute probability for a parse tree ---- */
double find_prob(GenCtx *ctx, PTNode *nodes, int nnodes, double base_prob) {
    double prob = base_prob;
    Word_t *pv;

    for (int i = 0; i < nnodes; i++) {
        JSLG(pv, ctx->grammar, (uint8_t *)nodes[i].type);
        if (!pv) return 0.0;
        GrammarEntryList *gel = (GrammarEntryList *)*pv;
        if (nodes[i].index >= gel->nentries) return 0.0;
        prob *= gel->entries[nodes[i].index].prob;
    }
    return prob;
}

/* ---- Get number of entries for a type ---- */
static int type_entry_count(GenCtx *ctx, const char *type) {
    Word_t *pv;
    JSLG(pv, ctx->grammar, (uint8_t *)type);
    if (!pv) return 0;
    GrammarEntryList *gel = (GrammarEntryList *)*pv;
    return gel->nentries;
}

/* ---- areYouMyChild: pruning check ----
 * Ensures that a candidate child's "virtual parents" at other positions
 * have already been explored.
 */
int are_you_my_child(GenCtx *ctx, PTNode *child, int nnodes,
                     double base_prob, int parent_pos, double parent_prob) {
    for (int pos = 0; pos < nnodes; pos++) {
        if (pos == parent_pos) continue;
        if (child[pos].index == 0) continue;

        /* Temporarily decrement to compute virtual parent probability */
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

/* ---- findChildren: generate successor parse trees ---- */
PTItem *find_children(GenCtx *ctx, PTItem *parent, int *nchildren) {
    PTItem *children = malloc(parent->nnodes * sizeof(PTItem));
    int nc = 0;

    for (int pos = 0; pos < parent->nnodes; pos++) {
        int max_idx = type_entry_count(ctx, parent->nodes[pos].type);
        if (parent->nodes[pos].index + 1 >= max_idx)
            continue;  /* Already at last entry */

        /* Create child by incrementing index at this position */
        PTNode *cnodes = malloc(parent->nnodes * sizeof(PTNode));
        memcpy(cnodes, parent->nodes, parent->nnodes * sizeof(PTNode));
        cnodes[pos].index++;

        /* Pruning check */
        if (!are_you_my_child(ctx, cnodes, parent->nnodes,
                              parent->base_prob, pos, parent->prob)) {
            free(cnodes);
            continue;
        }

        double cprob = find_prob(ctx, cnodes, parent->nnodes, parent->base_prob);

        children[nc].prob = cprob;
        children[nc].base_prob = parent->base_prob;
        children[nc].nodes = cnodes;
        children[nc].nnodes = parent->nnodes;
        children[nc].seq = 0;  /* Will be set by pq_push */
        nc++;
    }

    *nchildren = nc;
    return children;
}
