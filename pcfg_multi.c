/*
 * pcfg_multi.c - Multiword trie for splitting long alpha runs
 *
 * Learns word frequencies from passwords during a first training pass.
 * During parsing, attempts to split long alpha runs (8-21 chars) into
 * known words (each with count >= threshold).
 *
 * Algorithm: greedy left-to-right, try longest front piece first,
 * recursively split remainder.
 */

#include <stdlib.h>
#include <string.h>

#include "pcfg.h"

/* Use UTF-8 functions from pcfg_utf8.c for classification */

#define TRIE_CHILDREN 128   /* ASCII range */

typedef struct TrieNode {
    struct TrieNode *children[TRIE_CHILDREN];
    int count;
    int has_count;
} TrieNode;

/* Matches forward declaration in pcfg.h: typedef struct MultiWordTrie MultiWordTrie */
struct MultiWordTrie {
    TrieNode *root;
    int threshold;
    int min_len;
    int max_len;
    int min_check_len;  /* min_len * 2 */
};

/* ---- Trie node pool: bulk allocation to avoid per-node calloc ---- */
#define TRIE_POOL_CHUNK 16384

static TrieNode *trie_pool = NULL;
static int trie_pool_used = TRIE_POOL_CHUNK;  /* force alloc on first call */

static TrieNode *trie_new_node(void) {
    if (trie_pool_used >= TRIE_POOL_CHUNK) {
        trie_pool = calloc(TRIE_POOL_CHUNK, sizeof(TrieNode));
        trie_pool_used = 0;
    }
    return &trie_pool[trie_pool_used++];
}

MultiWordTrie *multiword_new(int threshold, int min_len, int max_len) {
    MultiWordTrie *mw = malloc(sizeof(MultiWordTrie));
    mw->root = trie_new_node();
    mw->threshold = threshold;
    mw->min_len = min_len;
    mw->max_len = max_len;
    mw->min_check_len = min_len * 2;
    return mw;
}

static void trie_free_node(TrieNode *n) {
    if (!n) return;
    for (int i = 0; i < TRIE_CHILDREN; i++)
        trie_free_node(n->children[i]);
    free(n);
}

void multiword_free(MultiWordTrie *mw) {
    if (!mw) return;
    trie_free_node(mw->root);
    free(mw);
}

/* Train: add word runs from a password to the trie.
 * Trie keys are lowered UTF-8 byte sequences.
 * run_len counts codepoints for min/max length checks. */
void multiword_train(MultiWordTrie *mw, const char *pw, int pwlen) {
    TrieNode *cur = mw->root;
    int run_len = 0;  /* codepoint count */

    int i = 0;
    while (i <= pwlen) {
        uint32_t cp = 0;
        int cpn = 0;
        if (i < pwlen) {
            cpn = utf8_decode(pw + i, pwlen - i, &cp);
            if (cpn == 0) { i++; continue; }
        }

        if (i < pwlen && utf8_is_alpha(cp)) {
            /* Insert lowered UTF-8 bytes into trie */
            uint32_t lcp = utf8_to_lower(cp);
            char enc[4];
            int elen = utf8_encode(enc, lcp);
            for (int b = 0; b < elen; b++) {
                unsigned char c = (unsigned char)enc[b];
                if (c < TRIE_CHILDREN) {
                    if (!cur->children[c])
                        cur->children[c] = trie_new_node();
                    cur = cur->children[c];
                }
            }
            run_len++;
            i += cpn;
        } else {
            /* End of letter run (non-alpha or end of string) */
            if (run_len >= mw->min_len && run_len <= mw->max_len) {
                if (!cur->has_count) {
                    cur->count = 1;
                    cur->has_count = 1;
                } else {
                    cur->count++;
                }
            }
            cur = mw->root;
            run_len = 0;
            if (i < pwlen) i += cpn; else i++;
        }
    }
}

/* Get count for a word in the trie */
static int trie_get_count(MultiWordTrie *mw, const char *word, int len) {
    TrieNode *cur = mw->root;
    int i = 0;
    while (i < len) {
        uint32_t cp;
        int n = utf8_decode(word + i, len - i, &cp);
        if (n == 0) break;
        uint32_t lcp = utf8_to_lower(cp);
        char enc[4];
        int elen = utf8_encode(enc, lcp);
        for (int b = 0; b < elen; b++) {
            unsigned char c = (unsigned char)enc[b];
            if (c >= TRIE_CHILDREN || !cur->children[c])
                return 0;
            cur = cur->children[c];
        }
        i += n;
    }
    return cur->has_count ? cur->count : 0;
}

/* Recursive split: try to split alpha string into known words */
#define MAX_MULTI_PARTS 8

static int identify_multi(MultiWordTrie *mw, const char *s, int slen,
                          int *splits, int *nsplits) {
    /* Try split points from longest front piece down to min_len */
    int max_front = slen - mw->min_len;

    for (int front_len = max_front; front_len >= mw->min_len; front_len--) {
        if (trie_get_count(mw, s, front_len) < mw->threshold)
            continue;

        int back_len = slen - front_len;

        /* Check if back is a known word */
        if (back_len >= mw->min_len &&
            trie_get_count(mw, s + front_len, back_len) >= mw->threshold) {
            splits[*nsplits] = front_len;
            (*nsplits)++;
            splits[*nsplits] = back_len;
            (*nsplits)++;
            return 1;
        }

        /* Try recursive split on back */
        if (back_len >= mw->min_check_len) {
            int saved = *nsplits;
            splits[*nsplits] = front_len;
            (*nsplits)++;
            if (identify_multi(mw, s + front_len, back_len, splits, nsplits))
                return 1;
            *nsplits = saved;  /* backtrack */
        }
    }
    return 0;
}

/*
 * multiword_parse - Try to split an alpha string into multiple known words.
 *
 * Returns number of parts (1 = no split, >1 = multi-word).
 * Fills parts[] with lengths of each part, left to right.
 */
int multiword_parse(MultiWordTrie *mw, const char *alpha, int alen,
                    int *parts, int max_parts) {
    (void)max_parts;
    if (!mw) return 0;
    if (alen < mw->min_len || alen > mw->max_len) return 0;

    /* Check if entire string is a known word */
    if (trie_get_count(mw, alpha, alen) >= mw->threshold) {
        parts[0] = alen;
        return 1;
    }

    /* Don't try splitting strings shorter than 2*min_len */
    if (alen < mw->min_check_len) return 0;

    /* Try recursive split */
    int nsplits = 0;
    if (identify_multi(mw, alpha, alen, parts, &nsplits)) {
        return nsplits;
    }

    return 0;
}
