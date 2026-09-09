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
    int64_t count;
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
 * Trie keys are lowered UTF-8 byte sequences with leet chars folded to
 * their base letters, matching pcfg_parse's alpha handling.  Runs are
 * trimmed so they start and end with a true letter: a leet char only
 * belongs to a word when it sits between letters.
 * main thread only — the static run buffer needs no locking. */
void multiword_train_n(MultiWordTrie *mw, const char *pw, int pwlen, int64_t n) {
    static char runbuf[PCFG_MAXLINE];
    int runlen = 0;          /* bytes buffered for the current run */
    int first_letter = -1;   /* byte offset of first true letter, -1 = none */
    int last_letter_end = 0; /* byte offset just past the last true letter */

    int i = 0;
    while (i <= pwlen) {
        uint32_t cp = 0;
        int cpn = 0;
        int at_end = (i >= pwlen);
        if (!at_end) {
            cpn = utf8_decode(pw + i, pwlen - i, &cp);
            if (cpn == 0) { i++; continue; }
        }

        int is_letter = !at_end && utf8_is_alpha(cp);
        int is_leet = !at_end && !is_letter && cpn == 1 &&
                      leet_fold[(unsigned char)pw[i]] != 0;

        if (is_letter || is_leet) {
            if (runlen + cpn < PCFG_MAXLINE) {
                memcpy(runbuf + runlen, pw + i, cpn);
                if (is_letter) {
                    if (first_letter < 0) first_letter = runlen;
                    last_letter_end = runlen + cpn;
                }
                runlen += cpn;
            }
            i += cpn;
        } else {
            /* Run ended — insert the trimmed [first_letter, last_letter_end)
             * region, lowered and folded. */
            if (first_letter >= 0 && last_letter_end - first_letter > 0) {
                int len = last_letter_end - first_letter;
                TrieNode *cur = mw->root;
                int si = first_letter;
                int word_cps = 0;
                while (si < first_letter + len) {
                    uint32_t c2;
                    int n2 = utf8_decode(runbuf + si, first_letter + len - si, &c2);
                    if (n2 == 0) break;
                    uint32_t lcp = (n2 == 1 && leet_fold[(unsigned char)runbuf[si]])
                                   ? leet_fold[(unsigned char)runbuf[si]]
                                   : utf8_to_lower(c2);
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
                    si += n2;
                    word_cps++;
                }
                if (cur != mw->root &&
                    word_cps >= mw->min_len && word_cps <= mw->max_len) {
                    if (!cur->has_count) {
                        cur->count = n;
                        cur->has_count = 1;
                    } else {
                        cur->count += n;
                    }
                }
            }
            runlen = 0;
            first_letter = -1;
            last_letter_end = 0;
            if (at_end) i++;
            else i += cpn;
        }
    }
}

void multiword_train(MultiWordTrie *mw, const char *pw, int pwlen) {
    multiword_train_n(mw, pw, pwlen, 1);
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
