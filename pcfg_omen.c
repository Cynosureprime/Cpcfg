/*
 * pcfg_omen.c - OMEN Markov chain training and generation
 *
 * Trains n-gram frequency tables (IP, EP, CP) on passwords using
 * a restricted alphabet. Produces level-based probability assignments
 * that integrate with the PCFG grammar as the "M" (Markov) entry.
 *
 * Training outputs:
 *   Omen/config.txt       - alphabet + ngram config
 *   Omen/alphabet.txt     - the alphabet characters
 *   Omen/IP.level         - initial prefix levels
 *   Omen/EP.level         - end prefix levels
 *   Omen/CP.level         - continuation prefix levels
 *   Omen/LN.level         - length levels
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <ctype.h>
#include <sys/stat.h>

#include "pcfg.h"

#define OMEN_MAX_LEVEL  10
#define OMEN_MIN_LEN    4
#define OMEN_MAX_LEN    24

/* OMEN context: n-gram entry */
typedef struct OmenCtx {
    int ip_count, ip_level;     /* initial prefix */
    int ep_count, ep_level;     /* end prefix */
    int cp_count;               /* total continuation count */
    int next_count[256];        /* per-char continuation counts */
    int next_level[256];        /* per-char continuation levels */
} OmenCtx;

/* OMEN trainer state */
struct OmenTrainer {
    int ngram;                  /* n-gram size (default 4) */
    int alphabet_size;          /* max chars in alphabet */
    char *alphabet;             /* the alphabet string */
    int alpha_map[256];         /* char → index (-1 if not in alphabet) */
    int ln_count[OMEN_MAX_LEN + 1]; /* length frequency */
    int ln_level[OMEN_MAX_LEN + 1]; /* smoothed length levels */
    Pvoid_t contexts;           /* JudySL: prefix_string → OmenCtx* */
    int total_ip;
    int total_ep;
};

/* ---- Create OMEN trainer ---- */
OmenTrainer *omen_new(int ngram, int alphabet_size) {
    OmenTrainer *ot = calloc(1, sizeof(OmenTrainer));
    ot->ngram = ngram;
    ot->alphabet_size = alphabet_size;
    ot->alphabet = NULL;
    memset(ot->alpha_map, -1, sizeof(ot->alpha_map));
    ot->contexts = NULL;
    return ot;
}

/* ---- Build alphabet from character frequency ---- */
void omen_build_alphabet(OmenTrainer *ot, Counter char_freq) {
    /* Collect all chars with their counts */
    typedef struct { unsigned char ch; int64_t count; } CharEntry;
    CharEntry *entries = NULL;
    int nentries = 0, cap = 256;
    entries = malloc(cap * sizeof(CharEntry));

    uint8_t idx[8];
    Word_t *pv;
    idx[0] = '\0';
    JSLF(pv, char_freq, idx);
    while (pv) {
        if (nentries >= cap) { cap *= 2; entries = realloc(entries, cap * sizeof(CharEntry)); }
        entries[nentries].ch = idx[0];
        entries[nentries].count = (int64_t)*pv;
        nentries++;
        JSLN(pv, char_freq, idx);
    }

    /* Sort by count descending */
    for (int i = 0; i < nentries - 1; i++)
        for (int j = i + 1; j < nentries; j++)
            if (entries[j].count > entries[i].count) {
                CharEntry tmp = entries[i]; entries[i] = entries[j]; entries[j] = tmp;
            }

    /* Take top alphabet_size */
    int n = nentries < ot->alphabet_size ? nentries : ot->alphabet_size;
    ot->alphabet = malloc(n + 1);
    for (int i = 0; i < n; i++) {
        ot->alphabet[i] = entries[i].ch;
        ot->alpha_map[(unsigned char)entries[i].ch] = i;
    }
    ot->alphabet[n] = '\0';
    free(entries);
}

/* Check if all chars of a string are in the alphabet */
static int in_alphabet(OmenTrainer *ot, const char *s, int len) {
    for (int i = 0; i < len; i++)
        if (ot->alpha_map[(unsigned char)s[i]] < 0) return 0;
    return 1;
}

/* Get or create context for a prefix */
static OmenCtx *get_context(OmenTrainer *ot, const char *prefix, int plen) {
    char key[16];
    memcpy(key, prefix, plen);
    key[plen] = '\0';

    Word_t *pv;
    JSLI(pv, ot->contexts, (uint8_t *)key);
    if (*pv == 0) {
        OmenCtx *ctx = calloc(1, sizeof(OmenCtx));
        *pv = (Word_t)ctx;
    }
    return (OmenCtx *)*pv;
}

/* ---- Train one password ---- */
void omen_train(OmenTrainer *ot, const char *pw, int pwlen) {
    if (pwlen < OMEN_MIN_LEN || pwlen > OMEN_MAX_LEN) return;
    if (!ot->alphabet) return;
    if (!in_alphabet(ot, pw, pwlen)) return;

    int prefix_len = ot->ngram - 1;
    ot->ln_count[pwlen]++;

    for (int i = 0; i <= pwlen - prefix_len; i++) {
        if (!in_alphabet(ot, pw + i, prefix_len)) continue;

        OmenCtx *ctx = get_context(ot, pw + i, prefix_len);

        if (i == 0) {
            ctx->ip_count++;
            ot->total_ip++;
        }

        if (i + prefix_len < pwlen) {
            unsigned char next = (unsigned char)pw[i + prefix_len];
            if (ot->alpha_map[next] >= 0) {
                ctx->next_count[next]++;
                ctx->cp_count++;
            }
        } else {
            ctx->ep_count++;
            ot->total_ep++;
        }
    }
}

/* ---- Smoothing: convert counts to levels ---- */
static int calc_level(int base_count, int total_count, double adjust) {
    if (total_count == 0 || base_count == 0) return OMEN_MAX_LEVEL;
    double prob = ((double)base_count / (double)total_count) * adjust + 1e-11;
    int level = (int)floor(-log(prob));
    if (level < 0) level = 0;
    if (level > OMEN_MAX_LEVEL) level = OMEN_MAX_LEVEL;
    return level;
}

void omen_smooth(OmenTrainer *ot) {
    uint8_t idx[16];
    Word_t *pv;

    idx[0] = '\0';
    JSLF(pv, ot->contexts, idx);
    while (pv) {
        OmenCtx *ctx = (OmenCtx *)*pv;
        ctx->ip_level = calc_level(ctx->ip_count, ot->total_ip, 250.0);
        ctx->ep_level = calc_level(ctx->ep_count, ot->total_ep, 250.0);
        for (int c = 0; c < 256; c++) {
            if (ctx->next_count[c] > 0)
                ctx->next_level[c] = calc_level(ctx->next_count[c], ctx->cp_count, 2.0);
            else
                ctx->next_level[c] = OMEN_MAX_LEVEL;
        }
        JSLN(pv, ot->contexts, idx);
    }

    /* Smooth length levels */
    int total_ln = 0;
    for (int i = 0; i <= OMEN_MAX_LEN; i++) total_ln += ot->ln_count[i];
    for (int i = 0; i <= OMEN_MAX_LEN; i++)
        ot->ln_level[i] = calc_level(ot->ln_count[i], total_ln, 10.0);
}

/* ---- Save OMEN files ---- */
int omen_save(OmenTrainer *ot, const char *omen_dir) {
    char path[PCFG_MAXPATH];
    FILE *fp;

#ifdef _WIN32
    mkdir(omen_dir);
#else
    mkdir(omen_dir, 0755);
#endif

    /* config.txt */
    snprintf(path, sizeof(path), "%s/config.txt", omen_dir);
    fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "ngram=%d\n", ot->ngram);
        fprintf(fp, "alphabet_size=%d\n", (int)strlen(ot->alphabet));
        fclose(fp);
    }

    /* alphabet.txt */
    snprintf(path, sizeof(path), "%s/alphabet.txt", omen_dir);
    fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "%s\n", ot->alphabet);
        fclose(fp);
    }

    /* IP.level */
    snprintf(path, sizeof(path), "%s/IP.level", omen_dir);
    fp = fopen(path, "w");
    if (fp) {
        uint8_t idx[16];
        Word_t *pv;
        idx[0] = '\0';
        JSLF(pv, ot->contexts, idx);
        while (pv) {
            OmenCtx *ctx = (OmenCtx *)*pv;
            if (ctx->ip_count > 0)
                fprintf(fp, "%d\t%s\n", ctx->ip_level, idx);
            JSLN(pv, ot->contexts, idx);
        }
        fclose(fp);
    }

    /* EP.level */
    snprintf(path, sizeof(path), "%s/EP.level", omen_dir);
    fp = fopen(path, "w");
    if (fp) {
        uint8_t idx[16];
        Word_t *pv;
        idx[0] = '\0';
        JSLF(pv, ot->contexts, idx);
        while (pv) {
            OmenCtx *ctx = (OmenCtx *)*pv;
            if (ctx->ep_count > 0)
                fprintf(fp, "%d\t%s\n", ctx->ep_level, idx);
            JSLN(pv, ot->contexts, idx);
        }
        fclose(fp);
    }

    /* CP.level */
    snprintf(path, sizeof(path), "%s/CP.level", omen_dir);
    fp = fopen(path, "w");
    if (fp) {
        uint8_t idx[16];
        Word_t *pv;
        idx[0] = '\0';
        JSLF(pv, ot->contexts, idx);
        while (pv) {
            OmenCtx *ctx = (OmenCtx *)*pv;
            for (int c = 0; c < 256; c++) {
                if (ctx->next_count[c] > 0)
                    fprintf(fp, "%d\t%s%c\n", ctx->next_level[c], idx, c);
            }
            JSLN(pv, ot->contexts, idx);
        }
        fclose(fp);
    }

    /* LN.level */
    snprintf(path, sizeof(path), "%s/LN.level", omen_dir);
    fp = fopen(path, "w");
    if (fp) {
        for (int i = 0; i <= OMEN_MAX_LEN; i++)
            fprintf(fp, "%d\n", ot->ln_level[i]);
        fclose(fp);
    }

    return 0;
}

void omen_free(OmenTrainer *ot) {
    if (!ot) return;
    /* Free all contexts */
    uint8_t idx[16];
    Word_t *pv;
    idx[0] = '\0';
    JSLF(pv, ot->contexts, idx);
    while (pv) {
        OmenCtx *ctx = (OmenCtx *)*pv;
        free(ctx);
        JSLN(pv, ot->contexts, idx);
    }
    Word_t bytes;
    JSLFA(bytes, ot->contexts);
    (void)bytes;
    free(ot->alphabet);
    free(ot);
}
