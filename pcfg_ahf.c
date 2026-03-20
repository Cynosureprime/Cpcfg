/*
 * pcfg_ahf.c - Adaptive Hybrid-Fuzzing generation
 *
 * Generates synthetic passwords using character-level Markov chains
 * trained from the OMEN data. Produces plausible passwords that were
 * never seen in training — exploring beyond the known terminal values.
 *
 * Approach:
 *   1. Load OMEN alphabet and n-gram tables (IP/CP/EP levels)
 *   2. For each base structure, generate synthetic terminal values
 *      character-by-character using Markov transition probabilities
 *   3. Output generated passwords interleaved with normal PCFG output
 *
 * Inspired by the AHF mode in hashcat's PCFG fork by matrix.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "pcfg.h"

/* ---- OMEN data for generation ---- */
typedef struct {
    char *alphabet;         /* character set */
    int   alpha_len;
    int   ngram;            /* n-gram size (from config) */
    /* IP: initial prefix → level */
    Pvoid_t ip_levels;      /* JudySL: prefix → level (int) */
    /* CP: prefix+char → level */
    Pvoid_t cp_levels;      /* JudySL: prefix+char → level (int) */
    /* EP: ending prefix → level */
    Pvoid_t ep_levels;      /* JudySL: prefix → level (int) */
    /* LN: length → level */
    int ln_levels[32];
} OmenGen;

/* Load OMEN data from grammar directory */
static OmenGen *omen_load(const char *gramdir) {
    OmenGen *og = calloc(1, sizeof(OmenGen));
    char path[PCFG_MAXPATH];
    char line[1024];

    /* Config */
    snprintf(path, sizeof(path), "%s/Omen/config.txt", gramdir);
    FILE *fp = fopen(path, "r");
    if (!fp) { free(og); return NULL; }
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "ngram=", 6) == 0) og->ngram = atoi(line + 6);
    }
    fclose(fp);
    if (og->ngram < 2) og->ngram = 4;

    /* Alphabet */
    snprintf(path, sizeof(path), "%s/Omen/alphabet.txt", gramdir);
    fp = fopen(path, "r");
    if (!fp) { free(og); return NULL; }
    if (fgets(line, sizeof(line), fp)) {
        int len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) len--;
        line[len] = '\0';
        og->alphabet = strdup(line);
        og->alpha_len = len;
    }
    fclose(fp);
    if (!og->alphabet || og->alpha_len == 0) { free(og); return NULL; }

    /* IP levels */
    snprintf(path, sizeof(path), "%s/Omen/IP.level", gramdir);
    fp = fopen(path, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            int len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) len--;
            line[len] = '\0';
            char *tab = strchr(line, '\t');
            if (!tab) continue;
            int level = atoi(line);
            char *prefix = tab + 1;
            Word_t *pv;
            JSLI(pv, og->ip_levels, (uint8_t *)prefix);
            *pv = (Word_t)level;
        }
        fclose(fp);
    }

    /* EP levels */
    snprintf(path, sizeof(path), "%s/Omen/EP.level", gramdir);
    fp = fopen(path, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            int len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) len--;
            line[len] = '\0';
            char *tab = strchr(line, '\t');
            if (!tab) continue;
            int level = atoi(line);
            char *prefix = tab + 1;
            Word_t *pv;
            JSLI(pv, og->ep_levels, (uint8_t *)prefix);
            *pv = (Word_t)level;
        }
        fclose(fp);
    }

    /* CP levels */
    snprintf(path, sizeof(path), "%s/Omen/CP.level", gramdir);
    fp = fopen(path, "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            int len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) len--;
            line[len] = '\0';
            char *tab = strchr(line, '\t');
            if (!tab) continue;
            int level = atoi(line);
            char *key = tab + 1;  /* prefix + next_char */
            Word_t *pv;
            JSLI(pv, og->cp_levels, (uint8_t *)key);
            *pv = (Word_t)level;
        }
        fclose(fp);
    }

    /* LN levels */
    snprintf(path, sizeof(path), "%s/Omen/LN.level", gramdir);
    fp = fopen(path, "r");
    if (fp) {
        int i = 0;
        while (fgets(line, sizeof(line), fp) && i < 32) {
            og->ln_levels[i++] = atoi(line);
        }
        fclose(fp);
    }

    return og;
}

/* Get IP level for a prefix */
static int omen_ip_level(OmenGen *og, const char *prefix) {
    Word_t *pv;
    JSLG(pv, og->ip_levels, (uint8_t *)prefix);
    return pv ? (int)*pv : 10;
}

/* Get CP level for prefix→char transition */
static int omen_cp_level(OmenGen *og, const char *key) {
    Word_t *pv;
    JSLG(pv, og->cp_levels, (uint8_t *)key);
    return pv ? (int)*pv : 10;
}

/* ---- Generate one synthetic password of given length using OMEN Markov ---- */
static int omen_generate_word(OmenGen *og, int target_len, int max_level,
                              char *out, unsigned int *seed) {
    if (target_len < og->ngram || target_len > 30) return 0;

    int prefix_len = og->ngram - 1;

    /* Find a starting prefix with IP level <= max_level */
    /* Try random prefixes from alphabet */
    for (int attempt = 0; attempt < 100; attempt++) {
        char prefix[8];
        for (int i = 0; i < prefix_len; i++) {
            *seed = *seed * 1103515245 + 12345;
            prefix[i] = og->alphabet[(*seed >> 16) % og->alpha_len];
        }
        prefix[prefix_len] = '\0';

        if (omen_ip_level(og, prefix) > max_level) continue;

        /* Build word character by character */
        memcpy(out, prefix, prefix_len);
        int pos = prefix_len;
        int ok = 1;

        while (pos < target_len) {
            /* Try each alphabet char, pick one with CP level <= max_level */
            char key[16];
            int best_level = 99;
            int best_count = 0;
            char candidates[256];

            for (int c = 0; c < og->alpha_len; c++) {
                memcpy(key, out + pos - prefix_len, prefix_len);
                key[prefix_len] = og->alphabet[c];
                key[prefix_len + 1] = '\0';

                int lev = omen_cp_level(og, key);
                if (lev <= max_level) {
                    if (lev < best_level) {
                        best_level = lev;
                        best_count = 0;
                    }
                    if (lev == best_level && best_count < 256)
                        candidates[best_count++] = og->alphabet[c];
                }
            }

            if (best_count == 0) { ok = 0; break; }

            /* Pick randomly from best candidates */
            *seed = *seed * 1103515245 + 12345;
            out[pos++] = candidates[(*seed >> 16) % best_count];
        }

        if (!ok || pos != target_len) continue;
        out[pos] = '\0';
        return pos;
    }
    return 0;
}

/* ---- AHF generation: produce synthetic passwords ---- */
int pcfg_ahf_generate(const char *gramdir, GenCtx *ctx, int64_t count) {
    OmenGen *og = omen_load(gramdir);
    if (!og) {
        fprintf(stderr, "pcfg: AHF requires OMEN training data in grammar\n");
        return 1;
    }

    fprintf(stderr, "pcfg: AHF mode: alphabet=%d chars, ngram=%d, generating %" PRId64 " passwords\n",
            og->alpha_len, og->ngram, count);

    /* Use base structures from grammar to determine patterns */
    if (pcfg_load(gramdir, ctx) < 0) return 1;

    char outbuf[1024 * 1024];
    int outpos = 0;
    int64_t generated = 0;
    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();

    /* For each base structure (probability-ordered), generate synthetic passwords */
    for (int si = 0; si < ctx->nbases && generated < count; si++) {
        BaseStructure *bs = &ctx->bases[si];
        if (bs->nreplace <= 0) continue;

        /* Skip M-only structures */
        int has_real = 0;
        for (int j = 0; j < bs->nreplace; j++)
            if (bs->replacements[j][0] != 'M') has_real = 1;
        if (!has_real) continue;

        /* Generate multiple passwords for this structure */
        int per_struct = (int)(bs->prob * 1000);
        if (per_struct < 1) per_struct = 1;
        if (per_struct > 100) per_struct = 100;

        for (int g = 0; g < per_struct && generated < count; g++) {
            char pw[256];
            int pwpos = 0;

            int ok = 1;
            for (int j = 0; j < bs->nreplace && ok; j++) {
                char *type = bs->replacements[j];
                int tlen = atoi(type + 1);
                if (tlen <= 0) tlen = 1;

                if (type[0] == 'A') {
                    /* Generate synthetic alpha word via OMEN */
                    char word[64];
                    int wlen = omen_generate_word(og, tlen, 5, word, &seed);
                    if (wlen > 0 && pwpos + wlen < 250) {
                        memcpy(pw + pwpos, word, wlen);
                        pwpos += wlen;
                    } else {
                        ok = 0;
                    }
                } else if (type[0] == 'D') {
                    /* Generate random digits */
                    for (int d = 0; d < tlen && pwpos < 250; d++) {
                        seed = seed * 1103515245 + 12345;
                        pw[pwpos++] = '0' + ((seed >> 16) % 10);
                    }
                } else if (type[0] == 'C') {
                    /* Apply random case mask to preceding alpha */
                    /* Skip — the alpha is already lowercase from OMEN */
                } else if (type[0] == 'O') {
                    /* Generate random special chars */
                    static const char specials[] = "!@#$%^&*()-_=+.,;:?/\\|~`'\"<>[]{}";
                    for (int d = 0; d < tlen && pwpos < 250; d++) {
                        seed = seed * 1103515245 + 12345;
                        pw[pwpos++] = specials[(seed >> 16) % (sizeof(specials) - 1)];
                    }
                } else if (type[0] == 'Y') {
                    /* Random year */
                    seed = seed * 1103515245 + 12345;
                    int year = 1980 + ((seed >> 16) % 46);
                    pwpos += snprintf(pw + pwpos, 250 - pwpos, "%d", year);
                } else if (type[0] == 'K') {
                    ok = 0;  /* Can't synthesize keyboard walks */
                } else if (type[0] == 'M') {
                    ok = 0;  /* Skip Markov-only slots */
                }
            }

            if (!ok || pwpos <= 0) continue;
            pw[pwpos] = '\0';

            /* Emit */
            if (outpos + pwpos + 1 >= (int)sizeof(outbuf)) {
                write(STDOUT_FILENO, outbuf, outpos);
                outpos = 0;
            }
            memcpy(outbuf + outpos, pw, pwpos);
            outpos += pwpos;
            outbuf[outpos++] = '\n';
            generated++;
        }
    }

    if (outpos > 0)
        write(STDOUT_FILENO, outbuf, outpos);

    fprintf(stderr, "pcfg: AHF generated %" PRId64 " synthetic passwords\n", generated);
    return 0;
}
