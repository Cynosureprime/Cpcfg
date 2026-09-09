/*
 * pcfg_diff.c - Coverage gap diagnosis
 *
 * Given a grammar A (trained by pcfg -t) and a password set B, reports WHY
 * B passwords are not generated from A, and what would close the gap.
 *
 * A B password is generatable by A's grammar exactly when every component
 * of its training parse exists in A:
 *   - the base structure (e.g. A8D1) in Grammar/grammar.txt
 *   - every terminal value in its type file (Alpha/8.txt, Digits/1.txt, ...)
 *   - the case mask and leet mask for each alpha section
 * This is the same decomposition training uses, so the check is exact.
 *
 * Each missed password is attributed to the missing components; the report
 * tallies them by category, lists the most frequent missing values, and
 * simulates how much coverage each category fix would recover.
 *
 * Multiword splitting is not applied (the trie is not saved in the grammar
 * directory), so compound words that A split differently are attributed as
 * alpha misses.  At the aggregate level this is still the right signal.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <errno.h>
#include <dirent.h>

#include "pcfg.h"

/* ---- Miss categories, in primary-attribution priority order ---- */
enum {
    CAT_BASE = 0,
    CAT_ALPHA,
    CAT_MASK,
    CAT_LEET,
    CAT_DIGIT,
    CAT_DATE,
    CAT_YEAR,
    CAT_OTHER,
    CAT_KBD,
    CAT_CTX,
    NCAT
};

static const char *cat_name[NCAT] = {
    "base structure", "alpha word", "case mask", "leet mask",
    "digit string", "date", "year", "special string",
    "keyboard walk", "context pattern"
};

/* short keys for the -o dump (greppable, no spaces) */
static const char *cat_key[NCAT] = {
    "base", "alpha", "mask", "leet", "digit", "date",
    "year", "other", "kbd", "ctx"
};

/* ---- Loaded grammar: type string → Counter of values, plus totals ---- */
static Pvoid_t TC_map;      /* JudySL: type ("A8", "C4", ...) → Counter */
static Pvoid_t TC_total;    /* JudySL: type → total count (Word_t) */
static Counter BaseC;       /* base structures → count */
static int64_t BaseTotal;

/* ---- Load one TSV file into a counter ---- */
static void load_tsv_into(Counter *c, int64_t *total_out, const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[PCFG_MAXLINE];
    while (fgets(line, sizeof(line), fp)) {
        int len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) len--;
        line[len] = '\0';
        if (len <= 0) continue;
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        char *probstr = tab + 1;
        int64_t count;
        char *slash = strchr(probstr, '/');
        if (slash) {
            count = strtoll(probstr, NULL, 10);
        } else {
            /* float format (pcfg-go): approximate a count that preserves
             * the ratios within the file */
            double p = strtod(probstr, NULL);
            count = (int64_t)(p * 1000000.0);
            if (count < 1) count = 1;
        }
        if (count <= 0) continue;
        counter_inc_n(c, line, count);
        *total_out += count;
    }
    fclose(fp);
}

static void store_type(const char *typekey, Counter c, int64_t total) {
    if (!c) return;
    Word_t *pv;
    JSLI(pv, TC_map, (uint8_t *)typekey);
    *pv = (Word_t)c;
    JSLI(pv, TC_total, (uint8_t *)typekey);
    *pv = (Word_t)total;
}

static int load_diff_grammar(const char *gramdir) {
    const char *dirs[] = { "Alpha", "Digits", "Other", "Keyboard",
                           "Capitalization", "Leet", "Dates", "Repeats",
                           "Years", "Context" };
    const char *prefixes[] = { "A", "D", "O", "K", "C", "L", "B", "R", "Y", "X" };
    int ndirs = sizeof(dirs) / sizeof(dirs[0]);
    int nloaded = 0;

    for (int d = 0; d < ndirs; d++) {
        char path[PCFG_MAXPATH];
        snprintf(path, sizeof(path), "%s/%s", gramdir, dirs[d]);
        DIR *dp = opendir(path);
        if (!dp) continue;
        struct dirent *ent;
        while ((ent = readdir(dp)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char *dot = strrchr(ent->d_name, '.');
            if (!dot || strcmp(dot, ".txt") != 0) continue;
            int num = atoi(ent->d_name);
            char typekey[PCFG_MAXTYPE];
            if (strcmp(dirs[d], "Years") == 0 || strcmp(dirs[d], "Context") == 0)
                snprintf(typekey, sizeof(typekey), "%s1", prefixes[d]);
            else
                snprintf(typekey, sizeof(typekey), "%s%d", prefixes[d], num);
            char fpath[PCFG_MAXPATH];
            snprintf(fpath, sizeof(fpath), "%s/%s/%s", gramdir, dirs[d], ent->d_name);
            Counter c = NULL;
            int64_t total = 0;
            load_tsv_into(&c, &total, fpath);
            if (c) {
                store_type(typekey, c, total);
                nloaded++;
            }
        }
        closedir(dp);
    }

    /* semantic type files: filename IS the type key */
    {
        char path[PCFG_MAXPATH];
        snprintf(path, sizeof(path), "%s/Sem", gramdir);
        DIR *dp = opendir(path);
        if (dp) {
            struct dirent *ent;
            while ((ent = readdir(dp)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char *dot = strrchr(ent->d_name, '.');
                if (!dot || strcmp(dot, ".txt") != 0) continue;
                char typekey[PCFG_MAXTYPE];
                snprintf(typekey, sizeof(typekey), "%.*s",
                         (int)(dot - ent->d_name), ent->d_name);
                char fpath[PCFG_MAXPATH];
                snprintf(fpath, sizeof(fpath), "%s/Sem/%s", gramdir, ent->d_name);
                Counter c = NULL;
                int64_t total = 0;
                load_tsv_into(&c, &total, fpath);
                if (c) {
                    store_type(typekey, c, total);
                    nloaded++;
                }
            }
            closedir(dp);
        }
    }

    /* base structures */
    {
        char path[PCFG_MAXPATH];
        snprintf(path, sizeof(path), "%s/Grammar/grammar.txt", gramdir);
        load_tsv_into(&BaseC, &BaseTotal, path);
        if (BaseC) nloaded++;
    }
    return nloaded;
}

/* ---- Membership + probability lookups ---- */
static double tc_prob(const char *type, const char *value) {
    Word_t *pv;
    JSLG(pv, TC_map, (uint8_t *)type);
    if (!pv) return 0.0;
    Counter c = (Counter)*pv;
    JSLG(pv, c, (uint8_t *)value);
    if (!pv) return 0.0;
    Word_t *tv;
    JSLG(tv, TC_total, (uint8_t *)type);
    int64_t total = tv ? (int64_t)*tv : 0;
    return total > 0 ? (double)*pv / (double)total : 0.0;
}

static double base_prob(const char *base) {
    if (!BaseC || BaseTotal <= 0) return 0.0;
    Word_t *pv;
    JSLG(pv, BaseC, (uint8_t *)base);
    return pv ? (double)*pv / (double)BaseTotal : 0.0;
}

/* ---- Report helpers: top-N from a counter ---- */
typedef struct { char *key; int64_t count; } DEntry;

static int cmp_dentry_desc(const void *a, const void *b) {
    const DEntry *da = a, *db = b;
    if (da->count != db->count)
        return (db->count > da->count) ? 1 : -1;
    return strcmp(da->key, db->key);
}

static void print_top(const char *label, Counter c, int topn) {
    if (!c) return;
    int n = 0;
    Word_t *pv;
    uint8_t idx[PCFG_MAXLINE];
    idx[0] = '\0';
    /* count first */
    int64_t nvals = 0;
    JSLF(pv, c, idx);
    while (pv) { nvals++; JSLN(pv, c, idx); }
    if (nvals == 0) return;

    DEntry *entries = malloc(nvals * sizeof(DEntry));
    if (!entries) return;
    idx[0] = '\0';
    JSLF(pv, c, idx);
    while (pv) {
        entries[n].key = strdup((char *)idx);
        entries[n].count = (int64_t)*pv;
        n++;
        JSLN(pv, c, idx);
    }
    qsort(entries, n, sizeof(DEntry), cmp_dentry_desc);
    printf("  %-18s", label);
    for (int i = 0; i < n && i < topn; i++) {
        char buf[40];
        snprintf(buf, sizeof(buf), "%s", entries[i].key);
        if (strlen(entries[i].key) > 24) buf[24] = '\0';
        printf("%s'%s' x%" PRId64, i ? ", " : "", buf, entries[i].count);
        if (i == topn - 1 && n > topn) printf(", ...");
    }
    printf("\n");
    for (int i = 0; i < n; i++) free(entries[i].key);
    free(entries);
}

/* ---- Dump the complete missing-entry list (category, value, count) ---- */
static int64_t dump_missing(const char *outfile, Counter *missval) {
    FILE *fo;
    if (strcmp(outfile, "-") == 0)
        fo = stdout;
    else {
        fo = fopen(outfile, "w");
        if (!fo) {
            fprintf(stderr, "pcfg: cannot create \"%s\": %s\n",
                    outfile, strerror(errno));
            return -1;
        }
    }

    int64_t total = 0;
    for (int c = 0; c < NCAT; c++) {
        if (!missval[c]) continue;
        int64_t nvals = 0;
        Word_t *pv;
        uint8_t idx[PCFG_MAXLINE];
        idx[0] = '\0';
        JSLF(pv, missval[c], idx);
        while (pv) { nvals++; JSLN(pv, missval[c], idx); }
        if (nvals == 0) continue;

        DEntry *entries = malloc(nvals * sizeof(DEntry));
        if (!entries) continue;
        int n = 0;
        idx[0] = '\0';
        JSLF(pv, missval[c], idx);
        while (pv) {
            entries[n].key = strdup((char *)idx);
            entries[n].count = (int64_t)*pv;
            n++;
            JSLN(pv, missval[c], idx);
        }
        qsort(entries, n, sizeof(DEntry), cmp_dentry_desc);
        for (int i = 0; i < n; i++) {
            fprintf(fo, "%s\t%s\t%" PRId64 "\n",
                    cat_key[c], entries[i].key, entries[i].count);
            free(entries[i].key);
        }
        free(entries);
        total += n;
    }

    if (fo != stdout) fclose(fo);
    return total;
}

/* ---- Main diagnosis ---- */
int pcfg_diagnose(const char *gramdir, const char *infile,
                  int weighted, int skip_masks, const char *outfile) {
    int ntypes = load_diff_grammar(gramdir);
    if (ntypes == 0 || !BaseC) {
        fprintf(stderr, "pcfg: cannot load grammar from \"%s\"\n", gramdir);
        return 1;
    }

    FILE *fi;
    if (strcmp(infile, "stdin") == 0)
        fi = stdin;
    else {
        fi = fopen(infile, "rb");
        if (!fi) {
            fprintf(stderr, "pcfg: cannot open \"%s\": %s\n",
                    infile, strerror(errno));
            return 1;
        }
    }

    WorkSpace *ws = ws_alloc();
    char *linebuf = malloc(PCFG_MAXLINE);
    if (!ws || !linebuf) { fprintf(stderr, "pcfg: OOM\n"); return 1; }
    GlobalMultiTrie = NULL;

    fprintf(stderr, "pcfg: diagnosing coverage of \"%s\" under grammar \"%s\"\n",
            infile, gramdir);

    int64_t total_lines = 0, parsed = 0, unsupported = 0, reachable = 0;
    int64_t cat_miss[NCAT] = {0};              /* exclusive primary tallies */
    static int64_t subset_count[1 << NCAT];    /* exact missing-set histogram */
    Counter missval[NCAT];
    memset(missval, 0, sizeof(missval));
    int64_t prob_hist[49];                     /* bucket = ceil(-log10 P) */
    memset(prob_hist, 0, sizeof(prob_hist));

    while (fgets(linebuf, PCFG_MAXLINE, fi)) {
        int len = strlen(linebuf);
        while (len > 0 && (linebuf[len-1] == '\n' || linebuf[len-1] == '\r'))
            len--;
        linebuf[len] = '\0';
        if (len <= 0) continue;
        total_lines++;

        char *pw = linebuf;
        int pwlen = len;
        int64_t weight = 1;
        if (weighted)
            weight = parse_weight(&pw, &pwlen);
        if (pwlen >= 5 && strncmp(pw, "$HEX[", 5) == 0) {
            int dlen = decode_hex(pw + 5, ws->decoded, pwlen - 5);
            pw = ws->decoded;
            pwlen = dlen;
        }
        if (pwlen <= 0) continue;

        int nsects = pcfg_parse(pw, pwlen, ws->sects, PCFG_MAXSECTIONS,
                                ws->tag, ws->lower);
        if (nsects <= 0) continue;
        parsed += weight;

        build_base_structure(ws->sects, nsects, ws->base_str, PCFG_MAXLINE);
        if (!ws->base_str[0]) {
            /* contains email/website sections — never generated by -G */
            unsupported += weight;
            continue;
        }

        uint32_t missmask = 0;
        double prob = base_prob(ws->base_str);
        if (prob == 0.0) {
            missmask |= 1 << CAT_BASE;
            counter_inc_n(&missval[CAT_BASE], ws->base_str, weight);
        }

        for (int i = 0; i < nsects; i++) {
            Section *s = &ws->sects[i];
            char *val = ws->val;
            int vlen = s->vlen;
            if (vlen >= PCFG_MAXLINE) vlen = PCFG_MAXLINE - 1;
            memcpy(val, s->value, vlen);
            val[vlen] = '\0';

            char tbuf[PCFG_MAXTYPE];
            int cat;
            const char *key;
            char tchr = s->type[0];

            if (tchr == ST_ALPHA || SemLetters[(unsigned char)tchr]) {
                /* folded/lowered key + masks, as training computes them */
                char *lowered = ws->lowered;
                char *lmask = ws->leetmask;
                int li = 0, ki = 0, si = 0;
                while (si < vlen && li < PCFG_MAXLINE - 4) {
                    uint32_t cp;
                    int n = utf8_decode(val + si, vlen - si, &cp);
                    if (n == 0) break;
                    unsigned char fold = (n == 1)
                        ? leet_fold[(unsigned char)val[si]] : 0;
                    if (fold) {
                        lowered[li++] = (char)fold;
                        lmask[ki++] = val[si];
                    } else {
                        li += utf8_encode(lowered + li, utf8_to_lower(cp));
                        lmask[ki++] = '.';
                    }
                    si += n;
                }
                lowered[li] = '\0';
                lmask[ki] = '\0';

                double p = tc_prob(s->type, lowered);
                if (p == 0.0) {
                    missmask |= 1 << CAT_ALPHA;
                    counter_inc_n(&missval[CAT_ALPHA], lowered, weight);
                } else {
                    prob *= p;
                }

                if (!skip_masks) {
                    build_case_mask(val, vlen, ws->mask);
                    tbuf[0] = 'C';
                    snprintf(tbuf + 1, sizeof(tbuf) - 1, "%d", s->tnum);
                    double pm = tc_prob(tbuf, ws->mask);
                    if (pm == 0.0) {
                        missmask |= 1 << CAT_MASK;
                        counter_inc_n(&missval[CAT_MASK], ws->mask, weight);
                    } else {
                        prob *= pm;
                    }

                    tbuf[0] = 'L';
                    double pl = tc_prob(tbuf, lmask);
                    if (pl == 0.0) {
                        missmask |= 1 << CAT_LEET;
                        counter_inc_n(&missval[CAT_LEET], lmask, weight);
                    } else {
                        prob *= pl;
                    }
                }
            }
            else switch (tchr) {
            case ST_DIGIT:  cat = CAT_DIGIT; key = val; goto check;
            case ST_DATE:   cat = CAT_DATE;  key = val; goto check;
            case ST_YEAR:   cat = CAT_YEAR;  key = val; goto check;
            case ST_OTHER:  cat = CAT_OTHER; key = val; goto check;
            case ST_KEYBOARD: cat = CAT_KBD; key = val; goto check;
            case ST_CONTEXT:  cat = CAT_CTX; key = val; goto check;
            default: continue;
            check:
                {
                    double p = tc_prob(s->type, key);
                    if (p == 0.0) {
                        missmask |= 1 << cat;
                        counter_inc_n(&missval[cat], key, weight);
                    } else {
                        prob *= p;
                    }
                }
            }
        }

        if (missmask == 0) {
            reachable += weight;
            if (prob > 0.0 && prob <= 1.0) {
                int b = (int)ceil(-log10(prob));
                if (b < 0) b = 0;
                if (b > 48) b = 48;
                prob_hist[b] += weight;
            }
        } else {
            subset_count[missmask] += weight;
            for (int c = 0; c < NCAT; c++) {
                if (missmask & (1u << c)) {
                    cat_miss[c] += weight;
                    break;
                }
            }
        }
    }
    if (fi != stdin) fclose(fi);

    /* ---- Report ---- */
    int64_t missed = parsed - reachable - unsupported;
    printf("\n");
    printf("Coverage of B under grammar A\n");
    printf("  passwords parsed:   %" PRId64 " (%" PRId64 " lines)\n", parsed, total_lines);
    printf("  reachable:          %" PRId64 " (%.1f%%)\n",
           reachable, parsed > 0 ? 100.0 * reachable / parsed : 0.0);
    printf("  missed:             %" PRId64 " (%.1f%%)\n",
           missed, parsed > 0 ? 100.0 * missed / parsed : 0.0);
    printf("  unsupported (email/website — never generated): %" PRId64 " (%.1f%%)\n",
           unsupported, parsed > 0 ? 100.0 * unsupported / parsed : 0.0);

    if (missed > 0) {
        printf("\nWhy passwords are missed (primary blocker, exclusive)\n");
        for (int c = 0; c < NCAT; c++) {
            if (cat_miss[c] > 0)
                printf("  %-24s %8" PRId64 "  (%.1f%% of B)\n",
                       cat_name[c], cat_miss[c],
                       parsed > 0 ? 100.0 * cat_miss[c] / parsed : 0.0);
        }

        printf("\nMost frequent missing entries (count in B)\n");
        for (int c = 0; c < NCAT; c++)
            print_top(cat_name[c], missval[c], 8);

        if (outfile) {
            int64_t n = dump_missing(outfile, missval);
            if (n >= 0)
                printf("\nComplete missing-entry list: \"%s\" (%" PRId64
                       " entries, format: category<TAB>value<TAB>count_in_B;\n"
                       "  alpha words: awk -F'\\t' '$1==\"alpha\"{print $2}' %s)\n",
                       outfile, n, outfile);
        }
    }

    /* probability depth of the reachable set */
    if (reachable > 0) {
        int64_t cum = 0;
        int b25 = -1, b50 = -1, b75 = -1;
        int64_t shallow = 0;
        for (int b = 0; b <= 48; b++) {
            cum += prob_hist[b];
            if (b25 < 0 && cum >= reachable / 4) b25 = b;
            if (b50 < 0 && cum >= reachable / 2) b50 = b;
            if (b75 < 0 && cum >= (reachable * 3) / 4) b75 = b;
            if (b <= 6) shallow += prob_hist[b];
        }
        printf("\nReachable passwords by probability under A\n");
        printf("  median P ~ 10^-%d, quartiles 10^-%d .. 10^-%d\n",
               b50, b25, b75);
        printf("  ~%.1f%% have P >= 10^-6 (early in the queue)\n",
               reachable > 0 ? 100.0 * shallow / reachable : 0.0);
        printf("  rough queue depth to reach the median: ~10^%d guesses\n", b50);
    }

    /* closure simulation: add categories in decreasing total-involvement
     * order — a category that is always secondary (e.g. a missing word that
     * always comes with a missing structure) still gets its step */
    if (missed > 0) {
        int64_t involve[NCAT] = {0};
        for (int c = 0; c < NCAT; c++)
            for (uint32_t m = 1; m < (1u << NCAT); m++)
                if (m & (1u << c)) involve[c] += subset_count[m];

        int order[NCAT], nord = 0;
        int used[NCAT] = {0};
        for (int pass = 0; pass < NCAT; pass++) {
            int best = -1;
            for (int c = 0; c < NCAT; c++)
                if (!used[c] && involve[c] > 0 &&
                    (best < 0 || involve[c] > involve[best]))
                    best = c;
            if (best < 0) break;
            order[nord++] = best;
            used[best] = 1;
        }

        printf("\nGap closure simulation (adding B's missing entries to A)\n");
        printf("  %-28s %10s\n", "step", "reachable");
        uint32_t added = 0;
        int64_t base_reach = reachable;
        for (int k = 0; k < nord; k++) {
            added |= 1u << order[k];
            int64_t now = base_reach;
            for (uint32_t m = 1; m < (1u << NCAT); m++)
                if ((m & added) == m) now += subset_count[m];
            printf("  + %-24s %6.1f%%\n", cat_name[order[k]],
                   parsed > 0 ? 100.0 * now / parsed : 0.0);
        }
        printf("  ceiling (all merged)      %6.1f%%\n",
               parsed > 0 ? 100.0 * (parsed - unsupported) / parsed : 0.0);
    }

    /* ---- Suggested actions ---- */
    printf("\nHow to close the gap\n");
    if (cat_miss[CAT_ALPHA] > 0)
        printf("  vocabulary: B uses words absent from A (%" PRId64 " passwords). "
               "Merge a B-derived grammar or extend the training corpus.\n",
               cat_miss[CAT_ALPHA]);
    if (cat_miss[CAT_BASE] > 0)
        printf("  structures: B uses base structures A never saw (%" PRId64
               " passwords) — a genuinely different population. Merging carries "
               "them across.\n", cat_miss[CAT_BASE]);
    if (cat_miss[CAT_MASK] + cat_miss[CAT_LEET] > 0)
        printf("  style: capitalization/leet conventions differ (%" PRId64
               " passwords). Merging fixes this.\n",
               cat_miss[CAT_MASK] + cat_miss[CAT_LEET]);
    if (missed == 0 && reachable > 0)
        printf("  everything in B is reachable from A — misses are a ranking "
               "problem: retrain with -w on cracked hits, or generate deeper.\n");
    if (unsupported > 0)
        printf("  %" PRId64 " B passwords contain emails/websites; -G never "
               "generates these by design.\n", unsupported);
    printf("\n  commands:\n");
    printf("    pcfg -t \"%s\" -g /tmp/gb -f 3\n", infile);
    printf("    pcfg -M \"%s\" -M /tmp/gb -g /tmp/gmerged\n", gramdir);

    /* free miss counters */
    for (int c = 0; c < NCAT; c++) counter_free(&missval[c]);
    ws_free(ws);
    free(linebuf);
    return 0;
}
