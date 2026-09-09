/*
 * pcfg_save.c - Save and load grammar files
 *
 * Output format is compatible with pcfg-go:
 *   Rules/{name}/config.ini
 *   Rules/{name}/Grammar/grammar.txt
 *   Rules/{name}/Alpha/1.txt, 2.txt, ...
 *   Rules/{name}/Capitalization/1.txt, 2.txt, ...
 *   Rules/{name}/Digits/1.txt, 2.txt, ...
 *   Rules/{name}/Other/1.txt, 2.txt, ...
 *   Rules/{name}/Years/1.txt
 *   Rules/{name}/Context/1.txt
 *   Rules/{name}/Keyboard/4.txt, 5.txt, ...
 *
 * TSV format: value\tprobability\n
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <math.h>
#include <unistd.h>

#include "pcfg.h"

/* Copy one file verbatim.  Returns 0 on success, -1 otherwise. */
static int copy_file(const char *src, const char *dst) {
    FILE *fin = fopen(src, "rb");
    if (!fin) return -1;
    FILE *fout = fopen(dst, "wb");
    if (!fout) { fclose(fin); return -1; }
    char buf[65536];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0) {
        if (fwrite(buf, 1, n, fout) != n) { rc = -1; break; }
    }
    if (fclose(fout) != 0) rc = -1;
    fclose(fin);
    return rc;
}

/* ---- Sorting helper for counter entries ---- */
typedef struct {
    char *key;
    int64_t count;
} CountEntry;

static int cmp_count_desc(const void *a, const void *b) {
    const CountEntry *ca = (const CountEntry *)a;
    const CountEntry *cb = (const CountEntry *)b;
    if (ca->count != cb->count)
        return (cb->count > ca->count) ? 1 : -1;
    return strcmp(ca->key, cb->key);
}

/* ---- Collect counter entries into sorted array ----
 * admit_min: skip entries with count < admit_min (0 = keep all)
 */
static int collect_counter(Counter c, CountEntry **out, int64_t *total_out, int admit_min) {
    int count = 0, cap = 1024;
    CountEntry *entries = malloc(cap * sizeof(CountEntry));
    if (!entries) return 0;

    uint8_t idx[PCFG_MAXLINE];
    Word_t *pv;
    int64_t total = 0;

    idx[0] = '\0';
    JSLF(pv, c, idx);
    while (pv) {
        if (count >= cap) {
            cap *= 2;
            entries = realloc(entries, cap * sizeof(CountEntry));
            if (!entries) return 0;
        }
        int64_t val = (int64_t)*pv;
        if (admit_min > 0 && val < admit_min) {
            JSLN(pv, c, idx);
            continue;
        }
        entries[count].key = strdup((char *)idx);
        entries[count].count = val;
        total += val;
        count++;
        JSLN(pv, c, idx);
    }

    qsort(entries, count, sizeof(CountEntry), cmp_count_desc);
    *out = entries;
    if (total_out) *total_out = total;
    return count;
}

static void free_entries(CountEntry *entries, int count) {
    for (int i = 0; i < count; i++)
        free(entries[i].key);
    free(entries);
}

/* ---- Write a TSV probability file ---- */
#define WBUF_SIZE (1024*1024)
static int write_prob_file(const char *path, CountEntry *entries, int count, int64_t total) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "pcfg: cannot create \"%s\": %s\n", path, strerror(errno));
        return -1;
    }

    char *wbuf = malloc(WBUF_SIZE);
    if (!wbuf) { close(fd); return -1; }
    int wpos = 0;

    char pbuf[64];
    for (int i = 0; i < count; i++) {
        int klen = strlen(entries[i].key);
        format_prob_ratio(entries[i].count, total, pbuf, sizeof(pbuf));
        int plen = strlen(pbuf);
        int need = klen + 1 + plen + 1;

        if (wpos + need >= WBUF_SIZE) {
            write(fd, wbuf, wpos);
            wpos = 0;
        }

        memcpy(wbuf + wpos, entries[i].key, klen);
        wpos += klen;
        wbuf[wpos++] = '\t';
        memcpy(wbuf + wpos, pbuf, plen);
        wpos += plen;
        wbuf[wpos++] = '\n';
    }
    if (wpos > 0)
        write(fd, wbuf, wpos);

    close(fd);
    free(wbuf);
    return 0;
}

/* ---- Helper: ensure directory exists ---- */
static void ensure_dir(const char *path) {
#ifdef _WIN32
    mkdir(path);
#else
    mkdir(path, 0755);
#endif
}

/* ---- Save length-indexed counters ----
 * For Alpha, Digits, Other, Keyboard, Capitalization.
 * Creates subdir/{length}.txt for each length.
 * Returns list of filenames written (for config.ini).
 */
static int save_len_counters(const char *subdir, LenCounters lc,
                             int *lens, int *nlens, int admit_min) {
    ensure_dir(subdir);

    Word_t idx = 0;
    Word_t *pv;
    int n = 0;

    JLF(pv, lc, idx);
    while (pv) {
        Counter c = *(Counter *)pv;
        int len = (int)idx;

        CountEntry *entries;
        int64_t total;
        int count = collect_counter(c, &entries, &total, admit_min);
        if (count > 0 && total > 0) {
            char path[PCFG_MAXPATH];
            snprintf(path, sizeof(path), "%s/%d.txt", subdir, len);
            write_prob_file(path, entries, count, total);
            if (lens && n < 256)
                lens[n] = len;
            n++;
        }
        free_entries(entries, count);
        JLN(pv, lc, idx);
    }

    if (nlens) *nlens = n;
    return 0;
}

/* ---- Save flat counter to single file ---- */
static int save_flat_counter(const char *subdir, const char *filename,
                             Counter c) {
    if (!c) return 0;

    ensure_dir(subdir);

    CountEntry *entries;
    int64_t total;
    int count = collect_counter(c, &entries, &total, 0);
    if (count <= 0 || total <= 0) {
        if (entries) free_entries(entries, count);
        return 0;
    }

    char path[PCFG_MAXPATH];
    snprintf(path, sizeof(path), "%s/%s", subdir, filename);
    int rc = write_prob_file(path, entries, count, total);
    free_entries(entries, count);
    return rc;
}

/* ---- Generate random hex UUID ---- */
static void gen_uuid(char *buf, int len) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)getpid());
        seeded = 1;
    }
    const char hex[] = "0123456789abcdef";
    for (int i = 0; i < len - 1 && i < 32; i++)
        buf[i] = hex[rand() % 16];
    buf[len > 32 ? 32 : len - 1] = '\0';
}

/* ---- Write config.ini ---- */
static int write_config(const char *outdir, TrainCtx *ctx,
                        int *alpha_lens, int nalpha,
                        int *digit_lens, int ndigits,
                        int *other_lens, int nother,
                        int *kbd_lens, int nkbd,
                        int *mask_lens, int nmask) {
    char path[PCFG_MAXPATH];
    snprintf(path, sizeof(path), "%s/config.ini", outdir);

    FILE *fp = fopen(path, "w");
    if (!fp) {
        fprintf(stderr, "pcfg: cannot create \"%s\": %s\n", path, strerror(errno));
        return -1;
    }

    char uuid[64];
    gen_uuid(uuid, sizeof(uuid));

    /* Extract base filename */
    const char *basename = ctx->filename;
    const char *slash = strrchr(basename, '/');
    if (slash) basename = slash + 1;

    fprintf(fp, "[TRAINING_PROGRAM_DETAILS]\n");
    fprintf(fp, "contact = https://github.com/cyclone-github/\n");
    fprintf(fp, "author = pcfg-c\n");
    fprintf(fp, "program = PCFG Trainer\n");
    fprintf(fp, "version = 0.1.0 (C)\n");
    fprintf(fp, "\n");

    fprintf(fp, "[TRAINING_DATASET_DETAILS]\n");
    fprintf(fp, "comments = %s\n", ctx->comments ? ctx->comments : "");
    fprintf(fp, "filename = %s\n", basename);
    fprintf(fp, "encoding = utf-8\n");
    fprintf(fp, "uuid = %s\n", uuid);
    fprintf(fp, "number_of_passwords_in_set = %" PRId64 "\n", ctx->total_passwords);
    fprintf(fp, "number_of_encoding_errors = %" PRId64 "\n", ctx->encoding_errors);
    fprintf(fp, "\n");

    /* START section - base structure */
    fprintf(fp, "[START]\n");
    fprintf(fp, "name = Base Structure\n");
    fprintf(fp, "function = Transparent\n");
    fprintf(fp, "directory = Grammar\n");
    fprintf(fp, "file_type = Flat\n");
    fprintf(fp, "inject_type = Wordlist\n");
    fprintf(fp, "is_terminal = False\n");
    fprintf(fp, "replacements = [");
    fprintf(fp, "{\"Config_id\": \"BASE_A\", \"Transition_id\": \"A\"}");
    fprintf(fp, ", {\"Config_id\": \"BASE_D\", \"Transition_id\": \"D\"}");
    fprintf(fp, ", {\"Config_id\": \"BASE_O\", \"Transition_id\": \"O\"}");
    fprintf(fp, ", {\"Config_id\": \"BASE_K\", \"Transition_id\": \"K\"}");
    fprintf(fp, ", {\"Config_id\": \"BASE_X\", \"Transition_id\": \"X\"}");
    fprintf(fp, ", {\"Config_id\": \"BASE_Y\", \"Transition_id\": \"Y\"}");
    fprintf(fp, "]\n");
    fprintf(fp, "filenames = [\"grammar.txt\"]\n");
    fprintf(fp, "\n");

    /* BASE_A */
    fprintf(fp, "[BASE_A]\n");
    fprintf(fp, "name = A\n");
    fprintf(fp, "function = Shadow\n");
    fprintf(fp, "directory = Alpha\n");
    fprintf(fp, "file_type = Length\n");
    fprintf(fp, "inject_type = Wordlist\n");
    fprintf(fp, "is_terminal = False\n");
    fprintf(fp, "replacements = [{\"Config_id\": \"CAPITALIZATION\", \"Transition_id\": \"Capitalization\"}]\n");
    fprintf(fp, "filenames = [");
    for (int i = 0; i < nalpha; i++)
        fprintf(fp, "%s\"%d.txt\"", i ? ", " : "", alpha_lens[i]);
    fprintf(fp, "]\n\n");

    /* BASE_D */
    fprintf(fp, "[BASE_D]\n");
    fprintf(fp, "name = D\n");
    fprintf(fp, "function = Copy\n");
    fprintf(fp, "directory = Digits\n");
    fprintf(fp, "file_type = Length\n");
    fprintf(fp, "inject_type = Copy\n");
    fprintf(fp, "is_terminal = True\n");
    fprintf(fp, "filenames = [");
    for (int i = 0; i < ndigits; i++)
        fprintf(fp, "%s\"%d.txt\"", i ? ", " : "", digit_lens[i]);
    fprintf(fp, "]\n\n");

    /* BASE_O */
    fprintf(fp, "[BASE_O]\n");
    fprintf(fp, "name = O\n");
    fprintf(fp, "function = Copy\n");
    fprintf(fp, "directory = Other\n");
    fprintf(fp, "file_type = Length\n");
    fprintf(fp, "inject_type = Copy\n");
    fprintf(fp, "is_terminal = True\n");
    fprintf(fp, "filenames = [");
    for (int i = 0; i < nother; i++)
        fprintf(fp, "%s\"%d.txt\"", i ? ", " : "", other_lens[i]);
    fprintf(fp, "]\n\n");

    /* BASE_K */
    fprintf(fp, "[BASE_K]\n");
    fprintf(fp, "name = K\n");
    fprintf(fp, "function = Copy\n");
    fprintf(fp, "directory = Keyboard\n");
    fprintf(fp, "file_type = Length\n");
    fprintf(fp, "inject_type = Copy\n");
    fprintf(fp, "is_terminal = True\n");
    fprintf(fp, "filenames = [");
    for (int i = 0; i < nkbd; i++)
        fprintf(fp, "%s\"%d.txt\"", i ? ", " : "", kbd_lens[i]);
    fprintf(fp, "]\n\n");

    /* BASE_X */
    fprintf(fp, "[BASE_X]\n");
    fprintf(fp, "name = X\n");
    fprintf(fp, "function = Copy\n");
    fprintf(fp, "directory = Context\n");
    fprintf(fp, "file_type = Flat\n");
    fprintf(fp, "inject_type = Copy\n");
    fprintf(fp, "is_terminal = True\n");
    fprintf(fp, "filenames = [\"1.txt\"]\n\n");

    /* BASE_Y */
    fprintf(fp, "[BASE_Y]\n");
    fprintf(fp, "name = Y\n");
    fprintf(fp, "function = Copy\n");
    fprintf(fp, "directory = Years\n");
    fprintf(fp, "file_type = Flat\n");
    fprintf(fp, "inject_type = Copy\n");
    fprintf(fp, "is_terminal = True\n");
    fprintf(fp, "filenames = [\"1.txt\"]\n\n");

    /* CAPITALIZATION */
    fprintf(fp, "[CAPITALIZATION]\n");
    fprintf(fp, "name = C\n");
    fprintf(fp, "function = Capitalization\n");
    fprintf(fp, "directory = Capitalization\n");
    fprintf(fp, "file_type = Length\n");
    fprintf(fp, "is_terminal = True\n");
    fprintf(fp, "filenames = [");
    for (int i = 0; i < nmask; i++)
        fprintf(fp, "%s\"%d.txt\"", i ? ", " : "", mask_lens[i]);
    fprintf(fp, "]\n\n");

    fclose(fp);
    return 0;
}

/* ---- Corpus smoothing (SE#PCFG-style, -s) ----
 * Reserves a fraction of each terminal distribution's mass for corpus words
 * not observed in training.  Injected as pseudo-counts into the counters
 * before saving, so probabilities written to disk come out consistent.
 * Corpus layout: JudySL letter ("N", or "_" for the fallback-A corpus) →
 * JudyL codepoint-length → JudySL word → 1. */
static void corpus_add_word(Pvoid_t *corpus, char letter, const char *word) {
    char lkey[2] = { letter ? letter : '_', '\0' };
    Word_t *lp;
    JSLI(lp, *corpus, (uint8_t *)lkey);
    /* lp is the slot holding the letter → length-map pointer */
    Word_t *lp2;
    JLI(lp2, *(Pvoid_t *)lp, (Word_t)utf8_cplen(word, (int)strlen(word)));
    /* lp2 is the slot holding the length → word-set pointer */
    Word_t *wp;
    JSLI(wp, *(Pvoid_t *)lp2, (uint8_t *)word);
    *wp = 1;
}

static void smooth_inject(Counter *c, Pvoid_t *words, double frac) {
    /* observed total */
    int64_t total = 0;
    uint8_t idx[PCFG_MAXLINE];
    Word_t *pv;
    idx[0] = '\0';
    JSLF(pv, *c, idx);
    while (pv) { total += (int64_t)*pv; JSLN(pv, *c, idx); }
    if (total <= 0) return;

    /* corpus words this type has never seen */
    char **unobs = NULL;
    int n = 0, cap = 0;
    idx[0] = '\0';
    JSLF(pv, *words, idx);
    while (pv) {
        Word_t *hit;
        JSLG(hit, *c, idx);
        if (!hit) {
            if (n >= cap) {
                cap = cap ? cap * 2 : 64;
                unobs = realloc(unobs, cap * sizeof(char *));
                if (!unobs) return;
            }
            unobs[n++] = strdup((char *)idx);
        }
        JSLN(pv, *words, idx);
    }
    if (n == 0) { free(unobs); return; }

    int64_t pseudo = (int64_t)ceil((frac / (1.0 - frac)) * (double)total / (double)n);
    if (pseudo < 1) pseudo = 1;
    for (int i = 0; i < n; i++) {
        counter_inc_n(c, unobs[i], pseudo);
        free(unobs[i]);
    }
    free(unobs);
}

static void apply_smoothing(TrainCtx *ctx) {
    if (!ctx->semdir || ctx->smoothing <= 0.0) return;

    Pvoid_t corpus = NULL;
    DIR *dp = opendir(ctx->semdir);
    if (!dp) {
        fprintf(stderr, "pcfg: smoothing: cannot open \"%s\"\n", ctx->semdir);
        return;
    }
    struct dirent *ent;
    int nwords = 0;
    while ((ent = readdir(dp)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot, ".txt") != 0) continue;
        char path[PCFG_MAXPATH];
        snprintf(path, sizeof(path), "%s/%s", ctx->semdir, ent->d_name);
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char line[PCFG_MAXLINE];
        while (fgets(line, sizeof(line), fp)) {
            int len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) len--;
            line[len] = '\0';
            if (len <= 0) continue;
            for (int i = 0; i < len; i++)
                if (line[i] >= 'A' && line[i] <= 'Z') line[i] += 32;
            corpus_add_word(&corpus, ent->d_name[0], line);
            nwords++;
        }
        fclose(fp);
    }
    closedir(dp);
    fprintf(stderr, "pcfg: smoothing: %d corpus words, mass fraction %.2f\n",
            nwords, ctx->smoothing);

    /* fallback corpus → plain A terminals, per length */
    if (SemHaveFallback) {
        Word_t *lp;
        JSLG(lp, corpus, (const uint8_t *)"_");
        if (lp) {
            Pvoid_t bylen = *(Pvoid_t *)lp;
            Word_t len = 0;
            Word_t *cl;
            JLF(cl, bylen, len);
            while (cl) {
                Word_t *ac;
                JLG(ac, ctx->cnt_alpha, len);
                if (ac) smooth_inject((Counter *)ac, (Pvoid_t *)cl, ctx->smoothing);
                JLN(cl, bylen, len);
            }
        }
    }

    /* category corpora → semantic terminals, per type key */
    for (int L = 0; L < 256; L++) {
        if (!SemLetters[L]) continue;
        char lkey[2] = { (char)L, '\0' };
        Word_t *lp;
        JSLG(lp, corpus, (uint8_t *)lkey);
        if (!lp) continue;
        Pvoid_t bylen = *(Pvoid_t *)lp;
        Word_t len = 0;
        Word_t *cl;
        JLF(cl, bylen, len);
        while (cl) {
            char tk[PCFG_MAXTYPE];
            snprintf(tk, sizeof(tk), "%c%d", (char)L, (int)len);
            Word_t *sp;
            JSLG(sp, ctx->cnt_sem, (uint8_t *)tk);
            if (sp) smooth_inject((Counter *)sp, (Pvoid_t *)cl, ctx->smoothing);
            JLN(cl, bylen, len);
        }
    }

    /* free corpus */
    uint8_t lidx[2];
    Word_t *lp;
    lidx[0] = '\0';
    JSLF(lp, corpus, lidx);
    while (lp) {
        Pvoid_t bylen = *(Pvoid_t *)lp;
        Word_t len = 0;
        Word_t *cl;
        JLF(cl, bylen, len);
        while (cl) {
            Counter w = *(Counter *)cl;
            counter_free(&w);
            JLN(cl, bylen, len);
        }
        Word_t bytes;
        JLFA(bytes, bylen);
        JSLN(lp, corpus, lidx);
    }
    {
        Word_t bytes;
        JSLFA(bytes, corpus);
    }
}

/* ---- Save complete grammar ---- */
int pcfg_save(const char *outdir, TrainCtx *ctx) {
    char subdir[PCFG_MAXPATH];
    int alpha_lens[256], nalpha = 0;
    int digit_lens[256], ndigits = 0;
    int other_lens[256], nother = 0;
    int kbd_lens[256], nkbd = 0;
    int mask_lens[256], nmask = 0;

    int af = ctx->admit_threshold;
    if (af > 0)
        fprintf(stderr, "pcfg: saving grammar to \"%s\" (admission filter: min count %d)\n", outdir, af);
    else
        fprintf(stderr, "pcfg: saving grammar to \"%s\"\n", outdir);

    /* inject unobserved corpus vocabulary before anything is written */
    apply_smoothing(ctx);

    /* Grammar (base structures — no admission filter) */
    snprintf(subdir, sizeof(subdir), "%s/Grammar", outdir);
    save_flat_counter(subdir, "grammar.txt", ctx->cnt_base);

    /* Also save raw grammar */
    save_flat_counter(subdir, "raw_grammar.txt", ctx->cnt_base);

    /* Alpha (apply admission filter) */
    snprintf(subdir, sizeof(subdir), "%s/Alpha", outdir);
    save_len_counters(subdir, ctx->cnt_alpha, alpha_lens, &nalpha, af);

    /* Capitalization masks */
    snprintf(subdir, sizeof(subdir), "%s/Capitalization", outdir);
    save_len_counters(subdir, ctx->cnt_masks, mask_lens, &nmask, 0);

    /* Digits (apply admission filter) */
    snprintf(subdir, sizeof(subdir), "%s/Digits", outdir);
    save_len_counters(subdir, ctx->cnt_digits, digit_lens, &ndigits, af);

    /* Other (apply admission filter) */
    snprintf(subdir, sizeof(subdir), "%s/Other", outdir);
    save_len_counters(subdir, ctx->cnt_other, other_lens, &nother, af);

    /* Keyboard */
    snprintf(subdir, sizeof(subdir), "%s/Keyboard", outdir);
    save_len_counters(subdir, ctx->cnt_keyboard, kbd_lens, &nkbd, 0);

    /* Leet substitution masks (no admission filter — compact) */
    snprintf(subdir, sizeof(subdir), "%s/Leet", outdir);
    save_len_counters(subdir, ctx->cnt_leet, NULL, NULL, 0);

    /* Date-shaped digit runs */
    snprintf(subdir, sizeof(subdir), "%s/Dates", outdir);
    save_len_counters(subdir, ctx->cnt_dates, NULL, NULL, 0);

    /* Repeated strings */
    snprintf(subdir, sizeof(subdir), "%s/Repeats", outdir);
    save_len_counters(subdir, ctx->cnt_repeats, NULL, NULL, 0);

    /* Semantic terminals — one file per type key, filename IS the key */
    if (ctx->cnt_sem) {
        snprintf(subdir, sizeof(subdir), "%s/Sem", outdir);
        ensure_dir(subdir);
        uint8_t tk[PCFG_MAXTYPE];
        Word_t *pv;
        tk[0] = '\0';
        JSLF(pv, ctx->cnt_sem, tk);
        while (pv) {
            Counter c = (Counter)*pv;
            if (c) {
                CountEntry *entries = NULL;
                int64_t total = 0;
                int count = collect_counter(c, &entries, &total, 0);
                if (count > 0 && total > 0) {
                    char path[PCFG_MAXPATH];
                    snprintf(path, sizeof(path), "%s/%s.txt", subdir, tk);
                    write_prob_file(path, entries, count, total);
                }
                free_entries(entries, count);
            }
            JSLN(pv, ctx->cnt_sem, tk);
        }
    }

    /* Years */
    snprintf(subdir, sizeof(subdir), "%s/Years", outdir);
    save_flat_counter(subdir, "1.txt", ctx->cnt_years);

    /* Context */
    snprintf(subdir, sizeof(subdir), "%s/Context", outdir);
    save_flat_counter(subdir, "1.txt", ctx->cnt_context);

    /* Emails */
    if (ctx->save_sensitive) {
        snprintf(subdir, sizeof(subdir), "%s/Emails", outdir);
        save_flat_counter(subdir, "full_emails.txt", ctx->cnt_email_full);
    }
    if (ctx->cnt_email_prov) {
        snprintf(subdir, sizeof(subdir), "%s/Emails", outdir);
        save_flat_counter(subdir, "email_providers.txt", ctx->cnt_email_prov);
    }

    /* Websites */
    if (ctx->save_sensitive) {
        snprintf(subdir, sizeof(subdir), "%s/Websites", outdir);
        save_flat_counter(subdir, "website_urls.txt", ctx->cnt_web_url);
    }
    if (ctx->cnt_web_host) {
        snprintf(subdir, sizeof(subdir), "%s/Websites", outdir);
        save_flat_counter(subdir, "website_hosts.txt", ctx->cnt_web_host);
        save_flat_counter(subdir, "website_prefixes.txt", ctx->cnt_web_pfx);
    }

    /* Create empty placeholder dirs (matching Go) */
    snprintf(subdir, sizeof(subdir), "%s/Omen", outdir);
    ensure_dir(subdir);
    snprintf(subdir, sizeof(subdir), "%s/Prince", outdir);
    ensure_dir(subdir);
    snprintf(subdir, sizeof(subdir), "%s/Masks", outdir);
    ensure_dir(subdir);

    /* Config.ini */
    write_config(outdir, ctx,
                 alpha_lens, nalpha,
                 digit_lens, ndigits,
                 other_lens, nother,
                 kbd_lens, nkbd,
                 mask_lens, nmask);

    return 0;
}

/* ==================================================================
 * LOADING: Read grammar from disk for generation
 * ================================================================== */

/* ---- Parse a TSV file into GrammarEntryList ---- */
static GrammarEntryList *load_tsv_file(const char *path, Arena *arena) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

    GrammarEntryList *gel = malloc(sizeof(GrammarEntryList));
    if (!gel) { fclose(fp); return NULL; }
    gel->entries = NULL;
    gel->nentries = 0;
    gel->cap = 0;

    char line[PCFG_MAXLINE];
    /* First pass: group values by probability */
    /* Simple approach: collect all entries, then group */

    typedef struct { char *val; double prob; } RawEntry;
    RawEntry *raw = NULL;
    int nraw = 0, rawcap = 0;

    while (fgets(line, sizeof(line), fp)) {
        int len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            len--;
        line[len] = '\0';
        if (len <= 0) continue;

        /* Find tab separator */
        char *tab = strchr(line, '\t');
        if (!tab) continue;

        *tab = '\0';
        /* Parse: "count/total" or plain float */
        char *probstr = tab + 1;
        double prob;
        char *slash = strchr(probstr, '/');
        if (slash) {
            int64_t num = strtoll(probstr, NULL, 10);
            int64_t den = strtoll(slash + 1, NULL, 10);
            prob = (den > 0) ? (double)num / (double)den : 0.0;
        } else {
            prob = strtod(probstr, NULL);
        }

        if (nraw >= rawcap) {
            rawcap = rawcap ? rawcap * 2 : 256;
            raw = realloc(raw, rawcap * sizeof(RawEntry));
        }
        raw[nraw].val = arena_strdup(arena, line);
        raw[nraw].prob = prob;
        nraw++;
    }
    fclose(fp);

    if (nraw == 0) {
        free(gel);
        free(raw);
        return NULL;
    }

    /* Group by probability: entries are already sorted by prob desc in file */
    gel->cap = 64;
    gel->entries = malloc(gel->cap * sizeof(GrammarEntry));

    double cur_prob = -1.0;
    for (int i = 0; i < nraw; i++) {
        if (raw[i].prob != cur_prob) {
            /* New probability group */
            if (gel->nentries >= gel->cap) {
                gel->cap *= 2;
                gel->entries = realloc(gel->entries, gel->cap * sizeof(GrammarEntry));
            }
            GrammarEntry *ge = &gel->entries[gel->nentries];
            ge->prob = raw[i].prob;
            ge->values = malloc(16 * sizeof(char *));
            ge->nvalues = 0;
            ge->cap = 16;
            gel->nentries++;
            cur_prob = raw[i].prob;
        }

        GrammarEntry *ge = &gel->entries[gel->nentries - 1];
        if (ge->nvalues >= ge->cap) {
            ge->cap *= 2;
            ge->values = realloc(ge->values, ge->cap * sizeof(char *));
        }
        ge->values[ge->nvalues++] = raw[i].val;
    }

    free(raw);
    return gel;
}

/* ---- Load base structures from grammar.txt ---- */
static int load_base_structures(const char *path, BaseStructure **bases_out, int *nbases_out) {
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;

    BaseStructure *bases = NULL;
    int nbases = 0, cap = 256;
    bases = malloc(cap * sizeof(BaseStructure));

    char line[PCFG_MAXLINE];
    while (fgets(line, sizeof(line), fp)) {
        int len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            len--;
        line[len] = '\0';
        if (len <= 0) continue;

        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        char *probstr = tab + 1;
        double prob;
        char *slash = strchr(probstr, '/');
        if (slash) {
            int64_t num = strtoll(probstr, NULL, 10);
            int64_t den = strtoll(slash + 1, NULL, 10);
            prob = (den > 0) ? (double)num / (double)den : 0.0;
        } else {
            prob = strtod(probstr, NULL);
        }

        /* Parse base structure string into replacement types */
        /* e.g., "A4C4D2O1" → {"A4","C4","D2","O1"} */
        char *p = line;
        char **repl = malloc(PCFG_MAXSECTIONS * sizeof(char *));
        int nrepl = 0;

        while (*p) {
            char type_buf[PCFG_MAXTYPE];
            int ti = 0;
            if (nrepl >= PCFG_MAXSECTIONS) break;

            /* First char is the type letter */
            type_buf[ti++] = *p++;
            /* Remaining chars are digits */
            while (*p >= '0' && *p <= '9' && ti < PCFG_MAXTYPE - 1)
                type_buf[ti++] = *p++;
            type_buf[ti] = '\0';

            repl[nrepl] = strdup(type_buf);
            nrepl++;
        }

        if (nbases >= cap) {
            cap *= 2;
            bases = realloc(bases, cap * sizeof(BaseStructure));
        }
        bases[nbases].prob = prob;
        bases[nbases].replacements = repl;
        bases[nbases].nreplace = nrepl;
        nbases++;
    }

    fclose(fp);
    *bases_out = bases;
    *nbases_out = nbases;
    return 0;
}

/* ---- Load full grammar for generation ---- */
int pcfg_load(const char *ruledir, GenCtx *ctx) {
    Arena arena;
    arena_init(&arena, 1024 * 1024);
    char path[PCFG_MAXPATH];

    /* Load base structures */
    snprintf(path, sizeof(path), "%s/Grammar/grammar.txt", ruledir);
    if (load_base_structures(path, &ctx->bases, &ctx->nbases) < 0) {
        fprintf(stderr, "pcfg: cannot load grammar from \"%s\"\n", path);
        return -1;
    }
    fprintf(stderr, "pcfg: loaded %d base structures\n", ctx->nbases);

    /* Scan for files and load each type
     * We need to discover which length files exist for each type directory */
    const char *dirs[] = { "Alpha", "Digits", "Other", "Keyboard",
                           "Capitalization", "Leet", "Dates", "Repeats",
                           "Years", "Context" };
    const char *prefixes[] = { "A", "D", "O", "K", "C", "L", "B", "R", "Y", "X" };
    int ndirs = sizeof(dirs) / sizeof(dirs[0]);

    for (int d = 0; d < ndirs; d++) {
        snprintf(path, sizeof(path), "%s/%s", ruledir, dirs[d]);
        DIR *dp = opendir(path);
        if (!dp) continue;

        struct dirent *ent;
        while ((ent = readdir(dp)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char *dot = strrchr(ent->d_name, '.');
            if (!dot || strcmp(dot, ".txt") != 0) continue;

            /* Extract number from filename (e.g., "4.txt" → 4) */
            int num = atoi(ent->d_name);

            char filepath[PCFG_MAXPATH];
            snprintf(filepath, sizeof(filepath), "%s/%s/%s",
                     ruledir, dirs[d], ent->d_name);

            GrammarEntryList *gel = load_tsv_file(filepath, &arena);
            if (!gel) continue;

            /* Build type key (e.g., "A4", "D2", "Y1", "X1") */
            char typekey[PCFG_MAXTYPE];
            if (strcmp(dirs[d], "Years") == 0 || strcmp(dirs[d], "Context") == 0)
                snprintf(typekey, sizeof(typekey), "%s1", prefixes[d]);
            else
                snprintf(typekey, sizeof(typekey), "%s%d", prefixes[d], num);

            /* Store in grammar JudySL */
            Word_t *pv;
            JSLI(pv, ctx->grammar, (uint8_t *)typekey);
            *pv = (Word_t)gel;
        }
        closedir(dp);
    }

    /* Semantic type files: the filename IS the type key ("N4.txt" → "N4") */
    snprintf(path, sizeof(path), "%s/Sem", ruledir);
    DIR *sdp = opendir(path);
    if (sdp) {
        struct dirent *ent;
        while ((ent = readdir(sdp)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char *dot = strrchr(ent->d_name, '.');
            if (!dot || strcmp(dot, ".txt") != 0) continue;

            char typekey[PCFG_MAXTYPE];
            snprintf(typekey, sizeof(typekey), "%.*s",
                     (int)(dot - ent->d_name), ent->d_name);

            char filepath[PCFG_MAXPATH];
            snprintf(filepath, sizeof(filepath), "%s/Sem/%s", ruledir, ent->d_name);

            GrammarEntryList *gel = load_tsv_file(filepath, &arena);
            if (!gel) continue;

            Word_t *pv;
            JSLI(pv, ctx->grammar, (uint8_t *)typekey);
            *pv = (Word_t)gel;
        }
        closedir(sdp);
    }

    return 0;
}

/* ==================================================================
 * MODEL MERGE: Combine two grammar directories
 * ================================================================== */

/* Load a TSV file into a JudySL counter (value → count) */
static void load_tsv_to_counter(const char *path, Counter *c) {
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
            /* Float format: approximate count as 1 */
            count = 1;
        }
        Word_t *pv;
        JSLI(pv, *c, (uint8_t *)line);
        *pv += (Word_t)count;
    }
    fclose(fp);
}

/* Merge one directory of TSV files (e.g., Alpha/1.txt, Alpha/2.txt...) */
static void merge_dir(const char *dir1, const char *dir2, const char *outdir,
                      const char *subname, int admit_min) {
    char path1[PCFG_MAXPATH], path2[PCFG_MAXPATH], pathout[PCFG_MAXPATH];
    char fulldir[PCFG_MAXPATH];
    snprintf(fulldir, sizeof(fulldir), "%s/%s", outdir, subname);
    ensure_dir(fulldir);

    /* Collect all .txt filenames from both dirs */
    char filenames[512][64];
    int nfiles = 0;

    for (int d = 0; d < 2; d++) {
        const char *base = (d == 0) ? dir1 : dir2;
        char dirpath[PCFG_MAXPATH];
        snprintf(dirpath, sizeof(dirpath), "%s/%s", base, subname);
        DIR *dp = opendir(dirpath);
        if (!dp) continue;
        struct dirent *ent;
        while ((ent = readdir(dp)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char *dot = strrchr(ent->d_name, '.');
            if (!dot || strcmp(dot, ".txt") != 0) continue;
            /* Check if already in list */
            int found = 0;
            for (int i = 0; i < nfiles; i++)
                if (strcmp(filenames[i], ent->d_name) == 0) { found = 1; break; }
            if (!found && nfiles < 512) {
                strncpy(filenames[nfiles], ent->d_name, 63);
                filenames[nfiles][63] = '\0';
                nfiles++;
            }
        }
        closedir(dp);
    }

    /* For each file, merge counters */
    for (int i = 0; i < nfiles; i++) {
        Counter c = NULL;
        snprintf(path1, sizeof(path1), "%s/%s/%s", dir1, subname, filenames[i]);
        snprintf(path2, sizeof(path2), "%s/%s/%s", dir2, subname, filenames[i]);
        load_tsv_to_counter(path1, &c);
        load_tsv_to_counter(path2, &c);
        if (!c) continue;

        CountEntry *entries;
        int64_t total;
        int count = collect_counter(c, &entries, &total, admit_min);
        if (count > 0 && total > 0) {
            snprintf(pathout, sizeof(pathout), "%s/%s/%s", outdir, subname, filenames[i]);
            write_prob_file(pathout, entries, count, total);
        }
        free_entries(entries, count);
        Word_t bytes;
        JSLFA(bytes, c);
        (void)bytes;
    }
}

int pcfg_merge(const char *dir1, const char *dir2, const char *outdir) {
    fprintf(stderr, "pcfg: merging \"%s\" + \"%s\" → \"%s\"\n", dir1, dir2, outdir);

    const char *dirs[] = {
        "Grammar", "Alpha", "Capitalization", "Digits", "Other",
        "Keyboard", "Leet", "Dates", "Repeats", "Sem", "Years", "Context",
        "Emails", "Websites", NULL
    };

    ensure_dir(outdir);
    for (int i = 0; dirs[i]; i++)
        merge_dir(dir1, dir2, outdir, dirs[i], 0);

    /* Copy Omen from dir1 if it exists.  The n-gram tables are not
     * mergeable, so the first grammar's OMEN data is carried across
     * intact.  Creating the directory is not enough on its own: without
     * the files, omen_load() fails and -A reports "AHF requires OMEN
     * training data in grammar" on every merged grammar. */
    char src[PCFG_MAXPATH], dst[PCFG_MAXPATH];
    snprintf(dst, sizeof(dst), "%s/Omen", outdir);
    ensure_dir(dst);
    {
        char omensrc[PCFG_MAXPATH];
        snprintf(omensrc, sizeof(omensrc), "%s/Omen", dir1);
        DIR *od = opendir(omensrc);
        if (od) {
            struct dirent *de;
            int copied = 0;
            while ((de = readdir(od)) != NULL) {
                if (de->d_name[0] == '.') continue;
                snprintf(src, sizeof(src), "%s/Omen/%s", dir1, de->d_name);
                snprintf(dst, sizeof(dst), "%s/Omen/%s", outdir, de->d_name);
                if (copy_file(src, dst) == 0) copied++;
            }
            closedir(od);
            if (copied)
                fprintf(stderr, "pcfg: copied %d OMEN file%s from \"%s\"\n",
                        copied, copied == 1 ? "" : "s", dir1);
        }
    }

    /* Copy config.ini from dir1 */
    snprintf(src, sizeof(src), "%s/config.ini", dir1);
    snprintf(dst, sizeof(dst), "%s/config.ini", outdir);
    FILE *fin = fopen(src, "r");
    if (fin) {
        FILE *fout = fopen(dst, "w");
        if (fout) {
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), fin)) > 0)
                fwrite(buf, 1, n, fout);
            fclose(fout);
        }
        fclose(fin);
    }

    fprintf(stderr, "pcfg: merge complete\n");
    return 0;
}
