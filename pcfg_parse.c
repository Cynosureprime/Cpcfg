/*
 * pcfg_parse.c - Password decomposition into typed sections
 *
 * 8 sequential detectors:
 *   1. Keyboard walks → K{len}
 *   2. Emails → E
 *   3. Websites → W
 *   4. Years (19XX/20XX) → Y1
 *   5. Context-sensitive patterns → X1
 *   6. Alpha runs → A{len} (multiword splits if trie available)
 *   7. Digit runs → D{len}
 *   8. Other/special → O{len}
 *
 * Single-pass tag array for years/context/keyboard/email/website,
 * then left-to-right scan for alpha/digit/other runs.
 *
 * Base structure does NOT include C (capitalization) entries.
 * C entries are added at generation time (matching Go's approach).
 */

#include "pcfg.h"
#include <dirent.h>

MultiWordTrie *GlobalMultiTrie = NULL;

static inline unsigned char fast_lower(unsigned char c);

/* ---- Semantic tagging state (-E) and repeated-string flag (-R) ---- */
Pvoid_t SemMap;                    /* folded word → category letter (0 = fallback corpus) */
unsigned char SemLetters[256];
int SemHaveFallback;
int DetectRepeats;

/* Type letters already used by the grammar; category files may not take them */
static const char *sem_reserved = "ADOYXKEWCMLBR";

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int sem_load(const char *dir) {
    DIR *dp = opendir(dir);
    if (!dp) return -1;
    struct dirent *ent;
    int ncats = 0;

    /* Collect and sort filenames: when a word appears in several category
     * files, the alphabetically first file wins — deterministic and
     * controllable via file naming. */
    char **names = NULL;
    int nnames = 0, capnames = 0;
    while ((ent = readdir(dp)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char *dot = strrchr(ent->d_name, '.');
        if (!dot || strcmp(dot, ".txt") != 0) continue;
        if (nnames >= capnames) {
            int newcap = capnames ? capnames * 2 : 32;
            char **grown = realloc(names, newcap * sizeof(char *));
            if (!grown) {
                for (int k = 0; k < nnames; k++) free(names[k]);
                free(names);
                closedir(dp);
                return -1;
            }
            names = grown;
            capnames = newcap;
        }
        names[nnames] = strdup(ent->d_name);
        if (names[nnames]) nnames++;
    }
    closedir(dp);
    if (nnames > 1) qsort(names, nnames, sizeof(char *), cmp_str);

    for (int fi = 0; fi < nnames; fi++) {
        const char *dname = names[fi];
        int letter = (unsigned char)dname[0];
        if (letter == '_') {
            letter = 0;                    /* fallback corpus for plain A */
            SemHaveFallback = 1;
        } else {
            if (letter < 'A' || letter > 'Z' ||
                strchr(sem_reserved, letter)) {
                /* Skip, do not abort.  One stray README.txt in the category
                 * directory used to disable -E for the whole run. */
                fprintf(stderr,
                        "pcfg: semantic file \"%s\": type letter '%c' is %s"
                        " - file ignored\n", dname, letter,
                        strchr(sem_reserved, letter) ? "reserved by the grammar"
                                                     : "not A-Z or _");
                continue;
            }
            if (!SemLetters[letter]) {
                SemLetters[letter] = 1;
                ncats++;
            }
        }

        char path[PCFG_MAXPATH];
        snprintf(path, sizeof(path), "%s/%s", dir, dname);
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char line[PCFG_MAXLINE];
        while (fgets(line, sizeof(line), fp)) {
            int len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                len--;
            line[len] = '\0';
            if (len <= 0) continue;
            char key[PCFG_MAXLINE];
            pcfg_fold_word(line, len, key, sizeof(key));
            if (!key[0]) continue;
            Word_t *pv;
            JSLI(pv, SemMap, (uint8_t *)key);
            /* First file wins, which is what the comment above promises.
             * Assigning unconditionally gave the LAST file the word, because
             * the names are walked in ascending order: a word in both
             * Names.txt and Places.txt came out a Place. */
            if (*pv == 0) *pv = (Word_t)(letter + 1);
        }
        fclose(fp);
    }
    for (int k = 0; k < nnames; k++) free(names[k]);
    free(names);
    return ncats;
}

void sem_free(void) {
    Word_t bytes;
    JSLFA(bytes, SemMap);
    SemMap = NULL;
    memset(SemLetters, 0, sizeof(SemLetters));
    SemHaveFallback = 0;
}

static char sem_lookup(const char *w) {
    if (!SemMap) return 0;
    Word_t *pv;
    JSLG(pv, SemMap, (const uint8_t *)w);
    /* Stored as letter + 1, so that a freshly inserted slot - which Judy
     * zeroes - is distinguishable from a real entry.  A fallback-corpus word
     * stores 1 and reads back as 0: known word, but no category tag. */
    return pv ? (char)(*pv - 1) : 0;
}

/*
 * Leet folding table: ASCII char → base letter, 0 = not a leet char.
 * A leet char is folded into the surrounding alpha run only when it sits
 * between letters (see the alpha branch in pcfg_parse), so digit runs and
 * separators are left alone.  The same table drives multiword training and
 * mask application at generation time.
 */
const unsigned char leet_fold[256] = {
    ['0'] = 'o', ['1'] = 'i', ['3'] = 'e', ['4'] = 'a',
    ['5'] = 's', ['7'] = 't',
    ['@'] = 'a', ['$'] = 's', ['!'] = 'i'
};

static inline unsigned char fast_lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static inline int is_leet_char(unsigned char c) {
    return leet_fold[c] != 0;
}

/* Fold one alpha run to the key the semantic map is stored under: leet
 * characters to their base letter, everything else to lowercase, each in the
 * byte width it arrived in.
 *
 * This exists because sem_load() and the parser used to fold differently.
 * sem_load() lowered with an ASCII-only table, so a category word carrying a
 * non-ASCII capital was stored under a key nothing could ever look up:
 * "MULLER" with U+00DC became "m<DC>ller" while the parser produced
 * "m<FC>ller".  A German or Turkish names list in its natural capitalisation
 * was almost entirely inert, and said nothing about it.  One fold, used by
 * both sides, is the only way that stays fixed.
 *
 * Width-preserving, so a caller may keep using byte offsets taken from the
 * unfolded run - which is what the multiword split does.
 *
 * Returns the folded length; out must hold outmax >= len + 5 bytes.
 */
/* As pcfg_fold_word(), but also records the leet mask: one character per
 * codepoint, the original character where a leet substitution was folded away
 * and '.' where it was not.  mask must hold outmax bytes.
 *
 * pcfg_train.c and pcfg_diff.c each had their own copy of this loop, and they
 * had already drifted - the -D copy widened a lone high byte where the -t copy
 * did not, so -D could report a terminal as missing from the very grammar -t
 * had just written it into.  Two readings of one grammar have to fold
 * identically or the diagnosis is about the fold, not the grammar.
 *
 * Returns the folded byte length; the mask length is the codepoint count.
 */
int pcfg_fold_leet(const char *s, int len, char *out, int outmax, char *mask) {
    int o = 0, k = 0, i = 0;
    while (i < len && o < outmax - 5) {
        uint32_t cp;
        int n = utf8_decode(s + i, len - i, &cp);
        if (n == 0) break;
        unsigned char fold = (n == 1) ? leet_fold[(unsigned char)s[i]] : 0;
        if (fold) {
            out[o++] = (char)fold;
            mask[k++] = s[i];
        } else {
            o += utf8_encode_width(out + o, utf8_to_lower(cp), n);
            mask[k++] = '.';
        }
        i += n;
    }
    out[o] = '\0';
    mask[k] = '\0';
    return o;
}

int pcfg_fold_word(const char *s, int len, char *out, int outmax) {
    int o = 0, i = 0;
    while (i < len && o < outmax - 5) {
        uint32_t cp;
        int n = utf8_decode(s + i, len - i, &cp);
        if (n == 0) break;
        unsigned char fold = (n == 1) ? leet_fold[(unsigned char)s[i]] : 0;
        if (fold)
            out[o++] = (char)fold;
        else
            o += utf8_encode_width(out + o, utf8_to_lower(cp), n);
        i += n;
    }
    out[o] = '\0';
    return o;
}

/* Context-sensitive patterns (from Go source) — with precomputed lengths */
static const struct { const char *pat; int len; } context_pats[] = {
    {";p",2}, {":p",2}, {"*0*",3}, {"#1",2},
    {"No.1",4}, {"no.1",4}, {"No.",3}, {"i<3",3}, {"I<3",3}, {"<3",2},
    {"Mr.",3}, {"mr.",3}, {"MR.",3},
    {"MS.",3}, {"Ms.",3}, {"ms.",3},
    {"Mz.",3}, {"mz.",3}, {"MZ.",3},
    {"St.",3}, {"st.",3},
    {"Dr.",3}, {"dr.",3}
};
/* Legacy exports for pcfg.h compatibility */
const char *context_patterns[] = {
    ";p", ":p", "*0*", "#1",
    "No.1", "no.1", "No.", "i<3", "I<3", "<3",
    "Mr.", "mr.", "MR.",
    "MS.", "Ms.", "ms.",
    "Mz.", "mz.", "MZ.",
    "St.", "st.",
    "Dr.", "dr."
};
int n_context_patterns = sizeof(context_patterns) / sizeof(context_patterns[0]);
#define N_CONTEXT_PATS (sizeof(context_pats)/sizeof(context_pats[0]))

/* TLD list — with precomputed lengths */
static const struct { const char *tld; int len; } tld_table[] = {
    {".com",4}, {".org",4}, {".edu",4}, {".gov",4}, {".mil",4}, {".net",4},
    {".us",3}, {".uk",3}, {".ca",3}, {".de",3}, {".jp",3}, {".fr",3},
    {".au",3}, {".ru",3}, {".ch",3}, {".it",3}, {".nl",3}, {".se",3},
    {".no",3}, {".es",3}, {".cn",3}, {".in",3}, {".br",3}, {".mx",3},
    {".kr",3}, {".za",3}, {".pl",3}, {".tr",3}, {".ir",3}, {".id",3},
    {".sg",3}, {".hk",3}, {".tw",3}, {".vn",3}, {".ar",3}, {".cl",3},
    {".nz",3}, {".be",3}, {".fi",3}, {".dk",3},
    {".info",5}, {".biz",4}, {".xyz",4}, {".online",7}, {".site",5},
    {".top",4}, {".club",5}, {".live",5}, {".shop",5}, {".store",6},
    {".tech",5}, {".app",4}, {".dev",4}, {".blog",5}, {".cloud",6},
    {".co",3}, {".io",3}, {".ai",3}, {".me",3}, {".gg",3}, {".tv",3},
    {".cc",3}, {".pw",3}, {".name",5}, {".pro",4}, {".win",4},
    {".loan",5}, {".click",6}
};
#define N_TLDS (sizeof(tld_table)/sizeof(tld_table[0]))
/* Legacy exports */
const char *tld_list[] = {
    ".com", ".org", ".edu", ".gov", ".mil", ".net",
    ".us", ".uk", ".ca", ".de", ".jp", ".fr", ".au", ".ru",
    ".ch", ".it", ".nl", ".se", ".no", ".es", ".cn", ".in",
    ".br", ".mx", ".kr", ".za", ".pl", ".tr", ".ir", ".id",
    ".sg", ".hk", ".tw", ".vn", ".ar", ".cl", ".nz", ".be",
    ".fi", ".dk",
    ".info", ".biz", ".xyz", ".online", ".site", ".top",
    ".club", ".live", ".shop", ".store", ".tech", ".app",
    ".dev", ".blog", ".cloud",
    ".co", ".io", ".ai", ".me", ".gg", ".tv", ".cc", ".pw",
    ".name", ".pro", ".win", ".loan", ".click"
};
int n_tlds = sizeof(tld_list) / sizeof(tld_list[0]);

/* Fast type string: "X" + int → "X123" */
static inline int make_type(char *buf, char prefix, int num) {
    buf[0] = prefix;
    if (num < 10) { buf[1] = '0' + num; buf[2] = '\0'; return 2; }
    if (num < 100) { buf[1] = '0' + num/10; buf[2] = '0' + num%10; buf[3] = '\0'; return 3; }
    buf[1] = '0' + num/100; buf[2] = '0' + (num/10)%10; buf[3] = '0' + num%10; buf[4] = '\0';
    return 4;
}

/* Set all section fields at once */
static inline void set_section(Section *s, char *value, int vlen,
                               char prefix, int num) {
    s->value = value;
    s->vlen = vlen;
    s->tnum = num;
    make_type(s->type, prefix, num);
}

/* Set section with literal type string (Y1, X1, E, W) */
static inline void set_section_str(Section *s, char *value, int vlen,
                                   const char *type, int tnum) {
    s->value = value;
    s->vlen = vlen;
    s->tnum = tnum;
    /* type is short, just copy */
    int i = 0;
    while (type[i] && i < PCFG_MAXTYPE - 1) { s->type[i] = type[i]; i++; }
    s->type[i] = '\0';
}


/* Build case mask for an alpha section (UTF-8 aware).
 * Outputs one U/L per codepoint, not per byte. */
void build_case_mask(const char *alpha, int bytelen, char *mask) {
    int mi = 0, i = 0;
    while (i < bytelen) {
        uint32_t cp;
        int n = utf8_decode(alpha + i, bytelen - i, &cp);
        if (n == 0) break;
        mask[mi++] = utf8_is_upper(cp) ? 'U' : 'L';
        i += n;
    }
    mask[mi] = '\0';
}

/* Build base structure from sections.
 * Go-compatible: does NOT include C entries. C is added at generation time.
 * Rejects base structures containing W or E (unsupported for guessing).
 */
void build_base_structure(Section *sects, int nsects, char *out, int outlen) {
    int pos = 0;
    for (int i = 0; i < nsects && pos < outlen - PCFG_MAXTYPE; i++) {
        if (sects[i].type[0] == ST_EMAIL || sects[i].type[0] == ST_WEBSITE) {
            /* Mark as unsupported — Go skips these */
            out[0] = '\0';
            return;
        }

        int len = strlen(sects[i].type);
        memcpy(out + pos, sects[i].type, len);
        pos += len;
    }
    out[pos] = '\0';
}

/*
 * Byte tags for marking detected patterns before the main scan.
 */
#define TAG_NONE   0
#define TAG_YEAR   1
#define TAG_CTX    2
#define TAG_KBD    3
#define TAG_EMAIL  4
#define TAG_WEB    5
#define TAG_DATE   6
#define TAG_REPEAT 7
#define TAG_KBD1   8   /* first byte of a walk; see phase 1a and phase 2 */

/* ---- Date-shaped digit runs ----
 * A maximal digit run of exactly 6 or 8 digits is tagged as a date when any
 * common interpretation is calendar-valid (leap years included):
 *   8: YYYYMMDD, DDMMYYYY, MMDDYYYY
 *   6: YYMMDD, DDMMYY, MMDDYY   (YY 00-29 → 20xx, 30-99 → 19xx)
 */
static int dim_month(int m, int y) {
    static const int dim[13] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
    if (m == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0)) return 29;
    return dim[m];
}

static int ok_ymd(int y, int m, int d) {
    return y >= 1900 && y <= 2099 && m >= 1 && m <= 12 &&
           d >= 1 && d <= dim_month(m, y);
}

static int dt2(const char *p) { return (p[0] - '0') * 10 + (p[1] - '0'); }
static int dt4(const char *p) { return dt2(p) * 100 + dt2(p + 2); }

static int is_date_run(const char *s, int n) {
    if (n == 8) {
        if (ok_ymd(dt4(s),     dt2(s + 4), dt2(s + 6))) return 1;  /* YYYYMMDD */
        if (ok_ymd(dt4(s + 4), dt2(s + 2), dt2(s)    )) return 1;  /* DDMMYYYY */
        if (ok_ymd(dt4(s + 4), dt2(s),     dt2(s + 2))) return 1;  /* MMDDYYYY */
        return 0;
    }
    if (n == 6) {
        int yy = dt2(s);
        int y = yy >= 30 ? 1900 + yy : 2000 + yy;
        if (ok_ymd(y, dt2(s + 2), dt2(s + 4))) return 1;           /* YYMMDD */
        if (ok_ymd(y, dt2(s + 2), dt2(s)    )) return 1;           /* DDMMYY */
        if (ok_ymd(y, dt2(s),     dt2(s + 2))) return 1;           /* MMDDYY */
        return 0;
    }
    return 0;
}

/* Declare keyboard walk detection from pcfg_keyboard.c */
typedef struct { int start; int len; } KbdWalk;
int detect_keyboard_walks(const char *pw, int pwlen, KbdWalk *walks, int max_walks);

/* ---- Email detection ----
 * Looks for @provider.tld pattern. Returns email end position or -1.
 */
static int detect_email_in(const char *pw, int pwlen, char *lower,
                           int *email_start, int *email_end,
                           char *provider, int *provlen) {
    /* Need both @ and . */
    char *at = memchr(pw, '@', pwlen);
    if (!at) return 0;
    char *dot = memchr(pw, '.', pwlen);
    if (!dot) return 0;

    /* Make lowercase copy for TLD matching */
    for (int i = 0; i < pwlen; i++)
        lower[i] = fast_lower((unsigned char)pw[i]);
    lower[pwlen] = '\0';

    for (int t = 0; t < (int)N_TLDS; t++) {
        const char *tld = tld_table[t].tld;
        int tlen = tld_table[t].len;

        char *found = strstr(lower, tld);
        if (!found) continue;

        int tld_pos = found - lower;
        int end_pos = tld_pos + tlen;

        int at_pos = -1;
        for (int j = tld_pos - 1; j >= 0; j--) {
            if (lower[j] == '@') { at_pos = j; break; }
        }
        if (at_pos < 0) continue;

        *provlen = tld_pos - at_pos - 1;
        if (*provlen <= 0 || *provlen >= 256) continue;
        memcpy(provider, lower + at_pos + 1, *provlen);
        provider[*provlen] = '\0';

        *email_start = 0;
        *email_end = end_pos;
        return 1;
    }
    return 0;
}

/* ---- Website detection ----
 * Looks for domain.tld pattern with optional http/www prefix.
 */
static int detect_website_in(const char *pw, int pwlen, char *lower,
                             int *web_start, int *web_end,
                             char *host, int *hostlen,
                             char *prefix, int *pfxlen) {
    if (!memchr(pw, '.', pwlen)) return 0;

    for (int i = 0; i < pwlen; i++)
        lower[i] = fast_lower((unsigned char)pw[i]);
    lower[pwlen] = '\0';

    for (int t = 0; t < (int)N_TLDS; t++) {
        const char *tld = tld_table[t].tld;
        int tlen = tld_table[t].len;

        char *found = strstr(lower, tld);
        if (!found) continue;

        int tld_pos = found - lower;
        int end_pos = tld_pos + tlen;

        /* Boundary check: char after TLD must not be alnum or hyphen */
        if (end_pos < pwlen) {
            unsigned char c = (unsigned char)lower[end_pos];
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')
                continue;
        }

        /* Scan forward for URL chars */
        while (end_pos < pwlen) {
            unsigned char c = (unsigned char)lower[end_pos];
            if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                c == '.' || c == '-' || c == '_' || c == '/' || c == '?' ||
                c == ':' || c == '#' || c == '=' || c == '&' || c == '%')
                end_pos++;
            else
                break;
        }

        /* Find domain start */
        int dom_start = 0;
        for (int j = tld_pos - 1; j >= 0; j--) {
            if (lower[j] == '.' || lower[j] == '/' || lower[j] == ':' || lower[j] == ' ') {
                dom_start = j + 1;
                break;
            }
        }

        /* Extract host */
        *hostlen = tld_pos + tlen - dom_start;
        if (*hostlen <= 0 || *hostlen >= 256) continue;
        memcpy(host, lower + dom_start, *hostlen);
        host[*hostlen] = '\0';

        /* Check for prefix */
        *pfxlen = 0;
        *web_start = dom_start;
        /* Check for URL prefix: one compare for "http", then branch */
        if (dom_start >= 7 && strncmp(lower + dom_start - 7, "http", 4) == 0) {
            char *hp = lower + dom_start - 7 + 4;
            if (dom_start >= 12 && strncmp(hp, "s://www.", 8) == 0) {
                *web_start = dom_start - 12; strcpy(prefix, "https://www."); *pfxlen = 12;
            } else if (dom_start >= 11 && strncmp(hp, "://www.", 6) == 0) {
                *web_start = dom_start - 11; strcpy(prefix, "http://www."); *pfxlen = 11;
            } else if (strncmp(hp, "s://", 4) == 0) {
                *web_start = dom_start - 8; strcpy(prefix, "https://"); *pfxlen = 8;
            } else if (strncmp(hp, "://", 3) == 0) {
                *web_start = dom_start - 7; strcpy(prefix, "http://"); *pfxlen = 7;
            }
        } else if (dom_start >= 4 && strncmp(lower + dom_start - 4, "www.", 4) == 0) {
            *web_start = dom_start - 4; strcpy(prefix, "www."); *pfxlen = 4;
        }

        *web_end = end_pos;
        return 1;
    }
    return 0;
}

/*
 * pcfg_parse - Full password decomposition
 *
 * Phase 1: Tag keyboard walks, emails, websites, years, context patterns
 * Phase 2: Scan left-to-right, classify untagged bytes into alpha/digit/other
 */
int pcfg_parse(char *pw, int pwlen, Section *sects, int maxsects,
               unsigned char *tag, char *lower) {
    if (pwlen <= 0 || maxsects <= 0 || pwlen >= PCFG_MAXLINE) return 0;

    memset(tag, TAG_NONE, pwlen);

    /* Phase 1a: Keyboard walks */
    KbdWalk walks[16];
    int nwalks = detect_keyboard_walks(pw, pwlen, walks, 16);
    /* Reported by matrix (github.com/matrix) in hpcfg's README.
     * Mark where each walk BEGINS.  Phase 2 used to collect a run of TAG_KBD
     * and emit it as one section, so two adjacent walks merged: 1qaz2wsx3edc
     * became a single rare K12 instead of the three common terminals 1qaz,
     * 2wsx and 3edc.  Adjacent walks are the normal case -- that is how the
     * pattern is typed -- so the merge cost the frequent terminals and
     * manufactured a rare one. */
    for (int w = 0; w < nwalks; w++) {
        for (int j = walks[w].start; j < walks[w].start + walks[w].len; j++)
            tag[j] = TAG_KBD;
        tag[walks[w].start] = TAG_KBD1;
    }

    /* Phase 1b: Email detection (only on untagged regions) */
    /* Simple: check entire password for email pattern */
    int em_start, em_end, provlen;
    char provider[256];
    if (detect_email_in(pw, pwlen, lower, &em_start, &em_end, provider, &provlen)) {
        int ok = 1;
        for (int j = em_start; j < em_end; j++)
            if (tag[j] != TAG_NONE) { ok = 0; break; }
        if (ok) {
            for (int j = em_start; j < em_end; j++)
                tag[j] = TAG_EMAIL;
        }
    }

    /* Phase 1c: Website detection */
    int wb_start, wb_end, hostlen, pfxlen;
    char host[256], pfx[64];
    if (detect_website_in(pw, pwlen, lower, &wb_start, &wb_end, host, &hostlen, pfx, &pfxlen)) {
        int ok = 1;
        for (int j = wb_start; j < wb_end; j++)
            if (tag[j] != TAG_NONE) { ok = 0; break; }
        if (ok) {
            for (int j = wb_start; j < wb_end; j++)
                tag[j] = TAG_WEB;
        }
    }

    /* Phase 1d: Years (19XX/20XX) */
    for (int j = 0; j + 3 < pwlen; j++) {
        /* Reported by matrix (github.com/matrix) in hpcfg's README.
         * All four bytes must be free, not just the first.  Testing tag[j] and
         * then writing tag[j..j+3] overwrote whatever an earlier pass owned:
         * "2009ol." tagged 9ol. as a walk, the year then claimed 2009 and took
         * the '9' with it, leaving "ol." as a three-byte keyboard terminal --
         * a K3, which detect_keyboard_walks can never produce because it
         * requires four.  The website pass below already does it this way. */
        int yfree = 1;
        for (int k = 0; k < 4; k++)
            if (tag[j+k] != TAG_NONE) { yfree = 0; break; }
        if (!yfree) continue;
        if ((pw[j] == '1' && pw[j+1] == '9') ||
            (pw[j] == '2' && pw[j+1] == '0')) {
            if (pw[j+2] >= '0' && pw[j+2] <= '9' &&
                pw[j+3] >= '0' && pw[j+3] <= '9') {
                if (j > 0 && pw[j-1] >= '0' && pw[j-1] <= '9') continue;
                if (j + 4 < pwlen && pw[j+4] >= '0' && pw[j+4] <= '9') continue;
                tag[j] = tag[j+1] = tag[j+2] = tag[j+3] = TAG_YEAR;
            }
        }
    }

    /* Phase 1d-2: Date-shaped digit runs (6 or 8 digits) */
    for (int j = 0; j < pwlen; ) {
        if (tag[j] != TAG_NONE || pw[j] < '0' || pw[j] > '9') { j++; continue; }
        int rs = j;
        int clean = 1;
        while (j < pwlen && pw[j] >= '0' && pw[j] <= '9') {
            if (tag[j] != TAG_NONE) clean = 0;
            j++;
        }
        int rl = j - rs;
        if (clean && (rl == 6 || rl == 8) && is_date_run(pw + rs, rl)) {
            for (int k = 0; k < rl; k++) tag[rs + k] = TAG_DATE;
        }
    }

    /* Phase 1e-2: Repeated strings ("haha", "123123", "qazqazqaz").
     * Claims digit and alpha runs that are 2+ copies of a unit of 2+
     * bytes: memcmp(p, p+u, n-u) == 0 means period u. */
    if (DetectRepeats) {
        for (int i = 0; i < pwlen; ) {
            if (tag[i] != TAG_NONE) { i++; continue; }
            unsigned char c = (unsigned char)pw[i];
            int cls = 0;
            if (c >= '0' && c <= '9') cls = 1;
            else {
                uint32_t cp0;
                int n0 = utf8_decode(pw + i, pwlen - i, &cp0);
                if (n0 > 0 && utf8_is_alpha(cp0)) cls = 2;
            }
            if (!cls) { i++; continue; }

            int j = i;
            while (j < pwlen && tag[j] == TAG_NONE) {
                if (cls == 1) {
                    if (pw[j] < '0' || pw[j] > '9') break;
                    j++;
                } else {
                    uint32_t cpj;
                    int nj = utf8_decode(pw + j, pwlen - j, &cpj);
                    if (nj == 0 || !utf8_is_alpha(cpj)) break;
                    j += nj;
                }
            }
            int rn = j - i;
            if (rn >= 4) {
                for (int u = 2; u <= rn / 2; u++) {
                    if (memcmp(pw + i, pw + i + u, rn - u) == 0) {
                        for (int m = 0; m < rn; m++) tag[i + m] = TAG_REPEAT;
                        break;
                    }
                }
            }
            i = j;
        }
    }

    /* Phase 1e: Context-sensitive patterns */
    for (int p = 0; p < (int)N_CONTEXT_PATS; p++) {
        const char *pat = context_pats[p].pat;
        int plen = context_pats[p].len;
        for (int j = 0; j + plen <= pwlen; j++) {
            if (tag[j] != TAG_NONE) continue;
            if (memcmp(&pw[j], pat, plen) == 0) {
                if (pat[0] == '#' && pat[1] == '1' && j + plen < pwlen &&
                    pw[j + plen] >= '0' && pw[j + plen] <= '9')
                    continue;
                int ok = 1;
                for (int k = 0; k < plen; k++)
                    if (tag[j + k] != TAG_NONE) { ok = 0; break; }
                if (!ok) continue;
                for (int k = 0; k < plen; k++)
                    tag[j + k] = TAG_CTX;
                break;
            }
        }
    }

    /* Phase 2: Scan left-to-right, emit sections */
    int nsects = 0;
    int i = 0;

    while (i < pwlen && nsects < maxsects - 1) {
        if (tag[i] == TAG_YEAR) {
            set_section_str(&sects[nsects], &pw[i], 4, "Y1", 1);
            nsects++; i += 4;
        } else if (tag[i] == TAG_CTX) {
            int start = i;
            while (i < pwlen && tag[i] == TAG_CTX) i++;
            set_section_str(&sects[nsects], &pw[start], i - start, "X1", 1);
            nsects++;
        } else if (tag[i] == TAG_KBD1 || tag[i] == TAG_KBD) {
            /* One section per walk: consume this walk's first byte, then its
             * continuation bytes, and stop at the next walk's first byte. */
            int start = i;
            i++;
            while (i < pwlen && tag[i] == TAG_KBD) i++;
            set_section(&sects[nsects], &pw[start], i - start, 'K', i - start);
            nsects++;
        } else if (tag[i] == TAG_DATE) {
            int start = i;
            while (i < pwlen && tag[i] == TAG_DATE) i++;
            set_section(&sects[nsects], &pw[start], i - start, 'B', i - start);
            nsects++;
        } else if (tag[i] == TAG_REPEAT) {
            int start = i;
            while (i < pwlen && tag[i] == TAG_REPEAT) i++;
            set_section(&sects[nsects], &pw[start], i - start, 'R', i - start);
            nsects++;
        } else if (tag[i] == TAG_EMAIL) {
            int start = i;
            while (i < pwlen && tag[i] == TAG_EMAIL) i++;
            set_section_str(&sects[nsects], &pw[start], i - start, "E", 0);
            nsects++;
        } else if (tag[i] == TAG_WEB) {
            int start = i;
            while (i < pwlen && tag[i] == TAG_WEB) i++;
            set_section_str(&sects[nsects], &pw[start], i - start, "W", 0);
            nsects++;
        } else {
            /* Classify using UTF-8 codepoints */
            uint32_t cp;
            int cpn = utf8_decode(pw + i, pwlen - i, &cp);
            if (cpn == 0) { i++; continue; }

            if (utf8_is_alpha(cp)) {
                /* Alpha run: extends through true letters and leet chars that
                 * sit between letters.  Trailing leet chars (no letter after
                 * them) fall through to the digit/other classifiers below. */
                int start = i;
                int last_letter_end = 0;
                while (i < pwlen && tag[i] == TAG_NONE) {
                    int n = utf8_decode(pw + i, pwlen - i, &cp);
                    if (n == 0) break;
                    if (utf8_is_alpha(cp)) {
                        i += n;
                        last_letter_end = i;
                    } else if (n == 1 && is_leet_char((unsigned char)pw[i])) {
                        i += 1;
                    } else {
                        break;
                    }
                }
                int alen = last_letter_end - start;
                /* tnum = codepoint count for type string (A6 = 6 codepoints) */
                int cpcount = utf8_cplen(pw + start, alen);

                /* Folded, lowered copy for multiword splitting.  Folding is
                 * byte-position-preserving (1-byte leet char → 1-byte
                 * letter), so split lengths map straight back onto pw. */
                int fl = pcfg_fold_word(pw + start, alen, lower, PCFG_MAXLINE);

                /* Try multiword split (byte-level, ASCII only for now) */
                int parts[16];
                int nparts = 0;
                if (GlobalMultiTrie && cpcount >= 8)
                    nparts = multiword_parse(GlobalMultiTrie, lower, fl, parts, 16);

                if (nparts > 1) {
                    int off = start;
                    for (int p = 0; p < nparts && nsects < maxsects - 1; p++) {
                        int pcp = utf8_cplen(pw + off, parts[p]);
                        /* semantic category of the folded part, if tagged */
                        char pfx = 'A';
                        if (SemMap && parts[p] < 64) {
                            char pbuf[64];
                            memcpy(pbuf, lower + (off - start), parts[p]);
                            pbuf[parts[p]] = '\0';
                            char hit = sem_lookup(pbuf);
                            if (hit) pfx = hit;
                        }
                        set_section(&sects[nsects], &pw[off], parts[p], pfx, pcp);
                        nsects++;
                        off += parts[p];
                    }
                    i = off;
                } else {
                    char pfx = 'A';
                    if (SemMap) {
                        char hit = sem_lookup(lower);
                        if (hit) pfx = hit;
                    }
                    set_section(&sects[nsects], &pw[start], alen, pfx, cpcount);
                    nsects++;
                    i = start + alen;
                }
            } else if (utf8_is_digit(cp)) {
                int start = i;
                while (i < pwlen && tag[i] == TAG_NONE &&
                       (unsigned char)pw[i] >= '0' && (unsigned char)pw[i] <= '9') i++;
                set_section(&sects[nsects], &pw[start], i - start, 'D', i - start);
                nsects++;
            } else {
                /* Other: advance by full codepoints, stop at alpha or digit */
                int start = i;
                while (i < pwlen && tag[i] == TAG_NONE) {
                    int n = utf8_decode(pw + i, pwlen - i, &cp);
                    if (n == 0) { i++; continue; }
                    if (utf8_is_alpha(cp) || utf8_is_digit(cp)) break;
                    i += n;
                }
                int ocp = utf8_cplen(pw + start, i - start);
                set_section(&sects[nsects], &pw[start], i - start, 'O', ocp);
                nsects++;
            }
        }
    }

    return nsects;
}
