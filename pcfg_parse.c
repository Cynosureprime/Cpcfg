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

MultiWordTrie *GlobalMultiTrie = NULL;

static inline unsigned char fast_lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
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

static inline int fast_itoa(char *buf, int num) {
    if (num < 10) { buf[0] = '0' + num; buf[1] = '\0'; return 1; }
    if (num < 100) { buf[0] = '0' + num/10; buf[1] = '0' + num%10; buf[2] = '\0'; return 2; }
    buf[0] = '0' + num/100; buf[1] = '0' + (num/10)%10; buf[2] = '0' + num%10; buf[3] = '\0';
    return 3;
}

/* Build case mask for an alpha section */
void build_case_mask(const char *alpha, int len, char *mask) {
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)alpha[i];
        mask[i] = (c >= 'A' && c <= 'Z') ? 'U' : 'L';
    }
    mask[len] = '\0';
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
    for (int w = 0; w < nwalks; w++) {
        for (int j = walks[w].start; j < walks[w].start + walks[w].len; j++)
            tag[j] = TAG_KBD;
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
        if (tag[j] != TAG_NONE) continue;
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
        } else if (tag[i] == TAG_KBD) {
            int start = i;
            while (i < pwlen && tag[i] == TAG_KBD) i++;
            set_section(&sects[nsects], &pw[start], i - start, 'K', i - start);
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
            unsigned char c = (unsigned char)pw[i];
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
                int start = i;
                while (i < pwlen && tag[i] == TAG_NONE) {
                    c = (unsigned char)pw[i];
                    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) break;
                    i++;
                }
                int alen = i - start;

                /* Try multiword split */
                int parts[16];
                int nparts = 0;
                if (GlobalMultiTrie && alen >= 8)
                    nparts = multiword_parse(GlobalMultiTrie, &pw[start], alen, parts, 16);

                if (nparts > 1) {
                    int off = start;
                    for (int p = 0; p < nparts && nsects < maxsects - 1; p++) {
                        set_section(&sects[nsects], &pw[off], parts[p], 'A', parts[p]);
                        nsects++;
                        off += parts[p];
                    }
                } else {
                    set_section(&sects[nsects], &pw[start], alen, 'A', alen);
                    nsects++;
                }
            } else if (c >= '0' && c <= '9') {
                int start = i;
                while (i < pwlen && tag[i] == TAG_NONE && pw[i] >= '0' && pw[i] <= '9') i++;
                set_section(&sects[nsects], &pw[start], i - start, 'D', i - start);
                nsects++;
            } else {
                int start = i;
                while (i < pwlen && tag[i] == TAG_NONE) {
                    c = (unsigned char)pw[i];
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) break;
                    if (c >= '0' && c <= '9') break;
                    i++;
                }
                set_section(&sects[nsects], &pw[start], i - start, 'O', i - start);
                nsects++;
            }
        }
    }

    return nsects;
}
