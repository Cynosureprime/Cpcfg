/*
 * pcfg_keyboard.c - Keyboard walk detection (11 layouts)
 *
 * QWERTY-US/UK, QWERTZ-DE, AZERTY-FR, Dvorak, JCUKEN-RU, QWERTY-ES, QWERTY-PT,
 * QWERTY-Nordic, QWERTY-TR, QWERTY-BR.
 *
 * Keys are CODEPOINTS, not bytes.  A layout's interesting keys are mostly the
 * ones that are not ASCII -- n-tilde, c-cedilla, a-ring, o-diaeresis, sterling,
 * the Cyrillic letters -- and a byte-indexed table could hold none of them.
 * Because utf8_decode returns U+00F1 both for a raw 0xF1 and for the two-byte
 * UTF-8 form, one codepoint table matches a walk in a CP1252 corpus and in a
 * UTF-8 one without knowing which it was handed.
 * Adjacent = row diff <= 1 AND col diff <= 1 (8 directions).
 * Min run: 4 chars. Must have >=2 char types (alpha/digit/special).
 * False positive filters for common words that look like walks.
 */

#include "pcfg.h"
#include <string.h>
#include <ctype.h>

/* Key position: row + column on a keyboard layout */
typedef struct {
    int row;
    int col;
} KeyPos;

/* Per-layout position table: ASCII 0-127 → KeyPos, valid flag */
#define NLAYOUTS 11
#define KMAP_SIZE 256          /* ASCII + Latin-1: every Latin layout key */
#define KMAP_CYR_BASE 0x0400   /* Cyrillic block, for JCUKEN */
#define KMAP_CYR_SIZE 0x60
#define KMAP_LEA_BASE 0x0100   /* Latin Extended-A: Turkish, Polish, Czech */
#define KMAP_LEA_SIZE 0x80

static struct {
    KeyPos pos[KMAP_SIZE];
    int    valid[KMAP_SIZE];
    KeyPos cyr[KMAP_CYR_SIZE];
    int    cyr_valid[KMAP_CYR_SIZE];
    KeyPos lea[KMAP_LEA_SIZE];
    int    lea_valid[KMAP_LEA_SIZE];
} Layout[NLAYOUTS];

/* Look a codepoint up on one layout. */
static int key_lookup(int layout, uint32_t cp, KeyPos *out) {
    if (cp < KMAP_SIZE) {
        if (!Layout[layout].valid[cp]) return 0;
        *out = Layout[layout].pos[cp];
        return 1;
    }
    if (cp >= KMAP_CYR_BASE && cp < KMAP_CYR_BASE + KMAP_CYR_SIZE) {
        int k = (int)(cp - KMAP_CYR_BASE);
        if (!Layout[layout].cyr_valid[k]) return 0;
        *out = Layout[layout].cyr[k];
        return 1;
    }
    if (cp >= KMAP_LEA_BASE && cp < KMAP_LEA_BASE + KMAP_LEA_SIZE) {
        int k = (int)(cp - KMAP_LEA_BASE);
        if (!Layout[layout].lea_valid[k]) return 0;
        *out = Layout[layout].lea[k];
        return 1;
    }
    return 0;
}

static void key_set(int layout, uint32_t cp, int row, int col) {
    if (cp < KMAP_SIZE) {
        Layout[layout].pos[cp].row = row;
        Layout[layout].pos[cp].col = col;
        Layout[layout].valid[cp] = 1;
    } else if (cp >= KMAP_CYR_BASE && cp < KMAP_CYR_BASE + KMAP_CYR_SIZE) {
        int k = (int)(cp - KMAP_CYR_BASE);
        Layout[layout].cyr[k].row = row;
        Layout[layout].cyr[k].col = col;
        Layout[layout].cyr_valid[k] = 1;
    } else if (cp >= KMAP_LEA_BASE && cp < KMAP_LEA_BASE + KMAP_LEA_SIZE) {
        int k = (int)(cp - KMAP_LEA_BASE);
        Layout[layout].lea[k].row = row;
        Layout[layout].lea[k].col = col;
        Layout[layout].lea_valid[k] = 1;
    }
}

static int keyboard_init_done = 0;


/* ---- Layout definitions ----
 * Each row is a string of chars at consecutive positions.
 * Format: row_number, unshifted_chars, shifted_chars
 */
/* Rows are written as UTF-8 source literals and decoded to codepoints, so a
 * key is one column whether it is 'a' or n-tilde. */
static void add_row(int layout, int row, const char *unshifted, const char *shifted) {
    for (int pass = 0; pass < 2; pass++) {
        const char *r = pass ? shifted : unshifted;
        if (!r) continue;
        int i = 0, col = 0, rlen = (int)strlen(r);
        while (i < rlen) {
            uint32_t cp;
            int n = utf8_decode(r + i, rlen - i, &cp);
            if (n == 0) break;
            key_set(layout, cp, row, col);
            i += n;
            col++;
        }
    }
}

static void init_keyboards(void) {
    if (keyboard_init_done) return;
    keyboard_init_done = 1;

    memset(Layout, 0, sizeof(Layout));

    /* QWERTY (layout 0) */
    add_row(0, 0, "1234567890-=",  "!@#$%^&*()_+");
    add_row(0, 1, "qwertyuiop[]\\","QWERTYUIOP{}|");
    add_row(0, 2, "asdfghjkl;'",   "ASDFGHJKL:\"");
    add_row(0, 3, "zxcvbnm,./",    "ZXCVBNM<>?");

    /* QWERTZ (layout 2) */
    add_row(2, 0, "1234567890",    "!\"$%&/()=?");
    add_row(2, 1, "qwertzuiop",    "QWERTZUIOP");
    add_row(2, 2, "asdfghjkl",     "ASDFGHJKL");
    add_row(2, 3, "yxcvbnm,.-",    "YXCVBNM;:_");

    /* AZERTY (layout 3) */
    add_row(3, 0, "1234567890",    NULL);
    add_row(3, 1, "azertyuiop",    "AZERTYUIOP");
    add_row(3, 2, "qsdfghjklm",    "QSDFGHJKLM");
    add_row(3, 3, "wxcvbn,;:!",    "WXCVBN?./" );

    /* DVORAK (layout 4) */
    add_row(4, 0, "1234567890[]",  "!@#$%^&*(){}");
    add_row(4, 1, "',. pyfgcrl/=\\","\"<>PYFGCRL?+|");
    add_row(4, 2, "aoeuidhtns-",   "AOEUIDHTNS_");
    add_row(4, 3, ";qjkxbmwvz",    ":QJKXBMWVZ");

    /* JCUKEN, Russian (layout 1).  Previously only the number row, so no
     * Cyrillic walk could ever be detected -- and the Cyrillic corpora are
     * exactly where they occur. */
    add_row(1, 0, "1234567890-=",       "!\"\u2116;%:?*()_+");
    add_row(1, 1, "\u0439\u0446\u0443\u043a\u0435\u043d\u0433\u0448\u0449\u0437\u0445\u044a",
                  "\u0419\u0426\u0423\u041a\u0415\u041d\u0413\u0428\u0429\u0417\u0425\u042a");
    add_row(1, 2, "\u0444\u044b\u0432\u0430\u043f\u0440\u043e\u043b\u0434\u0436\u044d",
                  "\u0424\u042b\u0412\u0410\u041f\u0420\u041e\u041b\u0414\u0416\u042d");
    add_row(1, 3, "\u044f\u0447\u0441\u043c\u0438\u0442\u044c\u0431\u044e.",
                  "\u042f\u0427\u0421\u041c\u0418\u0422\u042c\u0411\u042e,");

    /* QWERTY UK (layout 5).  The shifted number row is the tell: sterling at
     * position 3 where US has hash.  "!\"\u00a3$%^&*()" in the solved pool is
     * this row, not a US one. */
    add_row(5, 0, "1234567890-=",  "!\"\u00a3$%^&*()_+");
    add_row(5, 1, "qwertyuiop[]",  "QWERTYUIOP{}");
    add_row(5, 2, "asdfghjkl;'#",  "ASDFGHJKL:@~");
    add_row(5, 3, "\\zxcvbnm,./",  "|ZXCVBNM<>?");

    /* QWERTY Spanish (layout 6).  n-tilde sits at the end of the home row,
     * which is what extends "asdfghjkl" to "asdfghjkl\u00f1". */
    add_row(6, 0, "1234567890'\u00a1", "!\"\u00b7$%&/()=?\u00bf");
    add_row(6, 1, "qwertyuiop`+",   "QWERTYUIOP^*");
    add_row(6, 2, "asdfghjkl\u00f1\u00b4\u00e7", "ASDFGHJKL\u00d1\u00a8\u00c7");
    add_row(6, 3, "zxcvbnm,.-",     "ZXCVBNM;:_");

    /* QWERTY Portuguese, PT (layout 7). */
    add_row(7, 0, "1234567890'\u00ab", "!\"#$%&/()=?\u00bb");
    add_row(7, 1, "qwertyuiop+\u00b4",  "QWERTYUIOP*`");
    add_row(7, 2, "asdfghjkl\u00e7~",   "ASDFGHJKL\u00c7^");
    add_row(7, 3, "zxcvbnm,.-",     "ZXCVBNM;:_");

    /* QWERTY Nordic, SE/FI (layout 8).  "!\"#\u00a4%" is this shifted row --
     * the currency sign at position 4 distinguishes it from every other. */
    add_row(8, 0, "1234567890+\u00b4", "!\"#\u00a4%&/()=?`");
    add_row(8, 1, "qwertyuiop\u00e5\u00a8", "QWERTYUIOP\u00c5^");
    add_row(8, 2, "asdfghjkl\u00f6\u00e4'",  "ASDFGHJKL\u00d6\u00c4*");
    add_row(8, 3, "zxcvbnm,.-",     "ZXCVBNM;:_");

    /* QWERTY Turkish-Q (layout 9).  Dotless i and the dotted capital are
     * separate keys here, which is the same distinction the case tables and
     * procrule -L have to make. */
    add_row(9, 0, "1234567890*-",   "!'^+%&/()=?_");
    add_row(9, 1, "qwertyu\u0131op\u011f\u00fc", "QWERTYUIOP\u011e\u00dc");
    add_row(9, 2, "asdfghjkl\u015fi",   "ASDFGHJKL\u015e\u0130");
    add_row(9, 3, "zxcvbnm\u00f6\u00e7.",   "ZXCVBNM\u00d6\u00c7:");

    /* QWERTY Brazilian ABNT2 (layout 10).  "asdfghjkl\u00e7~]" in the solved
     * pool is this home row exactly, c-cedilla then tilde then bracket. */
    add_row(10, 0, "1234567890-=",  "!@#$%\u00a8&*()_+");
    add_row(10, 1, "qwertyuiop\u00b4[", "QWERTYUIOP`{");
    add_row(10, 2, "asdfghjkl\u00e7~]",  "ASDFGHJKL\u00c7^}");
    add_row(10, 3, "\\zxcvbnm,.;/", "|ZXCVBNM<>:?");

    /* German QWERTZ gains its umlauts and eszett (layout 2 rows re-stated). */
    add_row(2, 1, "qwertzuiop\u00fc+", "QWERTZUIOP\u00dc*");
    add_row(2, 2, "asdfghjkl\u00f6\u00e4#",  "ASDFGHJKL\u00d6\u00c4'");
}

/* ---- Check adjacency between two chars on a specific layout ---- */
static int is_adjacent(int layout, uint32_t c1, uint32_t c2) {
    KeyPos p1, p2;
    if (!key_lookup(layout, c1, &p1)) return 0;
    if (!key_lookup(layout, c2, &p2)) return 0;

    int dr = p1.row - p2.row;
    int dc = p1.col - p2.col;
    if (dr < 0) dr = -dr;
    if (dc < 0) dc = -dc;

    if (dr <= 1 && dc <= 1 && (dr + dc) > 0) return 1;
    return 0;
}

/* ---- False positive filters ---- */
static const char *fp_words[] = {
    "drew", "kiki", "fred", "were", "pop", "123;", "234;", NULL
};

static int is_interesting_keyboard(const char *combo, int len) {
    if (len < 4) return 0;

    /* Pattern checks */
    if (combo[0] == 'e') return 0;
    if (len >= 3 && combo[1] == 'e' && combo[2] == 'r') return 0;
    if (combo[0] == 't' && combo[1] == 'y') return 0;
    if (len >= 3 && combo[0] == 't' && combo[1] == 't' && combo[2] == 'y') return 0;
    if (combo[0] == 'y') return 0;
    if (len >= 3 && combo[0] == '1' && combo[1] == '2' && combo[2] == '3') return 0;
    if (len >= 4 && combo[len-1] == '3' && combo[len-2] == '2' && combo[len-3] == '1' &&
        combo[len-4] != 'q' && combo[len-4] != 'Q') return 0;

    /* Substring false positive check (case insensitive) */
    for (int i = 0; fp_words[i]; i++) {
        int plen = strlen(fp_words[i]);
        for (int j = 0; j + plen <= len; j++) {
            int match = 1;
            for (int k = 0; k < plen; k++) {
                if (tolower((unsigned char)combo[j+k]) != fp_words[i][k]) {
                    match = 0;
                    break;
                }
            }
            if (match) return 0;
        }
    }

    /* Classify by CODEPOINT.  Byte classification called every Cyrillic and
     * accented letter "special", so a Russian home-row run scored two types
     * and passed while its English equivalent scored one and did not. */
    int has_alpha = 0, has_digit = 0, has_special = 0, keys = 0, has_national = 0;
    for (int i = 0; i < len; ) {
        uint32_t cp;
        int n = utf8_decode(combo + i, len - i, &cp);
        if (n == 0) break;
        if (utf8_is_alpha(cp))      has_alpha = 1;
        else if (cp >= '0' && cp <= '9') has_digit = 1;
        else                        has_special = 1;
        if (cp > 0x7F)              has_national = 1;
        i += n;
        keys++;
    }

    /* Two character types is the usual evidence, because a mixed run is not a
     * word.  Two further cases are walks that the two-type rule refused:
     *
     * A run with NO letter and NO digit is a shifted-row walk.  "!@#$%^&*" is
     * the US number row and "!\"\u00a3$%^&*()" the UK one; the solved pool
     * holds 139 symbol-only strings of this kind among 7,500 non-ASCII
     * plaintexts.  Adjacency has already done the discriminating -- arbitrary
     * punctuation is not adjacent, and a character is not adjacent to itself,
     * so a run of repeats cannot reach here.
     *
     * And a single-type run of six or more keys, which is the length at which
     * an adjacent run stops being a plausible word: "zxcvbnm", "asdfghjkl\u00f1",
     * "\u0439\u0446\u0443\u043a\u0435\u043d\u0433\u0448". Four and five keys stay
     * excluded, which is where the false positives live. */
    int types = has_alpha + has_digit + has_special;
    if (types < 2) {
        if (has_alpha || has_digit) {
            /* A single-type run must carry a key that is not on a US board:
             * n-tilde, a-ring, o-diaeresis, a Cyrillic letter.  That is what
             * makes it a national-layout walk rather than a word.  Relaxing
             * this to ASCII as well costs real words -- measured on 60,000
             * dictionary entries it admitted 20, among them "desert", which
             * really is six adjacent QWERTY keys.  Six keys is the length at
             * which a non-ASCII adjacent run stops being plausible text. */
            if (!has_national || keys < 6) return 0;
        }
        /* symbol-only: accepted at the shared four-key minimum, because
         * adjacency has already excluded arbitrary punctuation */
    }

    return 1;
}

/* ---- Detect keyboard walks in a string ----
 * Returns number of walks found, fills walks[] with {start, len} pairs.
 * Max MAX_WALKS walks detected.
 */
#define MAX_WALKS 16

typedef struct {
    int start;
    int len;
} KbdWalk;

int detect_keyboard_walks(const char *pw, int pwlen, KbdWalk *walks, int max_walks) {
    init_keyboards();

    int nwalks = 0;
    int active[NLAYOUTS];
    KeyPos kp;

    if (pwlen < 4) return 0;

    /* Walk by CODEPOINT, record by BYTE.  pcfg_parse indexes its tag array by
     * byte, so start and len stay byte quantities; the four-key minimum is a
     * count of keys, because one key is one to four bytes. */
    uint32_t prev;
    int n = utf8_decode(pw, pwlen, &prev);
    if (n == 0) return 0;

    int combo_start = 0;    /* byte offset of the run   */
    int combo_bytes = n;    /* its length in bytes      */
    int combo_keys  = 1;    /* its length in keypresses */

    for (int l = 0; l < NLAYOUTS; l++)
        active[l] = key_lookup(l, prev, &kp);

    int i = n;
    while (i < pwlen) {
        uint32_t cur;
        int cn = utf8_decode(pw + i, pwlen - i, &cur);
        if (cn == 0) break;

        int any_active = 0;
        int next_active[NLAYOUTS];
        for (int l = 0; l < NLAYOUTS; l++) {
            if (active[l] && is_adjacent(l, prev, cur)) {
                next_active[l] = 1;
                any_active = 1;
            } else {
                next_active[l] = 0;
            }
        }

        if (any_active) {
            memcpy(active, next_active, sizeof(active));
            combo_keys++;
            combo_bytes += cn;
        } else {
            if (combo_keys >= 4 && combo_bytes < 255) {
                char tmp[256];
                memcpy(tmp, pw + combo_start, combo_bytes);
                tmp[combo_bytes] = 0;
                if (is_interesting_keyboard(tmp, combo_bytes) && nwalks < max_walks) {
                    walks[nwalks].start = combo_start;
                    walks[nwalks].len = combo_bytes;
                    nwalks++;
                }
            }
            combo_start = i;
            combo_bytes = cn;
            combo_keys = 1;
            for (int l = 0; l < NLAYOUTS; l++)
                active[l] = key_lookup(l, cur, &kp);
        }

        prev = cur;
        i += cn;
    }

    if (combo_keys >= 4 && combo_bytes < 255) {
        char tmp[256];
        memcpy(tmp, pw + combo_start, combo_bytes);
        tmp[combo_bytes] = 0;
        if (is_interesting_keyboard(tmp, combo_bytes) && nwalks < max_walks) {
            walks[nwalks].start = combo_start;
            walks[nwalks].len = combo_bytes;
            nwalks++;
        }
    }

    return nwalks;
}
