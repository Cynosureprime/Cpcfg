/*
 * pcfg_keyboard.c - Keyboard walk detection (5 layouts)
 *
 * Detects sequences of adjacent keys on QWERTY, JCUKEN, QWERTZ, AZERTY, Dvorak.
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
#define NLAYOUTS 5
#define KMAP_SIZE 128

static struct {
    KeyPos pos[KMAP_SIZE];
    int    valid[KMAP_SIZE];  /* 1 if char exists on this layout */
} Layout[NLAYOUTS];

static int keyboard_init_done = 0;


/* ---- Layout definitions ----
 * Each row is a string of chars at consecutive positions.
 * Format: row_number, unshifted_chars, shifted_chars
 */
static void add_row(int layout, int row, const char *unshifted, const char *shifted) {
    for (int i = 0; unshifted[i]; i++) {
        unsigned char c = (unsigned char)unshifted[i];
        if (c < KMAP_SIZE) {
            Layout[layout].pos[c].row = row;
            Layout[layout].pos[c].col = i;
            Layout[layout].valid[c] = 1;
        }
    }
    if (shifted) {
        for (int i = 0; shifted[i]; i++) {
            unsigned char c = (unsigned char)shifted[i];
            if (c < KMAP_SIZE) {
                Layout[layout].pos[c].row = row;
                Layout[layout].pos[c].col = i;
                Layout[layout].valid[c] = 1;
            }
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

    /* JCUKEN (layout 1) - only ASCII-range chars from number row */
    add_row(1, 0, "1234567890-=",  "!\"%;:?*()_+");
}

/* ---- Check adjacency between two chars on a specific layout ---- */
static int is_adjacent(int layout, unsigned char c1, unsigned char c2) {
    if (c1 >= KMAP_SIZE || c2 >= KMAP_SIZE) return 0;
    if (!Layout[layout].valid[c1] || !Layout[layout].valid[c2]) return 0;

    int dr = Layout[layout].pos[c1].row - Layout[layout].pos[c2].row;
    int dc = Layout[layout].pos[c1].col - Layout[layout].pos[c2].col;
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

    /* Must have >= 2 character types */
    int has_alpha = 0, has_digit = 0, has_special = 0;
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)combo[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
            has_alpha = 1;
        else if (c >= '0' && c <= '9')
            has_digit = 1;
        else
            has_special = 1;
    }
    if ((has_alpha + has_digit + has_special) < 2) return 0;

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
    int combo_start = 0;
    int combo_len = 1;
    /* Track which layouts have continuous adjacency */
    int active[NLAYOUTS];

    if (pwlen < 4) return 0;

    /* Initialize: first char — mark which layouts have it */
    for (int l = 0; l < NLAYOUTS; l++) {
        unsigned char c = (unsigned char)pw[0];
        active[l] = (c < KMAP_SIZE && Layout[l].valid[c]) ? 1 : 0;
    }

    for (int i = 1; i < pwlen; i++) {
        unsigned char prev = (unsigned char)pw[i-1];
        unsigned char cur = (unsigned char)pw[i];

        /* Check adjacency on each active layout */
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
            combo_len++;
        } else {
            /* Run ended — check if it qualifies */
            if (combo_len >= 4) {
                char tmp[256];
                int tlen = combo_len < 255 ? combo_len : 255;
                memcpy(tmp, pw + combo_start, tlen);
                tmp[tlen] = '\0';
                if (is_interesting_keyboard(tmp, tlen) && nwalks < max_walks) {
                    walks[nwalks].start = combo_start;
                    walks[nwalks].len = combo_len;
                    nwalks++;
                }
            }

            /* Reset for new potential walk */
            combo_start = i;
            combo_len = 1;
            for (int l = 0; l < NLAYOUTS; l++) {
                unsigned char c = cur;
                active[l] = (c < KMAP_SIZE && Layout[l].valid[c]) ? 1 : 0;
            }
        }
    }

    /* Check final run */
    if (combo_len >= 4) {
        char tmp[256];
        int tlen = combo_len < 255 ? combo_len : 255;
        memcpy(tmp, pw + combo_start, tlen);
        tmp[tlen] = '\0';
        if (is_interesting_keyboard(tmp, tlen) && nwalks < max_walks) {
            walks[nwalks].start = combo_start;
            walks[nwalks].len = combo_len;
            nwalks++;
        }
    }

    return nwalks;
}
