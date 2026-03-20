/*
 * pcfg_utf8.c - UTF-8 decoding and Unicode character classification
 *
 * Provides codepoint-level is_alpha, is_upper, to_lower for Unicode.
 * Covers ASCII, Latin-1 Supplement, Latin Extended-A/B, Cyrillic, Greek.
 * Unknown high codepoints default to alpha (conservative for passwords).
 */

#include "pcfg.h"

/* ---- UTF-8 decode ----
 * Decodes one codepoint from s, stores in *cp, returns bytes consumed.
 * Returns 0 on invalid/truncated sequence.
 */
int utf8_decode(const char *s, int len, uint32_t *cp) {
    if (len <= 0) return 0;
    unsigned char c = (unsigned char)s[0];

    if (c < 0x80) {
        *cp = c;
        return 1;
    }
    if ((c & 0xE0) == 0xC0 && len >= 2) {
        *cp = ((c & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if ((c & 0xF0) == 0xE0 && len >= 3) {
        *cp = ((c & 0x0F) << 12) | ((s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    }
    if ((c & 0xF8) == 0xF0 && len >= 4) {
        *cp = ((c & 0x07) << 18) | ((s[1] & 0x3F) << 12) |
              ((s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 4;
    }
    /* Invalid: skip one byte */
    *cp = c;
    return 1;
}

/* ---- UTF-8 encode ----
 * Encodes codepoint cp into buf, returns bytes written.
 */
int utf8_encode(char *buf, uint32_t cp) {
    if (cp < 0x80) {
        buf[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        buf[0] = 0xC0 | (cp >> 6);
        buf[1] = 0x80 | (cp & 0x3F);
        return 2;
    }
    if (cp < 0x10000) {
        buf[0] = 0xE0 | (cp >> 12);
        buf[1] = 0x80 | ((cp >> 6) & 0x3F);
        buf[2] = 0x80 | (cp & 0x3F);
        return 3;
    }
    buf[0] = 0xF0 | (cp >> 18);
    buf[1] = 0x80 | ((cp >> 12) & 0x3F);
    buf[2] = 0x80 | ((cp >> 6) & 0x3F);
    buf[3] = 0x80 | (cp & 0x3F);
    return 4;
}

/* ---- Count codepoints in UTF-8 string ---- */
int utf8_cplen(const char *s, int bytelen) {
    int count = 0;
    int i = 0;
    while (i < bytelen) {
        uint32_t cp;
        int n = utf8_decode(s + i, bytelen - i, &cp);
        if (n == 0) break;
        i += n;
        count++;
    }
    return count;
}

/* ---- Unicode character classification ----
 *
 * Covers: ASCII, Latin-1 Supplement (U+00C0-00FF),
 * Latin Extended-A (U+0100-017F), Latin Extended-B (U+0180-024F),
 * Greek (U+0370-03FF), Cyrillic (U+0400-04FF).
 * Codepoints above 0x80 not in known non-alpha ranges default to alpha.
 */

int utf8_is_alpha(uint32_t cp) {
    /* ASCII */
    if (cp < 0x80)
        return (cp >= 'A' && cp <= 'Z') || (cp >= 'a' && cp <= 'z');

    /* Latin-1 Supplement: U+00C0-00D6, U+00D8-00F6, U+00F8-00FF */
    if (cp >= 0xC0 && cp <= 0xFF) {
        if (cp == 0xD7 || cp == 0xF7) return 0;  /* multiply/divide signs */
        return 1;
    }

    /* Latin Extended-A/B: U+0100-024F — all letters */
    if (cp >= 0x100 && cp <= 0x24F) return 1;

    /* Greek: U+0370-03FF (most are letters, skip few punctuation) */
    if (cp >= 0x0391 && cp <= 0x03C9) return 1;
    if (cp >= 0x0370 && cp <= 0x03FF) return 1; /* broader Greek block */

    /* Cyrillic: U+0400-04FF */
    if (cp >= 0x0400 && cp <= 0x04FF) return 1;

    /* Cyrillic Supplement: U+0500-052F */
    if (cp >= 0x0500 && cp <= 0x052F) return 1;

    /* Common non-alpha Unicode ranges */
    if (cp >= 0x2000 && cp <= 0x206F) return 0;  /* General Punctuation */
    if (cp >= 0x2070 && cp <= 0x209F) return 0;  /* Superscripts/Subscripts */
    if (cp >= 0x20A0 && cp <= 0x20CF) return 0;  /* Currency Symbols */
    if (cp >= 0x2100 && cp <= 0x214F) return 0;  /* Letterlike Symbols */
    if (cp >= 0x2190 && cp <= 0x21FF) return 0;  /* Arrows */
    if (cp >= 0x2200 && cp <= 0x22FF) return 0;  /* Math Operators */
    if (cp >= 0x2300 && cp <= 0x23FF) return 0;  /* Misc Technical */
    if (cp >= 0x2500 && cp <= 0x257F) return 0;  /* Box Drawing */
    if (cp >= 0x2580 && cp <= 0x259F) return 0;  /* Block Elements */
    if (cp >= 0x25A0 && cp <= 0x25FF) return 0;  /* Geometric Shapes */
    if (cp >= 0xFE00 && cp <= 0xFE0F) return 0;  /* Variation Selectors */
    if (cp >= 0xFFF0 && cp <= 0xFFFF) return 0;  /* Specials */

    /* Arabic: U+0600-06FF — letters */
    if (cp >= 0x0620 && cp <= 0x06FF) return 1;

    /* Hebrew: U+0590-05FF — letters */
    if (cp >= 0x05D0 && cp <= 0x05EA) return 1;

    /* Thai: U+0E01-0E3A — consonants/vowels */
    if (cp >= 0x0E01 && cp <= 0x0E3A) return 1;

    /* CJK Unified Ideographs: U+4E00-9FFF — treat as alpha for passwords */
    if (cp >= 0x4E00 && cp <= 0x9FFF) return 1;

    /* Hangul: U+AC00-D7AF */
    if (cp >= 0xAC00 && cp <= 0xD7AF) return 1;

    /* Hiragana: U+3040-309F, Katakana: U+30A0-30FF */
    if (cp >= 0x3040 && cp <= 0x30FF) return 1;

    /* Default: treat high codepoints as alpha (conservative for passwords) */
    if (cp > 0x80) return 1;

    return 0;
}

int utf8_is_upper(uint32_t cp) {
    if (cp >= 'A' && cp <= 'Z') return 1;

    /* Latin-1 uppercase: U+00C0-00D6, U+00D8-00DE */
    if (cp >= 0xC0 && cp <= 0xD6) return 1;
    if (cp >= 0xD8 && cp <= 0xDE) return 1;

    /* Latin Extended-A: even codepoints 0x100-0x176 are uppercase */
    if (cp >= 0x100 && cp <= 0x176 && (cp & 1) == 0) return 1;

    /* Cyrillic uppercase: U+0410-042F */
    if (cp >= 0x0410 && cp <= 0x042F) return 1;
    /* Cyrillic Ё, Ђ-Џ: U+0400-040F */
    if (cp >= 0x0400 && cp <= 0x040F) return 1;

    /* Greek uppercase: U+0391-03A9 (skip U+03A2 — no final sigma) */
    if (cp >= 0x0391 && cp <= 0x03A9 && cp != 0x03A2) return 1;

    return 0;
}

int utf8_is_digit(uint32_t cp) {
    return (cp >= '0' && cp <= '9');
}

uint32_t utf8_to_lower(uint32_t cp) {
    /* ASCII */
    if (cp >= 'A' && cp <= 'Z') return cp + 32;

    /* Latin-1 Supplement uppercase → lowercase (+0x20) */
    if (cp >= 0xC0 && cp <= 0xD6) return cp + 0x20;
    if (cp >= 0xD8 && cp <= 0xDE) return cp + 0x20;

    /* Latin Extended-A: even → odd for 0x100-0x176 */
    if (cp >= 0x100 && cp <= 0x176 && (cp & 1) == 0) return cp + 1;

    /* Cyrillic uppercase → lowercase (+0x20 for 0x0410-042F → 0x0430-044F) */
    if (cp >= 0x0410 && cp <= 0x042F) return cp + 0x20;
    /* Cyrillic Ё etc: 0x0400-040F → 0x0450-045F */
    if (cp >= 0x0400 && cp <= 0x040F) return cp + 0x50;

    /* Greek uppercase → lowercase (+0x20 for 0x0391-03A1, 03A3-03A9) */
    if (cp >= 0x0391 && cp <= 0x03A1) return cp + 0x20;
    if (cp >= 0x03A3 && cp <= 0x03A9) return cp + 0x20;

    return cp;
}

uint32_t utf8_to_upper(uint32_t cp) {
    if (cp >= 'a' && cp <= 'z') return cp - 32;

    if (cp >= 0xE0 && cp <= 0xF6) return cp - 0x20;
    if (cp >= 0xF8 && cp <= 0xFE) return cp - 0x20;

    if (cp >= 0x101 && cp <= 0x177 && (cp & 1) == 1) return cp - 1;

    if (cp >= 0x0430 && cp <= 0x044F) return cp - 0x20;
    if (cp >= 0x0450 && cp <= 0x045F) return cp - 0x50;

    if (cp >= 0x03B1 && cp <= 0x03C1) return cp - 0x20;
    if (cp >= 0x03C3 && cp <= 0x03C9) return cp - 0x20;

    return cp;
}
