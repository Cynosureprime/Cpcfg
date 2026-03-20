/*
 * pcfg.h - Probabilistic Context-Free Grammar password generator
 *
 * C reimplementation of pcfg-go (cyclone-github/pcfg-go)
 * Trains on cracked passwords to learn structural patterns,
 * then generates guesses in probability-descending order.
 */

#ifndef PCFG_H
#define PCFG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <Judy.h>

/* Limits */
#define PCFG_MAXLINE      65536   /* max password length */
#define PCFG_MAXSECTIONS  64      /* max sections per password */
#define PCFG_MAXTYPE      16      /* max type string length (e.g. "A12") */
#define PCFG_MAXCHUNK     (50*1024*1024)
#define PCFG_RINDEXSIZE   (PCFG_MAXCHUNK/2/8)
#define PCFG_MAXPATH      4096

/* Section types (first char) */
#define ST_ALPHA    'A'
#define ST_DIGIT    'D'
#define ST_OTHER    'O'
#define ST_YEAR     'Y'
#define ST_CONTEXT  'X'
#define ST_KEYBOARD 'K'
#define ST_EMAIL    'E'
#define ST_WEBSITE  'W'
#define ST_CASE     'C'
#define ST_MARKOV   'M'
#define ST_UNTYPED  '\0'

/* Parsed password segment */
typedef struct {
    char *value;        /* pointer into password buffer (not owned) */
    int   vlen;         /* byte length */
    int   tnum;         /* numeric part of type (e.g., 4 for "A4") */
    char  type[PCFG_MAXTYPE]; /* "A4", "D2", "K5", "Y1", "X1", "O1", "C4", "" */
} Section;

/* Grammar entry: values sharing same probability */
typedef struct {
    char  **values;     /* array of string pointers */
    int     nvalues;
    int     cap;        /* capacity of values array */
    double  prob;
} GrammarEntry;

/* List of grammar entries for a type key */
typedef struct {
    GrammarEntry *entries;
    int nentries;
    int cap;
} GrammarEntryList;

/* Base structure pattern (e.g., A4C4D2O1) */
typedef struct {
    double  prob;
    char  **replacements;   /* {"A4","C4","D2","O1"} */
    int     nreplace;
} BaseStructure;

/* Parse tree node */
typedef struct {
    char type[PCFG_MAXTYPE];
    int  index;             /* index into GrammarEntryList for this type */
} PTNode;

/* Priority queue item */
typedef struct {
    double  prob;
    double  base_prob;
    PTNode *nodes;
    int     nnodes;
    int64_t seq;            /* insertion order for stable tie-breaking */
} PTItem;

/* Binary max-heap priority queue */
typedef struct {
    PTItem *items;
    int     size, cap;
    int64_t next_seq;
} PQueue;

/* Arena allocator */
typedef struct arena_block {
    char *base;
    size_t used, size;
    struct arena_block *next;
} ArenaBlock;

typedef struct {
    ArenaBlock *head;
    size_t block_size;
} Arena;

/* LineInfo for cacheline reader */
struct LineInfo {
    unsigned int offset;
    unsigned int len;
};

/* Counter: JudySL mapping string→count */
typedef Pvoid_t Counter;

/* Length-indexed counters: JudyL mapping int→Counter */
typedef Pvoid_t LenCounters;

/* Training context */
typedef struct {
    /* Counters for each type (length-indexed) */
    LenCounters cnt_alpha;      /* len → JudySL(lowered_value → count) */
    LenCounters cnt_masks;      /* len → JudySL(mask → count) */
    LenCounters cnt_digits;     /* len → JudySL(value → count) */
    LenCounters cnt_other;      /* len → JudySL(value → count) */
    LenCounters cnt_keyboard;   /* len → JudySL(value → count) */
    /* Flat counters */
    Counter cnt_years;          /* JudySL(year → count) */
    Counter cnt_context;        /* JudySL(pattern → count) */
    Counter cnt_base;           /* JudySL(base_structure → count) */
    Counter cnt_email_prov;     /* JudySL(provider → count) */
    Counter cnt_email_full;     /* JudySL(email → count) */
    Counter cnt_web_host;       /* JudySL(host → count) */
    Counter cnt_web_pfx;        /* JudySL(prefix → count) */
    Counter cnt_web_url;        /* JudySL(url → count) */
    /* Stats */
    int64_t total_passwords;
    int64_t encoding_errors;
    /* Options */
    int save_sensitive;         /* -S flag: save emails/urls */
    double coverage;            /* PCFG vs OMEN split (0.0-1.0) */
    int ngram_size;             /* OMEN n-gram size */
    int alphabet_size;          /* OMEN alphabet size */
    char *comments;             /* user comments */
    char *filename;             /* training filename */
    int max_threads;            /* 0 = auto */
    int admit_threshold;        /* admission filter: min count (0=off, default 2) */
    int weighted;               /* -w: input is count:password format */
    int filter_junk;            /* -F: filter junk lines (base64, hex, JSON) */
} TrainCtx;

/* Grammar (for generation) - JudySL mapping type_string → GrammarEntryList* */
typedef Pvoid_t Grammar;

/* Generation context */
typedef struct {
    Grammar grammar;            /* type → GrammarEntryList* */
    BaseStructure *bases;
    int nbases;
    PQueue queue;
    int64_t guess_count;
    int64_t guess_limit;        /* 0 = unlimited */
    int skip_brute;             /* -b flag */
    int skip_case;              /* -a flag */
    int debug;                  /* -d flag */
    int nthreads;
} GenCtx;

/* ---- Function declarations ---- */

/* pcfg.c - main + I/O */
int get_nprocs(void);
#ifdef INTEL
char *findeol(char *s, int64_t l);
#else
#define findeol(a,b) memchr(a,10,b)
#endif

/* Per-thread workspace for parse + train (heap allocated, no stack arrays) */
typedef struct {
    unsigned char *tag;         /* PCFG_MAXLINE bytes: byte tags for parse */
    char *lower;                /* PCFG_MAXLINE bytes: lowercase scratch */
    char *val;                  /* PCFG_MAXLINE bytes: section value copy */
    char *base_str;             /* PCFG_MAXLINE bytes: base structure string */
    char *mask;                 /* PCFG_MAXLINE bytes: case mask */
    char *lowered;              /* PCFG_MAXLINE bytes: lowered alpha */
    char *decoded;              /* PCFG_MAXLINE bytes: $HEX decode */
    Section *sects;             /* PCFG_MAXSECTIONS: parsed sections */
} WorkSpace;

WorkSpace *ws_alloc(void);
void ws_free(WorkSpace *ws);

/* pcfg_parse.c - password decomposition */
typedef struct MultiWordTrie MultiWordTrie;
extern MultiWordTrie *GlobalMultiTrie;
int  pcfg_parse(char *pw, int pwlen, Section *sects, int maxsects,
                unsigned char *tag, char *lower);
void detect_years(Section *sects, int *nsects);
void detect_context(Section *sects, int *nsects);
void detect_alpha(Section *sects, int *nsects);
void detect_digits(Section *sects, int *nsects);
void detect_other(Section *sects, int *nsects);
void build_base_structure(Section *sects, int nsects, char *out, int outlen);
void build_case_mask(const char *alpha, int len, char *mask);

/* pcfg_train.c - training */
int  pcfg_train(const char *infile, const char *outdir, TrainCtx *ctx);
void counter_inc(Counter *c, const char *key);
void counter_inc_n(Counter *c, const char *key, int64_t n);
void lencounter_inc(LenCounters *lc, int len, const char *key);
void counter_free(Counter *c);
void lencounter_free(LenCounters *lc);

/* pcfg_save.c - save/load grammar */
int  pcfg_save(const char *outdir, TrainCtx *ctx);
int  pcfg_load(const char *ruledir, GenCtx *ctx);

/* pcfg_queue.c - priority queue */
void    pq_init(PQueue *pq, int initial_cap);
void    pq_push(PQueue *pq, PTItem *item);
int     pq_pop(PQueue *pq, PTItem *out);
int     pq_empty(PQueue *pq);
void    pq_free(PQueue *pq);
PTItem *find_children(GenCtx *ctx, PTItem *parent, int *nchildren);
int     are_you_my_child(GenCtx *ctx, PTNode *child, int nnodes,
                         double base_prob, int parent_pos, double parent_prob);
double  find_prob(GenCtx *ctx, PTNode *nodes, int nnodes, double base_prob);

/* pcfg_gen.c - guess generation */
int  pcfg_generate(const char *ruledir, GenCtx *ctx);

/* Arena */
void  arena_init(Arena *a, size_t block_size);
char *arena_alloc(Arena *a, size_t nbytes);
char *arena_strdup(Arena *a, const char *s);
char *arena_strndup(Arena *a, const char *s, size_t n);
void  arena_free(Arena *a);

/* UTF-8 */
int      utf8_decode(const char *s, int len, uint32_t *cp);
int      utf8_encode(char *buf, uint32_t cp);
int      utf8_cplen(const char *s, int bytelen);
int      utf8_is_alpha(uint32_t cp);
int      utf8_is_upper(uint32_t cp);
int      utf8_is_digit(uint32_t cp);
uint32_t utf8_to_lower(uint32_t cp);
uint32_t utf8_to_upper(uint32_t cp);

/* Utility */
int  decode_hex(const char *hex, char *out, int hexlen);
void format_prob(double prob, char *buf, int buflen);
void format_prob_ratio(int64_t count, int64_t total, char *buf, int buflen);
void print_mem(const char *label);

/* Multiword trie */
MultiWordTrie *multiword_new(int threshold, int min_len, int max_len);
void  multiword_free(MultiWordTrie *mw);
void  multiword_train(MultiWordTrie *mw, const char *pw, int pwlen);
int   multiword_parse(MultiWordTrie *mw, const char *alpha, int alen,
                      int *parts, int max_parts);

/* OMEN Markov trainer */
typedef struct OmenTrainer OmenTrainer;
OmenTrainer *omen_new(int ngram, int alphabet_size);
void omen_build_alphabet(OmenTrainer *ot, Counter char_freq);
void omen_train(OmenTrainer *ot, const char *pw, int pwlen);
void omen_smooth(OmenTrainer *ot);
int  omen_save(OmenTrainer *ot, const char *omen_dir);
void omen_free(OmenTrainer *ot);

/* Context-sensitive patterns */
extern const char *context_patterns[];
extern int n_context_patterns;

/* TLD list */
extern const char *tld_list[];
extern int n_tlds;

#endif /* PCFG_H */
