# Cpcfg

High-performance Probabilistic Context-Free Grammar (PCFG) password generator, written in C. A reimplementation of [pcfg-go](https://github.com/cyclone-github/pcfg-go) with significant performance improvements.

## Overview

Cpcfg trains on cracked passwords to learn structural patterns (e.g., "6 letters + 2 digits" = `A6D2`), then generates guesses in probability-descending order using a priority queue. Integrates OMEN Markov chains for unknown character sequences.

**Performance**: 5.5x faster than pcfg-go on training. Trains 14.3 million passwords in 24 seconds (vs 131 seconds for Go).

## Features

Cpcfg implements the full feature set of [pcfg-go](https://github.com/cyclone-github/pcfg-go), which itself extended the original [pcfg_cracker](https://github.com/lakiw/pcfg_cracker) by Matt Weir:

- **8 password detectors** (from pcfg-go): keyboard walks (5 layouts), emails, websites, years, context-sensitive patterns, alpha runs with multiword splitting, digit runs, special characters
- **OMEN Markov integration** (from pcfg-go): n-gram based character-level probability model
- **Multiword detection** (from pcfg-go): trie-based splitting of compound passwords (e.g., "helloworld" → "hello" + "world")
- **Priority queue generation** (from pcfg_cracker): guesses emitted in strict probability-descending order

Cpcfg adds:

- **Parallel training**: job-queue architecture with double-buffered I/O and adaptive thread scaling
- **Parallel generation**: popper/worker pipeline with pre-allocated buffers
- **Single-pass I/O**: no file rewinding, works with pipes
- **UTF-8 support**: Unicode alpha/case detection for Latin Extended, Cyrillic, Greek, CJK, Arabic, Hebrew, Thai
- **Admission filter** (`-f`): removes rare tokens below a count threshold, reducing grammar size by 80%+ (inspired by [hashcat PCFG](https://github.com/matrix/hashcat/tree/pcfg_ahf_v1.0) by matrix)
- **Weighted wordlists** (`-w`): input format `count:password` — weights flow into every counter, the multiword trie, and the OMEN Markov model for frequency-aware training
- **Leet folding**: `p4ssw0rd` trains as the word "password" plus a learned substitution mask, so one trained word regenerates all its leet spellings (applied like case masks at generation)
- **Date detection**: 6/8-digit runs that parse as calendar dates (`DDMMYYYY`, `MMDDYYYY`, `YYMMDD`, ...) are typed `B` instead of opaque digit runs
- **Temperature sampling** (`-P`): sample passwords from the grammar weighted by `prob^(1/τ)` instead of enumerating — τ > 1 explores rare patterns, τ < 1 sharpens toward the most likely
- **Junk filter** (`-F`): automatic removal of base64, hex hashes, JSON, and HTML from training input (inspired by hashcat PCFG)
- **Grammar merge** (`-M`): combine two trained grammars by summing their counters (inspired by hashcat PCFG)
- **AHF synthetic generation** (`-A`): generates passwords never seen in training using OMEN Markov chains (inspired by hashcat PCFG)
- **Model info** (`-i`): display grammar statistics (structure count, entry distribution, top patterns)
- **Skip brute** (`-b`): exclude Markov/OMEN entries during generation
- **$HEX[] support**: decodes $HEX-encoded passwords in training, encodes non-printable output — on every generation path (`-G`, `-P`, `-A`), from one shared implementation
- **File format compatible** with pcfg-go: trained grammars are interchangeable. `config.ini` describes every section type the grammar actually uses, including `B` (dates), `R` (repeats), the `L` leet transition and any `-E` category letters. One caveat: `Sem/` names its files by the whole type key (`N4.txt`) rather than by length (`4.txt`) as the other length-indexed directories do, so a reader must open the filenames `config.ini` lists rather than deriving them
- **Memory reporting**: RSS displayed at key phases

## Building

Requires libJudy and pthreads.

```sh
make pcfg
```

## Usage

### Training

Train on a wordlist of cracked passwords:

```sh
pcfg -t <wordlist> -g <grammar_dir> [options]
```

Training analyzes password structure and writes the resulting grammar to a directory tree at the path given by `-g`. This directory is created automatically and contains probability tables, OMEN Markov data, and training metadata (`config.ini`).

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-t <file>` | Training password file (required, or `stdin` for standard input) | — |
| `-g <grammar_dir>` | Output grammar directory (created by training) | — |
| `-T <int>` | Max worker threads | auto |
| `-f <int>` | Admission filter: skip tokens with count below threshold | 0 (off) |
| `-w` | Weighted input: lines are `count:password` format | off |
| `-F` | Filter junk lines (base64, hex hashes, JSON, HTML) | off |
| `-S` | Save sensitive data (full emails, URLs) | off |
| `-c <float>` | PCFG vs OMEN coverage split (0.0–1.0) | 0.6 |
| `-n <int>` | OMEN n-gram size (2–5) | 4 |
| `-a <int>` | OMEN alphabet size | 100 |
| `-C <str>` | Add comments to config | — |

**Examples:**

```sh
# Basic training
pcfg -t rockyou.txt -g /tmp/rockyou_grammar

# With admission filter (skip tokens seen fewer than 3 times — reduces grammar 80%+)
pcfg -t rockyou.txt -g /tmp/rockyou_grammar -f 3

# Filter junk lines from messy input (removes base64, hex hashes, JSON, HTML)
getpass < cracked.txt | pcfg -t stdin -g /tmp/clean_grammar -F

# Weighted input (count:password format, e.g. from frequency analysis)
pcfg -t weighted_passwords.txt -g /tmp/weighted_grammar -w

# Train with 4 threads and custom OMEN settings
pcfg -t passwords.txt -g /tmp/mygrammar -T 4 -c 0.8 -n 3

# Train from pipe — single-pass, no seeking required
cat cracked.txt | pcfg -t stdin -g /tmp/piped

# Merge two grammars (combine training from separate datasets)
pcfg -M /tmp/round1_grammar -M /tmp/round2_grammar -g /tmp/combined_grammar

# AHF: generate 1M synthetic passwords using Markov chains
pcfg -A -g /tmp/rockyou_grammar -n 1000000

# Sample 1M passwords at temperature 1.5 (more diversity)
pcfg -P -g /tmp/rockyou_grammar -n 1000000 -e 1.5

# Display grammar statistics
pcfg -i -g /tmp/rockyou_grammar
```

### Generation

Generate password guesses from a previously trained grammar:

```sh
pcfg -G -g <grammar_dir> [options]
```

Reads the grammar directory created by a prior training run and writes guesses to stdout in probability-descending order. Passwords containing colons or non-printable characters are output in `$HEX[]` encoding. Case masks (`C`) and leet masks (`L`) are applied to alpha values at generation time, mirroring how they were folded during training.

### Sampling

Sample passwords directly from the trained distribution instead of enumerating:

```sh
pcfg -P -g <grammar_dir> [-n count] [-e temperature]
```

Each sample draws a base structure weighted by `prob^(1/τ)`, then draws each terminal the same way, falling back to OMEN Markov generation for alpha slots with no trained data. τ = 1.0 is faithful to training; τ > 1 flattens the distribution for broader coverage; τ < 1 concentrates on the head. Sampling reaches deep, low-probability parts of the grammar without the priority queue's ordering overhead.

### Coverage diagnosis

Find out why a grammar misses a password set, and what would close the gap:

```sh
pcfg -D -g <grammar_A> -t <passwords_B> [-w] [-k] [-o <file>]
```

With `-o <file>` the complete missing-entry list is dumped as TSV — `category<TAB>value<TAB>count_in_B`, sorted by count within category (`-o -` writes to stdout). The full missing alpha vocabulary is then just:

```sh
pcfg -D -g grammar_A -t setB.txt -o missing.tsv
awk -F'\t' '$1=="alpha"{print $2}' missing.tsv > missing_words.txt
```

Every B password is decomposed exactly as training would (structure, terminals, case/leet masks, dates) and checked against A's grammar. A password is generatable iff all components exist. The report shows:

- **Reachable vs missed vs unsupported** (emails/websites are never generated)
- **Primary blocker per miss**, tallied by category, with the most frequent missing entries — which words, structures, masks, digit strings, or dates B uses that A never saw
- **Probability depth** of the reachable set under A (how deep in the queue B's passwords live)
- **Gap closure simulation**: adding each missing category in order of impact, with the exact reachable % after each step, up to the merge ceiling
- **Suggested commands** (`-M` merge, retrain) matched to the findings

Limitations: multiword splitting is not replayed (the trie isn't saved), so compound words A split differently are attributed as alpha misses; diagnosis assumes the grammar was trained with the same cpcfg version (same leet/date rules).

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-G` | Generation mode (required) | — |
| `-g <grammar_dir>` | Grammar directory (created by prior `-t` training) | — |
| `-n <int>` | Max guesses (0 = unlimited) | 0 |
| `-b` | Skip OMEN/Markov guesses | off |
| `-a` | Disable case mangling | off |
| `-d` | Debug: print parse trees instead of guesses | off |
| `-T <int>` | Number of threads | auto |

**Examples:**

```sh
# Generate guesses to stdout
pcfg -G -g /tmp/rockyou_grammar

# Generate 10 million guesses
pcfg -G -g /tmp/rockyou_grammar -n 10000000

# Generate without Markov guesses
pcfg -G -g /tmp/rockyou_grammar -b
```

## Integration with mdxfind

Cpcfg is designed to work in a pipeline with mdxfind for password cracking.

### Basic pipeline

```sh
# Generate guesses and feed directly to mdxfind
pcfg -G -g /tmp/mygrammar | mdxfind -f hashes.txt stdin

# With a guess limit
pcfg -G -g /tmp/mygrammar -n 50000000 | mdxfind -f hashes.txt stdin
```

### Iterative cracking

Crack, retrain on new results, crack again:

```sh
# Initial crack with a wordlist
mdxfind -f hashes.txt wordlist.txt > cracked_round1.txt

# Extract passwords and train grammar
getpass < cracked_round1.txt | pcfg -t stdin -g /tmp/round1

# Generate guesses for round 2
pcfg -G -g /tmp/round1 | mdxfind -f hashes.txt stdin > cracked_round2.txt

# Train round 2 results separately, then merge both grammars
getpass < cracked_round2.txt | pcfg -t stdin -g /tmp/round2
pcfg -M /tmp/round1 -M /tmp/round2 -g /tmp/combined

# Round 3 with improved model
pcfg -G -g /tmp/combined | mdxfind -f hashes.txt stdin > cracked_round3.txt
```

### Combining with mangling rules

Stream pcfg guesses into mdxfind with rule-based mangling:

```sh
pcfg -G -g /tmp/mygrammar | mdxfind -f hashes.txt -r best64.rule stdin
```

Or save guesses first, then use procrule to apply rules (procrule reads the full wordlist before processing):

```sh
pcfg -G -g /tmp/mygrammar -n 10000000 > /tmp/pcfg_words.txt
procrule -r best64.rule /tmp/pcfg_words.txt | mdxfind -f hashes.txt stdin
```

### Training on $HEX[] encoded output

mdxfind outputs non-printable passwords in `$HEX[]` format. Cpcfg handles this natively — no preprocessing needed:

```sh
mdxfind -f hashes.txt wordlist.txt > cracked.txt
getpass < cracked.txt | pcfg -t stdin -g /tmp/mygrammar
```

## Memory Usage

Memory consumption scales with the number of unique password patterns, not total passwords. Typical values for rockyou.txt (14.3M passwords):

```
pcfg: before merge: 14.7 GB RSS
pcfg: after merge: 14.8 GB RSS
pcfg: final: 14.9 GB RSS
```

The majority of memory is consumed by:
- OMEN Markov n-gram contexts (JudySL)
- Multiword detection trie
- Per-thread Judy arrays for PCFG counters

Thread count (`-T`) does not significantly affect memory — the sequential components (OMEN, multiword) dominate.

## Trained Grammar Format

Training output is stored in the grammar directory with this structure:

```
<grammar_dir>/
├── config.ini           # Training metadata
├── Grammar/
│   └── grammar.txt      # Base structure probabilities
├── Alpha/               # Alphabetic values by length
├── Capitalization/      # Case masks by length
├── Leet/                # Leet substitution masks by length
├── Digits/              # Digit sequences by length
├── Dates/               # Date-shaped digit runs by length (6, 8)
├── Other/               # Special character sequences
├── Keyboard/            # Keyboard walk sequences
├── Years/               # Year values
├── Context/             # Context-sensitive patterns
├── Emails/              # Email providers
├── Websites/            # Website hosts and prefixes
└── Omen/                # OMEN Markov model files
```

Probability format: `value\tcount/total` (integer ratio, converted to float at load time).

Grammars trained with Cpcfg can be loaded by pcfg-go's guesser, and vice versa. Cpcfg-specific extensions (the `Leet/` and `Dates/` directories, the `L`/`B` grammar types) are extra: pcfg-go ignores the unknown directories, while cpcfg uses them for leet-mask and date generation.

## How It Works

### Password Decomposition

Each training password is parsed through 8 sequential detectors:

1. **Keyboard walks** — adjacent keys on QWERTY/JCUKEN/QWERTZ/AZERTY/Dvorak (min 4 chars, >=2 char types)
2. **Emails** — `user@provider.tld` patterns
3. **Websites** — `domain.tld` with optional `http://`/`www.` prefix
4. **Years** — 4-digit years matching `19XX` or `20XX`
5. **Dates** — 6/8-digit runs that parse as calendar dates in any common order (`YYYYMMDD`, `DDMMYYYY`, `MMDDYYYY`, `YYMMDD`, `DDMMYY`, `MMDDYY`), validated per month and leap years
6. **Context-sensitive** — fixed patterns like `;p`, `<3`, `Mr.`, `No.1`
7. **Alpha runs** — letter sequences, with multiword trie splitting for compound words. Leet chars between letters (`4 a e`, `3 e`, `0 o`, `1 i`, `5 s`, `7 t`, `@ a`, `$ s`, `! i`) fold into the word: `p4ssw0rd` trains as "password" plus a leet mask, exactly like a case mask
8. **Digit runs** — digit sequences
9. **Other** — remaining special characters

Leet chars only fold when surrounded by letters, so `password1` stays `A8 D1` (word + digit) while `p4ssw0rd` becomes a single `A8`. The leet mask is stored per length in `Leet/` and re-applied at generation, so every trained word can regenerate its leet variants.

Example: `password2024!` → `A8` `D4` `O1` (base structure `A8D4O1`)

### Semantic tagging (`-E`), smoothing (`-s`), repeats (`-R`)

Inspired by SE#PCFG (TDSC 2025), as opt-in training flags:

- **`-R`** types digit/alpha runs made of 2+ copies of a unit (`123123`, `hahaha`, `qazqazqaz`) as `R{len}` sections (`Repeats/{len}.txt`).
- **`-E <dir>`** tags alpha words with a semantic category letter you define via wordlists: `dir/{X}*.txt`, one word per line in whatever capitalisation the list comes in, where `X` is the grammar type letter (reserved: `A D O Y X K E W C M L B R`). Words are matched after folding — lowercased by Unicode rules, leet characters folded to the letters they stand for — so `MÜLLER` and `Öztürk` match; matching is exact on the folded form, so `José` does not tag `jose1990`. A word in several category files takes the alphabetically first filename's letter. A file matching neither `{Letter}*.txt` nor `_*.txt` is reported and skipped rather than aborting the load. `mary123` then trains as `N4 D3` instead of `A4 D3`, and the grammar can regenerate `susan123` — vocabulary generalization through structure. Untagged words fall back to plain `A`. Terminals are stored per type key in `Sem/` (`N4.txt`), case/leet masks stay shared. Use the same `-E`/`-R` flags with `-D` so parsing matches.
- **`-s <frac>`** (with `-E`) reserves a fraction of each terminal distribution's probability mass for corpus words never seen in training (SEPCA-style smoothing): unobserved corpus words are injected with equal pseudo-counts sized to that budget. A file named `_*.txt` in the corpus dir provides the vocabulary for untagged `A` terminals.

```sh
# categories: names (N), months (T), fallback vocabulary (_)
mkdir sem && cp names.txt sem/N_names.txt && cp months.txt sem/T_months.txt && cp top10k.txt sem/_words.txt
pcfg -t cracked.txt -g grammar -R -E sem -s 0.2
```

Building the category wordlists is easiest with `tools/build_sem.py` (Python 3, stdlib; `--lang` needs `pip install wordfreq`). It normalizes words to pcfg's terminal-key format, dedupes across categories with fixed priority (specific before generic), and writes the lettered files:

```sh
python3 tools/build_sem.py --out sem \
    --builtin --names-ssa names.zip --geonames cities15000.txt \
    --lang F=en:50000 --from-grammar /tmp/mygrammar
```

Sources: `--builtin` (calendar → `T`), `--names-ssa` (SSA yob files or zip → `N`, [names.zip](https://www.ssa.gov/oact/babynames/names.zip)), `--geonames` (GeoNames cities dump → `G`), `--lang F=en:50000` (top-N words of a language via wordfreq), `--from-wordlist N=file` (any wordlist you have), `--from-grammar DIR` (the Alpha vocabulary of a trained grammar — a good bootstrap from your own cracked data), `--fallback FILE` (`_words.txt`).

No-Python alternatives for quick categories:

```sh
# English vocabulary from rockyou: frequent pure-alpha words as fallback corpus
grep -E '^[a-z]{3,21}$' rockyou.txt | sort | uniq -c | awk '$1>=20{print $2}' > sem/_words.txt

# any wordlist becomes a category
cp names.txt sem/N_names.txt

# vocabulary from an existing trained grammar
cat grammar/Alpha/*.txt | cut -f1 | sort -u > sem/_words.txt
```

### Priority Queue Generation

Guesses are produced in strict probability-descending order using a binary max-heap. The `areYouMyChild` pruning algorithm ensures each configuration is explored exactly once. Case masks (`C` entries) are applied at generation time, not stored in the base structure.

## Performance

### Training (rockyou.txt, 14.3M passwords, same machine)

| Tool | Language | Time | Speedup |
|---|---|---|---|
| **Cpcfg** | C | **24s** | — |
| pcfg-go | Go | 131s | 5.5x |
| pcfg_cracker | Python | 24 min | 60x |

Larger datasets:

| Dataset | Passwords | Machine | Threads | Time | RSS |
|---|---|---|---|---|---|
| rockyou.txt | 14.3M | macOS x86_64 | 16 | **24s** | 14.9 GB |
| BigBabyPass | 332M | Linux x86_64 | 72 | **15 min** | 159 GB |

### Generation (same machine, macOS x86_64, rockyou.txt grammar)

| Guesses | Cpcfg | pcfg-go v0.5.2 | Speedup |
|---|---|---|---|
| 1M | **1.0s** | 2.5s | **2.4x** |
| 50M | **9.6s** | 15.0s | **1.6x** |
| 100M | **17.3s** | 26.8s | **1.5x** |

pcfg_cracker (Python): 28s for 1M guesses (28x slower than Cpcfg).


Key optimizations:
- Double-buffered block I/O with SSE2 `findeol()`
- SSSE3 vectorized `$HEX[]` decoding (from mdxfind `get32()`)
- Job-queue parallel training with persistent worker threads
- Thread-local Judy arrays with single post-merge
- Pool-allocated trie nodes for multiword detection
- Inline integer-to-ASCII for probability output (no `snprintf`)
- Single-pass file reading (no rewind)

## Companion tool: `tools/stylegen`

Some passwords were never typed. They were pasted, from a "fancy text
generator" website, and no case or mangling rule can produce them:

```
Ｐａｓｓｗｏｒｄ    pɹoʍssɐd    p̲a̲s̲s̲w̲o̲r̲d̲    𝙃𝙚𝙣𝙧𝙞𝙦𝙪𝙚20
```

Mathematical Alphanumeric characters have **no Unicode case mappings**, so
`c`, `u`, `l`, `C` and `t` are identity transforms on them. A grammar trained
on such a plaintext learns the styled byte sequence, which is a one-off, rather
than the base word, which is reusable.

`stylegen --unstyle` is the normaliser for that, and it is why the tool ships
here:

```sh
stylegen --unstyle founds.txt | pcfg -t stdin -g grammar
```

It undoes the compatibility substitution and **keeps combining marks**, so
`𝙃𝙚𝙣𝙧𝙞𝙦𝙪𝙚` becomes `Henrique` while `Muñoz` keeps its `ñ`. That distinction
matters because the hash covers bytes: `Munoz` and `Muñoz` are different
passwords with different digests, so a grammar trained on a deaccented form can
never generate the accented one.

`--strip` is the destructive variant — it also drops combining marks, which is
what you want for Zalgo (`p͞é͜ng̸u̡͘iń͢͞k̴è͢͜e̛p͠è͢r` → `penguinkeeper`), since Zalgo is
randomised mark injection and is not enumerable at any scale.

Run without a mode it generates styled variants instead, for use as candidates.
The productive base list there is names and handles rather than dictionary
words: no keyboard layout emits U+1D643, so these arrive by paste, typically
from a social-media display name.

See `man stylegen` for the full option set and the per-script coverage.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [pcfg_cracker](https://github.com/lakiw/pcfg_cracker) by Matt Weir — the original PCFG password research toolkit
- [pcfg-go](https://github.com/cyclone-github/pcfg-go) by cyclone — Go reimplementation
- [hashcat PCFG](https://github.com/matrix/hashcat/tree/pcfg_ahf_v1.0) by matrix — admission filter and junk detection concepts
- [hpcfg](https://github.com/matrix/hpcfg) by matrix — reported three defects fixed in 1.20: the Latin Extended-A case parity runs, the year pass overwriting an earlier pass, and adjacent keyboard walks merging into a single terminal
- [yarn.c](http://www.zlib.net/) by Mark Adler — threading library
- [Judy arrays](http://judy.sourceforge.net/) — high-performance associative arrays
