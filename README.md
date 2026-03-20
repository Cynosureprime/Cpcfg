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
- **Weighted wordlists** (`-w`): input format `count:password` for frequency-aware training
- **Junk filter** (`-F`): automatic removal of base64, hex hashes, JSON, and HTML from training input (inspired by hashcat PCFG)
- **$HEX[] support**: decodes $HEX-encoded passwords in training, encodes non-printable output
- **File format compatible** with pcfg-go: trained grammars are interchangeable
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
```

### Generation

Generate password guesses from a previously trained grammar:

```sh
pcfg -G -g <grammar_dir> [options]
```

Reads the grammar directory created by a prior training run and writes guesses to stdout in probability-descending order. Passwords containing colons or non-printable characters are output in `$HEX[]` encoding.

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

# Combine results, extract passwords, retrain
cat cracked_round1.txt cracked_round2.txt | getpass | sort -u | pcfg -t stdin -g /tmp/combined

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
├── Digits/              # Digit sequences by length
├── Other/               # Special character sequences
├── Keyboard/            # Keyboard walk sequences
├── Years/               # Year values
├── Context/             # Context-sensitive patterns
├── Emails/              # Email providers
├── Websites/            # Website hosts and prefixes
└── Omen/                # OMEN Markov model files
```

Probability format: `value\tcount/total` (integer ratio, converted to float at load time).

Grammars trained with Cpcfg can be loaded by pcfg-go's guesser, and vice versa.

## How It Works

### Password Decomposition

Each training password is parsed through 8 sequential detectors:

1. **Keyboard walks** — adjacent keys on QWERTY/JCUKEN/QWERTZ/AZERTY/Dvorak (min 4 chars, >=2 char types)
2. **Emails** — `user@provider.tld` patterns
3. **Websites** — `domain.tld` with optional `http://`/`www.` prefix
4. **Years** — 4-digit years matching `19XX` or `20XX`
5. **Context-sensitive** — fixed patterns like `;p`, `<3`, `Mr.`, `No.1`
6. **Alpha runs** — letter sequences, with multiword trie splitting for compound words
7. **Digit runs** — digit sequences
8. **Other** — remaining special characters

Example: `password2024!` → `A8` `D4` `O1` (base structure `A8D4O1`)

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

### Generation (same machine, macOS x86_64, 16 threads)

| Guesses | Cpcfg | pcfg-go | Speedup |
|---|---|---|---|
| 1M | **4.4s** | 5.1s | **1.2x** |
| 50M | **27.4s** | 16.9s | 0.6x |
| 100M | **27.4s** | 28.7s | **1.0x** |

Note: Cpcfg generation is currently bottlenecked by stdout write contention across worker threads. In pipeline use (`pcfg | mdxfind`), the downstream consumer is typically the limiting factor.

pcfg_cracker (Python): 28s for 1M guesses (22x slower than Cpcfg).


Key optimizations:
- Double-buffered block I/O with SSE2 `findeol()`
- SSSE3 vectorized `$HEX[]` decoding (from mdxfind `get32()`)
- Job-queue parallel training with persistent worker threads
- Thread-local Judy arrays with single post-merge
- Pool-allocated trie nodes for multiword detection
- Inline integer-to-ASCII for probability output (no `snprintf`)
- Single-pass file reading (no rewind)

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [pcfg_cracker](https://github.com/lakiw/pcfg_cracker) by Matt Weir — the original PCFG password research toolkit
- [pcfg-go](https://github.com/cyclone-github/pcfg-go) by cyclone — Go reimplementation
- [hashcat PCFG](https://github.com/matrix/hashcat/tree/pcfg_ahf_v1.0) by matrix — admission filter and junk detection concepts
- [yarn.c](http://www.zlib.net/) by Mark Adler — threading library
- [Judy arrays](http://judy.sourceforge.net/) — high-performance associative arrays
