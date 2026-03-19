# Cpcfg

High-performance Probabilistic Context-Free Grammar (PCFG) password generator, written in C. A reimplementation of [pcfg-go](https://github.com/cyclone-github/pcfg-go) with significant performance improvements.

## Overview

Cpcfg trains on cracked passwords to learn structural patterns (e.g., "6 letters + 2 digits" = `A6D2`), then generates guesses in probability-descending order using a priority queue. Integrates OMEN Markov chains for unknown character sequences.

**Performance**: 5.5x faster than pcfg-go on training. Trains 14.3 million passwords in 24 seconds (vs 131 seconds for Go).

## Features

- **8 password detectors**: keyboard walks (5 layouts), emails, websites, years, context-sensitive patterns, alpha runs (with multiword splitting), digit runs, special characters
- **OMEN Markov integration**: n-gram based character-level probability model
- **Multiword detection**: trie-based splitting of compound passwords (e.g., "helloworld" → "hello" + "world")
- **Parallel training**: job-queue architecture with double-buffered I/O, adaptive thread scaling
- **Single-pass I/O**: no file rewinding, works with pipes
- **File format compatible** with pcfg-go: trained grammars are interchangeable
- **$HEX[] support**: decodes $HEX-encoded passwords in training input
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

The trained grammar is stored in the directory specified by `-g`.

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-t <file>` | Training password file (required, or `stdin` for standard input) | — |
| `-g <dir>` | Grammar directory (required) | — |
| `-T <int>` | Max worker threads | auto |
| `-S` | Save sensitive data (full emails, URLs) | off |
| `-p` | Input lines prefixed with occurrence count | off |
| `-c <float>` | PCFG vs OMEN coverage split (0.0–1.0) | 0.6 |
| `-n <int>` | OMEN n-gram size (2–5) | 4 |
| `-a <int>` | OMEN alphabet size | 100 |
| `-C <str>` | Add comments to config | — |

**Examples:**

```sh
# Basic training
pcfg -t rockyou.txt -g /tmp/rockyou_grammar

# Train with 4 threads and custom OMEN settings
pcfg -t passwords.txt -g /tmp/mygrammar -T 4 -c 0.8 -n 3

# Train from pipe — single-pass, no seeking required
cat cracked.txt | pcfg -t stdin -g /tmp/piped
```

### Generation

Generate password guesses from a trained grammar:

```sh
pcfg -G -g <grammar> [options]
```

Guesses are written to stdout in probability-descending order.

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `-G` | Generation mode (required) | — |
| `-g <path>` | Grammar path (required) | — |
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

### Training

| Dataset | Passwords | Machine | Threads | Time | RSS |
|---|---|---|---|---|---|
| rockyou.txt | 14.3M | macOS x86_64 | 16 | **24s** | 14.9 GB |
| BigBabyPass | 332M | Linux x86_64 (mmt) | 72 | **15 min** | 159 GB |

pcfg-go comparison (rockyou.txt, same machine):

| | Cpcfg | pcfg-go | Speedup |
|---|---|---|---|
| Training | 24s | 131s | **5.5x** |

### Generation

| | Cpcfg | pcfg-go | Speedup |
|---|---|---|---|
| 1M guesses | **1.4s** | 5.1s | **3.6x** |
| 10M guesses | **3.2s** | 8.6s | **2.7x** |


Key optimizations:
- Double-buffered block I/O with SSE2 `findeol()`
- SSSE3 vectorized `$HEX[]` decoding (from mdxfind `get32()`)
- Job-queue parallel training with persistent worker threads
- Thread-local Judy arrays with single post-merge
- Pool-allocated trie nodes for multiword detection
- Inline integer-to-ASCII for probability output (no `snprintf`)
- Single-pass file reading (no rewind)

## License

See individual source files for license terms.

## Acknowledgments

- [pcfg-go](https://github.com/cyclone-github/pcfg-go) by cyclone — the reference implementation
- [yarn.c](http://www.zlib.net/) by Mark Adler — threading library
- [Judy arrays](http://judy.sourceforge.net/) — high-performance associative arrays
