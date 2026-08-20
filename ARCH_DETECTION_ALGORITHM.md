# FirmArchDetect Instruction Set Detection Algorithm

This document describes the core algorithm used by `detect_arch_rizin.py` to identify the most likely CPU instruction set for a firmware image.

## High-level Goal

FirmArchDetect does not identify an architecture from a single magic value. It runs the same firmware through several Rizin architecture profiles, measures whether the resulting code analysis looks structurally valid, and ranks the candidates by a weighted confidence score.

The pipeline is:

```text
input firmware
  -> normalize address/data image
  -> analyze with candidate Rizin profiles
  -> collect functions, instructions, jumps, and xrefs
  -> compute per-profile structural scores
  -> rank by confidence
```

## Input Normalization

The detector accepts two broad input classes.

### Raw Binary Inputs

Raw binary-like files such as `.bin`, `.img`, `.rom`, `.raw`, and `.dump` do not carry address information. These inputs require `--base`.

The base address is passed to Rizin with `-m`, so Rizin maps file offset `0` to the provided load address.

Example:

```powershell
python .\detect_arch_rizin.py firmware.bin --base 0x00158000
```

### HEX-like Inputs

HEX-like files such as `.hex`, `.ihex`, `.mot`, `.s19`, and `.srec` already contain addresses. The detector parses these records, finds the minimum and maximum addressed bytes, builds a temporary flat binary filled with `0xFF` for gaps, and uses the minimum embedded address as the effective base address.

This means HEX-like inputs normally do not need `--base`.

Example:

```powershell
python .\detect_arch_rizin.py firmware.hex
```

## Candidate Architecture Profiles

Each candidate is represented by an `ArchProfile` containing:

- Rizin architecture name, such as `arm`, `v850`, or `tricore`
- bit width
- optional CPU subtype, such as ARM `thumb`
- optional endian setting
- expected function alignment
- expected bytes-per-instruction range
- reasonable function size range

The full supported profile list is kept in `PROFILES`. Normal detection uses a smaller ECU-focused default set for speed:

| Profile | Reason |
| --- | --- |
| `arm` / `thumb` | Common Cortex-M and ARM-based ECU firmware |
| `arm` 32-bit | ARM32 firmware without Thumb vector evidence |
| `v850` | Renesas V850 / RH850 automotive MCUs |
| `tricore` | Infineon AURIX / TriCore ECUs |
| `ppc` big-endian | PowerPC automotive controllers |
| `mips` big/little-endian | Some embedded controllers and SoCs |
| `sh` | Renesas SuperH legacy firmware |
| `rx` | Renesas RX firmware |
| `rl78` | Renesas RL78 firmware |
| `m68k` | Motorola 68000 family legacy controllers |

Use `--all-arch` to scan every supported profile, or `--arch` to pass an explicit subset.

```powershell
python .\detect_arch_rizin.py firmware.bin --base 0x00158000 --all-arch
python .\detect_arch_rizin.py firmware.bin --base 0x00158000 --arch arm,v850,tricore
```

## Rizin Analysis Stage

For each selected profile, the detector starts Rizin with profile-specific arguments:

```text
-a <arch> -b <bits> -e io.va=true [-e asm.cpu=<cpu>] [-E <endian>] [-m <base>]
```

The normal analysis command is `aaa`, followed by:

```text
aflj;axlj
```

These collect:

- `aflj`: analyzed functions
- `axlj`: cross-references

For ARM Thumb firmware with a valid vector table, the detector seeds analysis at vector-table targets before reading `aflj`. This is important because Cortex-M reset vectors are Thumb addresses and often need explicit function creation.

## Function and Reference Evidence

After Rizin returns analysis data, FirmArchDetect extracts these values:

| Metric | Meaning |
| --- | --- |
| `functions` | Number of Rizin-discovered functions |
| `basic_blocks` | Total basic blocks reported by Rizin |
| `analyzed_bytes` | Total bytes covered by discovered functions |
| `valid_instructions` | Instruction sample count minus invalid instructions |
| `code_references` | Code-like references discovered by Rizin |
| `valid_code_references` | Code references whose target falls inside a known function |
| `function_xrefs` | References whose source falls inside a known function |
| `valid_function_xrefs` | Function xrefs whose target also falls inside a known function |

The detector also samples disassembly with `pdj` from the largest functions to estimate invalid instruction density. This helps reduce false positives where Rizin creates many functions from random data.

## Structural Sub-scores

Each profile gets several normalized sub-scores in the range `0.0..1.0`.

### Function Count Score

Function count is useful but not trusted by itself. The detector applies logarithmic normalization so a profile with many functions does not dominate everything else:

```text
function_count_score = log1p(functions) / max_log_functions
```

`max_log_functions` is computed across successful candidates in the same run.

### Alignment Score

Each architecture has an expected function start alignment. For example:

- ARM32: 4-byte alignment
- Thumb: 2-byte alignment
- RH850/V850: 2-byte alignment
- TriCore: 2-byte alignment
- PowerPC/MIPS: 4-byte alignment

The score is:

```text
alignment_score = aligned_functions / functions
```

Misaligned functions reduce confidence.

### Size Score

Functions with implausible sizes are penalized. A function is considered suspicious if it is too small, too large, or outside the mapped firmware image.

```text
size_score = reasonable_function_count / functions
```

### Instruction Score

The detector first checks bytes-per-instruction against architecture-specific expected ranges. If real disassembly samples are available, it prefers the sampled invalid-instruction ratio:

```text
instruction_score = valid_sampled_instructions / sampled_instructions
```

Invalid opcodes or illegal instruction types reduce this score.

### Jump Target Score

A candidate architecture should produce code references that point back into code. The score is:

```text
jump_target_score = valid_code_references / code_references
```

If there are no code references, a neutral score is used instead of forcing zero.

### Xref Score

Real code usually has internal function-to-function references. The score is:

```text
xref_score = valid_function_xrefs / function_xrefs
```

A high xref score means the candidate produced a coherent function graph.

### Entry Score

Some architectures have recognizable entry patterns. Entry evidence is used as an additional heuristic, especially when automatic function discovery is sparse.

Currently implemented entry checks include:

| Architecture | Entry evidence |
| --- | --- |
| ARM Thumb | Cortex-M style vector table: initial stack pointer in SRAM range, reset vector is odd Thumb address inside firmware |
| V850/RH850 | Lightweight reset/vector-pattern evidence near the image start |
| TriCore | Startup opcode markers and high-address base hints such as `0x80000000` or `0xA0000000` |
| RL78/RX/SH | Small neutral prior, because lightweight entry recognition is less specific |

When entry evidence is strong enough, a candidate can remain valid even if Rizin finds few or no functions.

## Final Confidence Formula

After all candidates are analyzed, the detector combines sub-scores with fixed weights:

```text
confidence =
    function_count_score * 0.12 +
    alignment_score      * 0.10 +
    size_score           * 0.15 +
    instruction_score    * 0.23 +
    jump_target_score    * 0.12 +
    xref_score           * 0.10 +
    entry_score          * 0.18
```

The largest weights are assigned to instruction validity and function-size sanity because they are usually stronger indicators than raw function count.

For strong ARM/V850/TriCore entry evidence, the score may be raised to a minimum confidence floor:

```text
score = max(score, 0.78 + entry_score * 0.10)
```

This is used to rescue cases where the entry pattern is highly characteristic but Rizin analysis is incomplete.

## Ranking and Winner Selection

Candidates are sorted by:

1. confidence
2. raw score
3. structural score
4. function count
5. architecture priority tie-breaker

The terminal output shows the top 10 candidates by default.

A candidate is eligible as the winner when:

- Rizin status is `ok`, and
- it has at least one function, or strong enough entry evidence

If no candidate meets those conditions, the result is `unknown`.

## Why Function Count Alone Is Not Enough

Different Rizin architecture plugins may decode random bytes into very different numbers of functions. A wrong architecture can sometimes produce more functions than the correct one.

For that reason, function count only contributes 12% to final confidence. The detector also checks:

- whether function starts match architecture alignment
- whether function sizes are plausible
- whether sampled instructions contain many invalid opcodes
- whether jumps land inside discovered code
- whether functions reference each other coherently
- whether reset/vector evidence matches the architecture

## Known Limitations

This is still a heuristic detector. Results should be reviewed together with known ECU metadata, memory maps, and manual reverse engineering evidence.

Important limitations:

- Encrypted or compressed firmware payloads may produce misleading scores.
- Bootloader-only images may not contain enough application code.
- Flat binaries require a correct `--base`; a wrong base weakens entry and reference checks.
- HEX-like inputs with many artificial gaps are flattened for Rizin analysis, which may affect cross-reference quality.
- Rizin plugin quality differs by architecture and build.
- Some architectures share similar instruction widths and can score close together.

## Practical Interpretation

A confident result usually has:

- a clear confidence margin over the runner-up
- high instruction score
- good alignment and size scores
- non-trivial valid xrefs or valid jump targets
- architecture-specific entry evidence if applicable

A low-margin result should be treated as a shortlist, not as a final answer.
