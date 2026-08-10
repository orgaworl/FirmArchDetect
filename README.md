# FirmArchDetect

FirmArchDetect is a heuristic firmware architecture detector built around Rizin.
It tries multiple CPU profiles on the same firmware image, runs automatic
analysis, and ranks the candidates by structural confidence.

## What it does

- Supports raw binary inputs and HEX-like inputs.
- Requires `--base` for raw binaries.
- Uses embedded addresses for HEX / S-record style files.
- Scores candidates using:
  - function count
  - function start alignment
  - function size sanity
  - instruction density / invalid-code hints
  - jump-target validity
  - function cross-references
- Prints a ranked top-10 table by default.
- Can emit the full JSON report with `--json`.

## Requirements

- Python 3.10+
- Rizin available in `PATH`, or pass its path with `--rizin`
- Rizin GitHub: [rizinorg/rizin](https://github.com/rizinorg/rizin)

## Usage

```powershell
python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000
python .\detect_arch_rizin.py .\firmware.hex
python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000 --json
python .\detect_arch_rizin.py .\firmware.bin --arch arm --arch v850 --arch tricore
python .\detect_arch_rizin.py --list-arch
```

## Input rules

- Raw binary files such as `.bin`, `.img`, `.rom`, `.raw`, and `.dump` must
  provide `--base`.
- HEX-like files such as `.hex`, `.ihex`, `.mot`, `.s19`, and `.srec` keep
  their own addresses and do not need `--base`.

## Output

Default terminal output:

- ranked top 10 architectures
- per-candidate confidence
- `Funcs`, `Align`, `Size`, `Instr`, `Jumps`, and `Xrefs` scores
- selected winner

JSON output includes:

- `winner`
- `winner_confidence_margin`
- full ranked `results`
- per-candidate structural sub-scores and errors

## Notes

This tool is heuristic. A high score does not guarantee the correct architecture.
Use the result together with known memory maps, entry points, and manual review.

