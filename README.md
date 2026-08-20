# FirmArchDetect

FirmArchDetect is a heuristic firmware architecture detector built around Rizin.
It tries an ECU-focused default set of CPU profiles on the same firmware image, runs automatic
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
- Uses a smaller automotive ECU default profile set for faster scans.
- Offers `--fast` for shorter sampling and early exit on clear winners.
- Prints a ranked top-10 table by default.
- Can emit the full JSON report with `--json`.

## Algorithm

For the detailed instruction-set detection and scoring algorithm, see [ARCH_DETECTION_ALGORITHM.md](ARCH_DETECTION_ALGORITHM.md).

## Requirements

- Python 3.10+
- Rizin available in `PATH`, or pass its path with `--rizin`
- Rizin GitHub: [rizinorg/rizin](https://github.com/rizinorg/rizin)

## Usage

```powershell
python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000
python .\detect_arch_rizin.py .\firmware.hex
python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000 --json
python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000 --all-arch
python .\detect_arch_rizin.py .\firmware.bin --arch arm --arch v850 --arch tricore
python .\detect_arch_rizin.py --list-arch
```

## Examples

- Detect architecture for a raw binary image:

    ```powershell
    python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000
    ```

- Detect architecture for HEX-like firmware with embedded addresses:

    ```powershell
    python .\detect_arch_rizin.py .\firmware.hex
    ```

- Run the full supported profile list when speed is less important:

    ```powershell
    python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000 --all-arch
    ```

- Limit the search to common automotive MCU families:

    ```powershell
    python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000 --arch arm --arch v850 --arch tricore
    ```

- Or pass them as a single comma-separated list:

    ```powershell
    python .\detect_arch_rizin.py .\firmware.bin --base 0x00158000 --arch arm,v850,tricore
    ```

- Print the candidate profile list:

    ```powershell
    python .\detect_arch_rizin.py --list-arch
    ```

- Evaluate the labeled datasheet samples. The script infers expected labels
  from names such as `ARM32LE_0x00020000.bin`, `RH850_0x00048000.bin`, and
  `Tricore_0xa0102000.bin`:

    ```powershell
    python .\evaluate_arch_dataset.py ..\arch-detect-datasheet
    ```

- Analyze extracted HEX firmware in `test_firmware_100_hex_rerun` and write
  per-file timing and architecture results:

    ```powershell
    python .\analyze_hex_firmwares.py ..\test_firmware_100_hex_rerun
    ```

## Input rules

- Raw binary files such as `.bin`, `.img`, `.rom`, `.raw`, and `.dump` must
  provide `--base`.
- HEX-like files such as `.hex`, `.ihex`, `.mot`, `.s19`, and `.srec` keep
  their own addresses and do not need `--base`.

## Default architectures

By default, FirmArchDetect only tests common automotive ECU families to keep
runtime reasonable:

- `arm` / `thumb`
- `v850` / RH850
- `tricore`
- `ppc` big-endian
- `mips` big-endian and little-endian
- `sh`
- `rx`
- `rl78`
- `m68k`

Use `--all-arch` to scan every supported Rizin profile, or `--arch` to choose a
custom subset.

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
