from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

ARCH_PRIORITY = ["arm", "v850", "tricore", "ppc", "mips", "sh", "rx", "rl78"]


@dataclass
class CaseResult:
    file: str
    expected: str
    predicted: str
    confidence: float
    match: bool


def guess_expected(name: str) -> str:
    upper = name.upper()
    if upper.startswith("ARM32LE"):
        return "arm"
    if upper.startswith("RH850"):
        return "v850"
    if upper.startswith("TRICORE"):
        return "tricore"
    return "unknown"


def extract_base(path: Path) -> str | None:
    match = re.search(r"0x([0-9A-Fa-f]+)\.bin$", path.name)
    if match:
        return "0x" + match.group(1)
    return None


def run_detector(detector: Path, firmware: Path, base: str | None, timeout: int) -> dict:
    command = ["python", str(detector), str(firmware), "--arch", ",".join(ARCH_PRIORITY), "--timeout", str(timeout), "--json"]
    if base is not None:
        command.extend(["--base", base])
    completed = subprocess.run(command, capture_output=True, text=True, cwd=detector.parent)
    if completed.returncode != 0:
        raise RuntimeError(f"detector failed for {firmware.name}: {completed.stderr.strip() or completed.stdout.strip()}")
    return json.loads(completed.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark FirmArchDetect against a labeled dataset directory.")
    parser.add_argument("dataset", type=Path, help="Dataset directory")
    parser.add_argument("--detector", type=Path, default=Path(__file__).with_name("detect_arch_rizin.py"), help="Path to detect_arch_rizin.py")
    parser.add_argument("--timeout", type=int, default=20, help="Per-sample timeout for the detector")
    args = parser.parse_args()

    dataset = args.dataset.resolve()
    detector = args.detector.resolve()
    files = sorted(p for p in dataset.iterdir() if p.is_file() and not p.suffix.lower() == ".i64")
    results: list[CaseResult] = []
    for file in files:
        expected = guess_expected(file.name)
        if expected == "unknown":
            continue
        base = extract_base(file)
        report = run_detector(detector, file, base, args.timeout)
        winner = report.get("winner") or {}
        predicted = str(winner.get("name") or winner.get("arch") or "unknown").lower()
        match = predicted.startswith(expected) or winner.get("arch") == expected
        results.append(CaseResult(file.name, expected, predicted, float(winner.get("confidence") or 0.0), match))

    if not results:
        print("No labeled samples found.")
        return 1

    correct = sum(item.match for item in results)
    total = len(results)
    print("File	Expected	Predicted	Confidence	Match")
    for item in results:
        print(f"{item.file}	{item.expected}	{item.predicted}	{item.confidence:.4f}	{item.match}")
    print(f"Accuracy: {correct}/{total} = {correct / total:.1%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
