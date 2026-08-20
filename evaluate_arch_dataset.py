#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import click


DEFAULT_DATASET = Path(__file__).resolve().parents[1] / "arch-detect-datasheet"
DEFAULT_DETECTOR = Path(__file__).with_name("detect_arch_rizin.py")
SUPPORTED_SUFFIXES = {".bin", ".hex", ".ihex", ".mot", ".s19", ".srec"}


def expected_architecture(path: Path) -> str | None:
    name = path.stem.lower()
    if name.startswith("arm32le") or name.startswith("arm"):
        return "arm"
    if name.startswith("rh850") or name.startswith("v850"):
        return "v850"
    if name.startswith("tricore"):
        return "tricore"
    if name.startswith("ppc") or name.startswith("powerpc"):
        return "ppc"
    if name.startswith("mips"):
        return "mips"
    if name.startswith("sh"):
        return "sh"
    if name.startswith("rx"):
        return "rx"
    if name.startswith("rl78"):
        return "rl78"
    if name.startswith("m68k"):
        return "m68k"
    return None


def base_from_filename(path: Path) -> str | None:
    match = re.search(r"_0x([0-9a-fA-F]+)(?:\.[^.]+)?$", path.name)
    if not match:
        return None
    return f"0x{int(match.group(1), 16):X}"


def parse_json_report(stdout: str) -> dict[str, Any]:
    start = stdout.find("{")
    if start < 0:
        return {}
    try:
        report, _ = json.JSONDecoder().raw_decode(stdout[start:])
        return report if isinstance(report, dict) else {}
    except json.JSONDecodeError:
        return {}


def load_json_report(path: Path, stdout: str) -> dict[str, Any]:
    if path.exists():
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            return report if isinstance(report, dict) else {}
        except json.JSONDecodeError:
            pass
    return parse_json_report(stdout)


def detector_command(
    detector: Path,
    firmware: Path,
    timeout: int,
    rizin: str,
    analysis: str,
    fast: bool,
    all_arch: bool,
    architectures: tuple[str, ...],
    report: Path,
) -> list[str]:
    command = [
        sys.executable,
        str(detector),
        str(firmware),
        "--timeout",
        str(timeout),
        "--rizin",
        rizin,
        "--analysis",
        analysis,
        "--json",
        "-o",
        str(report),
    ]
    base = base_from_filename(firmware)
    if base and firmware.suffix.lower() == ".bin":
        command.extend(["--base", base])
    if fast:
        command.append("--fast")
    if all_arch:
        command.append("--all-arch")
    for arch in architectures:
        command.extend(["--arch", arch])
    return command


def collect_samples(dataset: Path, recursive: bool, limit: int | None) -> list[Path]:
    iterator = dataset.rglob("*") if recursive else dataset.iterdir()
    samples = [
        path
        for path in iterator
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES and expected_architecture(path) is not None
    ]
    samples = sorted(samples, key=lambda item: str(item).lower())
    return samples[:limit] if limit else samples


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    lines = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows)
    return "\n".join(lines)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("dataset", required=False, type=click.Path(exists=True, file_okay=False, path_type=Path), default=DEFAULT_DATASET)
@click.option("-o", "--outdir", type=click.Path(file_okay=False, path_type=Path), help="Output directory for CSV, logs, and JSON reports")
@click.option("--detector", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=DEFAULT_DETECTOR, show_default=True, help="Path to detect_arch_rizin.py")
@click.option("--rizin", default="rizin", show_default=True, help="Path to the Rizin executable")
@click.option("--timeout", type=int, default=60, show_default=True, help="Maximum analysis time per architecture in seconds")
@click.option("--analysis", type=click.Choice(("aaa", "aaaa")), default="aaa", show_default=True, help="Rizin analysis depth")
@click.option("--fast", is_flag=True, help="Pass --fast to detect_arch_rizin.py")
@click.option("--all-arch", is_flag=True, help="Pass --all-arch to detect_arch_rizin.py")
@click.option("--arch", "architectures", multiple=True, help="Architecture profiles to pass through; repeatable or comma-separated")
@click.option("--recursive", is_flag=True, help="Search dataset recursively")
@click.option("--limit", type=int, help="Limit the number of samples, useful for smoke tests")
def main(
    dataset: Path,
    outdir: Path | None,
    detector: Path,
    rizin: str,
    timeout: int,
    analysis: str,
    fast: bool,
    all_arch: bool,
    architectures: tuple[str, ...],
    recursive: bool,
    limit: int | None,
) -> None:
    """Evaluate FirmArchDetect against labeled firmware files.

    Labels are inferred from file names such as ARM32LE_0x00020000.bin,
    RH850_0x00048000.bin, and Tricore_0xa0102000.bin.
    """
    dataset = dataset.resolve()
    outdir = (outdir or dataset / "arch_detect_eval_results").resolve()
    reports = outdir / "reports"
    reports.mkdir(parents=True, exist_ok=True)

    arch_args = tuple(item for value in architectures for item in value.split(",") if item)
    samples = collect_samples(dataset, recursive, limit)
    if not samples:
        raise click.ClickException(f"No labeled firmware samples found in {dataset}")

    rows: list[dict[str, str]] = []
    wall_start = time.perf_counter()
    for index, sample in enumerate(samples, 1):
        expected = expected_architecture(sample) or "unknown"
        report_path = reports / f"{sample.stem}.json"
        log_path = reports / f"{sample.stem}.log"
        command = detector_command(detector, sample, timeout, rizin, analysis, fast, all_arch, arch_args, report_path)
        start = time.perf_counter()
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", cwd=detector.parent)
        elapsed = time.perf_counter() - start
        log_path.write_text(completed.stdout, encoding="utf-8", errors="replace")
        report = load_json_report(report_path, completed.stdout)
        winner = report.get("winner") or {}
        predicted = str(winner.get("name") or winner.get("arch") or "unknown").lower()
        confidence = winner.get("confidence")
        match = predicted == expected or str(winner.get("arch") or "").lower() == expected
        row = {
            "index": str(index),
            "file": sample.name,
            "expected": expected,
            "predicted": predicted,
            "match": "yes" if match else "no",
            "confidence": f"{confidence:.4f}" if isinstance(confidence, int | float) else "",
            "elapsed_seconds": f"{elapsed:.3f}",
            "status": "ok" if completed.returncode == 0 else "fail",
            "returncode": str(completed.returncode),
            "base": base_from_filename(sample) or "",
            "report": str(report_path) if report_path.exists() else "",
            "log": str(log_path),
        }
        rows.append(row)
        click.echo(f"[{index}/{len(samples)}] {sample.name}: expected={expected} predicted={predicted} match={row['match']} time={row['elapsed_seconds']}s")

        with (outdir / "evaluation.csv").open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    wall_elapsed = time.perf_counter() - wall_start
    correct = sum(row["match"] == "yes" for row in rows)
    table_rows = [[row["file"], row["expected"], row["predicted"], row["match"], row["confidence"], row["elapsed_seconds"]] for row in rows]
    summary = [
        "FirmArchDetect dataset evaluation",
        "==================================",
        f"Dataset          : {dataset}",
        f"Samples          : {len(rows)}",
        f"Correct          : {correct}",
        f"Accuracy         : {correct / len(rows):.1%}",
        f"Wall time        : {wall_elapsed:.3f}s ({wall_elapsed / 60:.3f}min)",
        f"Timeout          : {timeout}s per architecture",
        f"Fast mode        : {'yes' if fast else 'no'}",
        f"CSV              : {outdir / 'evaluation.csv'}",
        "",
        format_table(["File", "Expected", "Predicted", "Match", "Conf", "Seconds"], table_rows),
    ]
    (outdir / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    click.echo("\n".join(summary))


if __name__ == "__main__":
    main()
