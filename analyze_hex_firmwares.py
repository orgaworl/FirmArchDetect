#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click


DEFAULT_INPUT = Path(__file__).resolve().parents[1] / "test_firmware_100_hex_rerun"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "arch_detect_hex_analysis"
DEFAULT_DETECTOR = Path(__file__).with_name("detect_arch_rizin.py")


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


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))
    lines = ["  ".join(header.ljust(widths[index]) for index, header in enumerate(headers))]
    lines.append("  ".join("-" * width for width in widths))
    lines.extend("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)) for row in rows)
    return "\n".join(lines)


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
    if fast:
        command.append("--fast")
    if all_arch:
        command.append("--all-arch")
    for arch in architectures:
        command.extend(["--arch", arch])
    return command


def analyze_one(
    index: int,
    total: int,
    firmware: Path,
    detector: Path,
    reports: Path,
    timeout: int,
    rizin: str,
    analysis: str,
    fast: bool,
    all_arch: bool,
    architectures: tuple[str, ...],
) -> dict[str, str]:
    sample = firmware.parent.name if firmware.parent.name else firmware.stem
    output_stem = f"{index:03d}_{sample}_{firmware.stem}"
    report_path = reports / f"{output_stem}.json"
    log_path = reports / f"{output_stem}.log"
    command = detector_command(detector, firmware, timeout, rizin, analysis, fast, all_arch, architectures, report_path)
    start = time.perf_counter()
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", cwd=detector.parent)
    elapsed = time.perf_counter() - start
    log_path.write_text(completed.stdout, encoding="utf-8", errors="replace")
    report = load_json_report(report_path, completed.stdout)
    winner = report.get("winner") or {}
    predicted = str(winner.get("name") or winner.get("arch") or "unknown").lower()
    confidence = winner.get("confidence")
    margin = report.get("winner_confidence_margin")
    return {
        "index": str(index),
        "total": str(total),
        "sample": sample,
        "file": str(firmware),
        "size_bytes": str(firmware.stat().st_size),
        "predicted": predicted,
        "confidence": f"{confidence:.4f}" if isinstance(confidence, int | float) else "",
        "confidence_margin": f"{margin:.4f}" if isinstance(margin, int | float) else "",
        "elapsed_seconds": f"{elapsed:.3f}",
        "status": "ok" if completed.returncode == 0 else "fail",
        "returncode": str(completed.returncode),
        "candidate_profiles": str(report.get("candidate_profiles", "")),
        "evaluated_profiles": str(report.get("evaluated_profiles", "")),
        "early_exit": str(report.get("early_exit", "")),
        "report": str(report_path) if report_path.exists() else "",
        "log": str(log_path),
    }


def write_results_csv(path: Path, rows: list[dict[str, str]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("input_dir", required=False, type=click.Path(exists=True, file_okay=False, path_type=Path), default=DEFAULT_INPUT)
@click.option("-o", "--outdir", type=click.Path(file_okay=False, path_type=Path), default=DEFAULT_OUTPUT, show_default=True, help="Output directory for CSV, logs, and JSON reports")
@click.option("--detector", type=click.Path(exists=True, dir_okay=False, path_type=Path), default=DEFAULT_DETECTOR, show_default=True, help="Path to detect_arch_rizin.py")
@click.option("--rizin", default="rizin", show_default=True, help="Path to the Rizin executable")
@click.option("--timeout", type=int, default=60, show_default=True, help="Maximum analysis time per architecture in seconds")
@click.option("--analysis", type=click.Choice(("aaa", "aaaa")), default="aaa", show_default=True, help="Rizin analysis depth")
@click.option("--fast", is_flag=True, help="Pass --fast to detect_arch_rizin.py")
@click.option("--all-arch", is_flag=True, help="Pass --all-arch to detect_arch_rizin.py")
@click.option("--arch", "architectures", multiple=True, help="Architecture profiles to pass through; repeatable or comma-separated")
@click.option("--workers", type=int, default=min(4, os.cpu_count() or 4), show_default=True, help="Parallel detector processes")
@click.option("--limit", type=int, help="Limit the number of HEX files, useful for smoke tests")
def main(
    input_dir: Path,
    outdir: Path,
    detector: Path,
    rizin: str,
    timeout: int,
    analysis: str,
    fast: bool,
    all_arch: bool,
    architectures: tuple[str, ...],
    workers: int,
    limit: int | None,
) -> None:
    """Run FirmArchDetect against extracted HEX firmware files."""
    input_dir = input_dir.resolve()
    outdir = outdir.resolve()
    reports = outdir / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    arch_args = tuple(item for value in architectures for item in value.split(",") if item)
    firmware_files = sorted(input_dir.rglob("*.hex"), key=lambda item: str(item).lower())
    if limit:
        firmware_files = firmware_files[:limit]
    if not firmware_files:
        raise click.ClickException(f"No .hex files found in {input_dir}")

    workers = max(1, workers)
    rows: list[dict[str, str]] = []
    results_csv = outdir / "arch_detect_results.csv"
    wall_start = time.perf_counter()
    click.echo(f"Input HEX files: {len(firmware_files)}")
    click.echo(f"Workers        : {workers}")
    click.echo(f"Timeout        : {timeout}s per architecture")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                analyze_one,
                index,
                len(firmware_files),
                firmware,
                detector,
                reports,
                timeout,
                rizin,
                analysis,
                fast,
                all_arch,
                arch_args,
            ): firmware
            for index, firmware in enumerate(firmware_files, 1)
        }
        for finished, future in enumerate(as_completed(futures), 1):
            row = future.result()
            rows.append(row)
            rows.sort(key=lambda item: int(item["index"]))
            write_results_csv(results_csv, rows)
            click.echo(f"[{finished}/{len(firmware_files)}] {row['sample']}: arch={row['predicted']} time={row['elapsed_seconds']}s status={row['status']}")

    wall_elapsed = time.perf_counter() - wall_start
    rows.sort(key=lambda item: int(item["index"]))
    write_results_csv(results_csv, rows)
    ok = sum(row["status"] == "ok" for row in rows)
    total_sample_time = sum(float(row["elapsed_seconds"]) for row in rows)
    slowest = sorted(rows, key=lambda item: float(item["elapsed_seconds"]), reverse=True)[:10]
    by_arch: dict[str, int] = {}
    for row in rows:
        by_arch[row["predicted"]] = by_arch.get(row["predicted"], 0) + 1
    arch_rows = [[arch, str(count)] for arch, count in sorted(by_arch.items(), key=lambda item: (-item[1], item[0]))]
    slow_rows = [[row["sample"], row["predicted"], row["confidence"], row["elapsed_seconds"], row["status"]] for row in slowest]
    summary = [
        "FirmArchDetect HEX analysis summary",
        "===================================",
        f"Input directory  : {input_dir}",
        f"HEX files        : {len(rows)}",
        f"OK               : {ok}",
        f"Fail             : {len(rows) - ok}",
        f"Wall time        : {wall_elapsed:.3f}s ({wall_elapsed / 60:.3f}min)",
        f"Sum sample time  : {total_sample_time:.3f}s ({total_sample_time / 60:.3f}min)",
        f"Timeout          : {timeout}s per architecture",
        f"Workers          : {workers}",
        f"Fast mode        : {'yes' if fast else 'no'}",
        f"CSV              : {results_csv}",
        "",
        "Architecture Counts",
        "-------------------",
        format_table(["Arch", "Count"], arch_rows),
        "",
        "Slowest Samples",
        "---------------",
        format_table(["Sample", "Arch", "Conf", "Seconds", "Status"], slow_rows),
    ]
    (outdir / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    click.echo("\n".join(summary))


if __name__ == "__main__":
    main()
