#!/usr/bin/env python3
"""Try multiple Rizin CPU profiles and rank raw firmware architecture confidence.

This is a heuristic detector, not a proof of architecture. Raw firmware often
contains data, padding, vectors, compressed blocks, and multiple images. The
score combines function count with structural checks that are harder for random
data to satisfy consistently.
"""
from __future__ import annotations

import click
import json
import logging
import math
import re
import shutil
import subprocess
from bisect import bisect_right
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

LOG = logging.getLogger("rizin_arch_detect")


@dataclass(frozen=True)
class ArchProfile:
    name: str
    arch: str
    bits: int
    cpu: str | None = None
    endian: str | None = None
    alignment: int = 2
    min_function_size: int = 4
    max_function_size: int = 0x4000
    min_bytes_per_instruction: float = 1.5
    max_bytes_per_instruction: float = 6.5
    description: str = ""


@dataclass
class ProbeResult:
    name: str
    arch: str
    bits: int
    cpu: str | None
    endian: str | None
    functions: int = 0
    basic_blocks: int = 0
    analyzed_bytes: int = 0
    valid_instructions: int = 0
    code_references: int = 0
    valid_code_references: int = 0
    function_xrefs: int = 0
    valid_function_xrefs: int = 0
    misaligned_functions: int = 0
    unreasonable_size_functions: int = 0
    suspicious_instruction_functions: int = 0
    alignment_score: float = 0.0
    size_score: float = 0.0
    instruction_score: float = 0.0
    jump_target_score: float = 0.0
    xref_score: float = 0.0
    structural_score: float = 0.0
    function_count_score: float = 0.0
    score: float = 0.0
    confidence: float = 0.0
    status: str = "error"
    error: str = ""


# Names are intentionally configurable because Rizin package builds can expose
# slightly different plugin aliases. Use --list-arch to inspect local support.
PROFILES = (
    ArchProfile("arm", "arm", 32, alignment=4, min_bytes_per_instruction=3.5, max_bytes_per_instruction=4.5, description="ARM 32-bit little-endian"),
    ArchProfile("arm", "arm", 16, alignment=2, min_bytes_per_instruction=1.7, max_bytes_per_instruction=4.5, description="ARM Thumb little-endian", cpu="thumb"),
    ArchProfile("arm", "arm", 64, alignment=4, min_bytes_per_instruction=4.0, max_bytes_per_instruction=8.0, description="ARM 64-bit"),
    ArchProfile("v850", "v850", 32, alignment=2, min_bytes_per_instruction=1.7, max_bytes_per_instruction=6.5, description="Renesas V850 / RH850"),
    ArchProfile("tricore", "tricore", 32, alignment=2, min_bytes_per_instruction=2.0, max_bytes_per_instruction=6.5, description="Infineon TriCore"),
    ArchProfile("ppc", "ppc", 32, endian="big", alignment=4, min_bytes_per_instruction=3.5, max_bytes_per_instruction=4.5, description="PowerPC 32-bit big-endian"),
    ArchProfile("ppc", "ppc", 32, endian="little", alignment=4, min_bytes_per_instruction=3.5, max_bytes_per_instruction=4.5, description="PowerPC 32-bit little-endian"),
    ArchProfile("mips", "mips", 32, endian="little", alignment=4, min_bytes_per_instruction=3.5, max_bytes_per_instruction=4.5, description="MIPS32 little-endian"),
    ArchProfile("mips", "mips", 32, endian="big", alignment=4, min_bytes_per_instruction=3.5, max_bytes_per_instruction=4.5, description="MIPS32 big-endian"),
    ArchProfile("sh", "sh", 32, alignment=2, min_bytes_per_instruction=1.8, max_bytes_per_instruction=4.5, description="Renesas SuperH SH-4"),
    ArchProfile("rx", "rx", 32, alignment=1, min_bytes_per_instruction=1.0, max_bytes_per_instruction=8.0, description="Renesas RX"),
    ArchProfile("rl78", "rl78", 32, alignment=1, min_bytes_per_instruction=1.0, max_bytes_per_instruction=6.0, description="Renesas RL78"),
    ArchProfile("m68k", "m68k", 32, alignment=2, min_bytes_per_instruction=1.8, max_bytes_per_instruction=8.0, description="Motorola 68000 family"),
    ArchProfile("avr", "avr", 8, alignment=1, min_bytes_per_instruction=1.0, max_bytes_per_instruction=6.0, description="Atmel AVR"),
    ArchProfile("8051", "8051", 8, alignment=1, min_bytes_per_instruction=1.0, max_bytes_per_instruction=8.0, description="Intel 8051 family"),
    ArchProfile("cr16", "cr16", 16, alignment=2, min_bytes_per_instruction=1.5, max_bytes_per_instruction=6.0, description="National/TI CR16"),
    ArchProfile("cris", "cris", 32, alignment=2, min_bytes_per_instruction=2.0, max_bytes_per_instruction=6.5, description="Axis CRIS"),
    ArchProfile("h8300", "h8300", 16, alignment=2, min_bytes_per_instruction=1.5, max_bytes_per_instruction=6.0, description="Renesas H8/300"),
    ArchProfile("m680x", "m680x", 8, alignment=1, min_bytes_per_instruction=1.0, max_bytes_per_instruction=6.0, description="Motorola 680x family"),
    ArchProfile("mcs96", "mcs96", 16, alignment=2, min_bytes_per_instruction=1.5, max_bytes_per_instruction=6.5, description="Intel MCS-96"),
    ArchProfile("msp430", "msp430", 16, alignment=2, min_bytes_per_instruction=1.0, max_bytes_per_instruction=6.0, description="TI MSP430"),
    ArchProfile("nios2", "nios2", 32, alignment=4, min_bytes_per_instruction=3.0, max_bytes_per_instruction=6.0, description="Altera Nios II"),
    ArchProfile("riscv", "riscv", 32, alignment=2, min_bytes_per_instruction=2.0, max_bytes_per_instruction=6.5, description="RISC-V 32-bit"),
    ArchProfile("sparc", "sparc", 32, alignment=4, min_bytes_per_instruction=3.5, max_bytes_per_instruction=4.5, description="SPARC 32-bit"),
    ArchProfile("v810", "v810", 32, alignment=2, min_bytes_per_instruction=1.7, max_bytes_per_instruction=6.5, description="NEC V810"),
    ArchProfile("xtensa", "xtensa", 32, alignment=4, min_bytes_per_instruction=2.0, max_bytes_per_instruction=8.0, description="Cadence Xtensa"),
    ArchProfile("xcore", "xcore", 32, alignment=4, min_bytes_per_instruction=2.0, max_bytes_per_instruction=6.0, description="XMOS XCore"),
    ArchProfile("z80", "z80", 8, alignment=1, min_bytes_per_instruction=1.0, max_bytes_per_instruction=6.0, description="Zilog Z80"),
)


CODE_REF_TYPES = {"CODE", "CALL", "JMP", "CJMP", "UCALL", "ICALL", "RCALL"}


HEX_LIKE_SUFFIXES = {".hex", ".ihex", ".mot", ".s19", ".srec"}
RAW_BINARY_SUFFIXES = {".bin", ".img", ".rom", ".raw", ".dump"}


def find_tool(name: str) -> str:
    tool = shutil.which(name)
    if not tool:
        raise SystemExit(f"Rizin executable not found: {name}. Install Rizin or pass its path with --rizin.")
    return tool


def run_command(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    LOG.debug("run: %s", " ".join(command))
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def extract_json_values(output: str) -> list[Any]:
    values: list[Any] = []
    index = 0
    while index < len(output):
        if output[index] not in "[{":
            index += 1
            continue
        start = index
        stack = [output[index]]
        in_string = False
        escape = False
        index += 1
        while index < len(output) and stack:
            char = output[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char in "[{":
                stack.append(char)
            elif char in "]}":
                opener = stack[-1]
                if (opener, char) in (("[", "]"), ("{", "}")):
                    stack.pop()
                else:
                    break
            index += 1
        if not stack:
            candidate = output[start:index]
            try:
                values.append(json.loads(candidate))
            except json.JSONDecodeError:
                pass
        else:
            index = start + 1
    return values


def parse_json_output(output: str) -> Any:
    values = extract_json_values(output)
    if values:
        return values[0]
    raise ValueError("Rizin did not return valid JSON")


def int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return 0
    return 0


def score_ratio(numerator: int, denominator: int, neutral: float = 0.5) -> float:
    if denominator <= 0:
        return neutral
    return max(0.0, min(1.0, numerator / denominator))


def is_hex_like_input(path: Path) -> bool:
    return path.suffix.lower() in HEX_LIKE_SUFFIXES


def input_requires_base(path: Path) -> bool:
    return not is_hex_like_input(path)


def parse_architectures_option(_ctx: click.Context, _param: click.Parameter, values: tuple[str, ...]) -> tuple[str, ...]:
    architectures: list[str] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                architectures.append(item)
    return tuple(architectures)


def profile_args(profile: ArchProfile) -> list[str]:
    args = ["-a", profile.arch, "-b", str(profile.bits)]
    if profile.cpu:
        args.extend(["-e", f"asm.cpu={profile.cpu}"])
    if profile.endian:
        args.extend(["-e", f"cfg.bigendian={'true' if profile.endian == 'big' else 'false'}"])
    return args


def ref_target(ref: dict[str, Any]) -> int:
    for key in ("to", "addr", "target", "jump", "ptr"):
        value = int_value(ref.get(key))
        if value:
            return value
    return 0


def ref_source(ref: dict[str, Any]) -> int:
    for key in ("from", "at", "addr", "source"):
        value = int_value(ref.get(key))
        if value:
            return value
    return 0


def ref_type(ref: dict[str, Any]) -> str:
    return str(ref.get("type", ref.get("ref", ""))).upper()


def collect_function_refs(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for function in functions:
        source = int_value(function.get("offset"))
        for field in ("callrefs", "coderefs", "datarefs"):
            value = function.get(field)
            if not isinstance(value, list):
                continue
            for item in value:
                if isinstance(item, dict):
                    ref = dict(item)
                    ref.setdefault("from", source)
                    refs.append(ref)
                else:
                    refs.append({"from": source, "to": int_value(item), "type": field})
    return refs


def normalize_refs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    refs = [item for item in value if isinstance(item, dict)]
    if not refs:
        return []
    if not any("from" in item or "to" in item for item in refs):
        return []
    return refs


def function_ranges(functions: list[dict[str, Any]]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for function in functions:
        start = int_value(function.get("offset"))
        size = int_value(function.get("size"))
        if start and size > 0:
            ranges.append((start, start + size))
    return sorted(ranges)


def contains_address(ranges: list[tuple[int, int]], starts: list[int], address: int) -> bool:
    if not ranges:
        return False
    index = bisect_right(starts, address) - 1
    if index < 0:
        return False
    start, end = ranges[index]
    return start <= address < end


def score_functions(profile: ArchProfile, result: ProbeResult, functions: list[dict[str, Any]], refs: list[dict[str, Any]]) -> None:
    if not functions:
        return

    ranges = function_ranges(functions)
    starts = [start for start, _ in ranges]
    seen_code_refs: set[tuple[int, int, str]] = set()
    seen_function_refs: set[tuple[int, int, str]] = set()

    for function in functions:
        offset = int_value(function.get("offset"))
        size = int_value(function.get("size"))
        instructions = int_value(function.get("ninstrs"))

        if profile.alignment > 1 and offset % profile.alignment:
            result.misaligned_functions += 1
        if size < profile.min_function_size or size > profile.max_function_size:
            result.unreasonable_size_functions += 1
        bytes_per_instruction = size / instructions if instructions > 0 else 0.0
        if instructions <= 0 or bytes_per_instruction < profile.min_bytes_per_instruction or bytes_per_instruction > profile.max_bytes_per_instruction:
            result.suspicious_instruction_functions += 1

    for ref in refs:
        source = ref_source(ref)
        target = ref_target(ref)
        if not source or not target:
            continue
        kind = ref_type(ref)
        normalized = (source, target, kind)
        is_code_ref = any(marker in kind for marker in CODE_REF_TYPES) or not kind
        if is_code_ref and normalized not in seen_code_refs:
            seen_code_refs.add(normalized)
            result.code_references += 1
            if contains_address(ranges, starts, target):
                result.valid_code_references += 1
        if normalized not in seen_function_refs and contains_address(ranges, starts, source):
            seen_function_refs.add(normalized)
            result.function_xrefs += 1
            if contains_address(ranges, starts, target):
                result.valid_function_xrefs += 1

    result.alignment_score = score_ratio(result.functions - result.misaligned_functions, result.functions, neutral=0.0)
    result.size_score = score_ratio(result.functions - result.unreasonable_size_functions, result.functions, neutral=0.0)
    result.instruction_score = score_ratio(result.functions - result.suspicious_instruction_functions, result.functions, neutral=0.0)
    result.jump_target_score = score_ratio(result.valid_code_references, result.code_references, neutral=0.5)
    result.xref_score = score_ratio(result.valid_function_xrefs, result.function_xrefs, neutral=0.5)
    result.structural_score = (
        result.alignment_score * 0.20
        + result.size_score * 0.20
        + result.instruction_score * 0.25
        + result.jump_target_score * 0.20
        + result.xref_score * 0.15
    )


def probe_profile(
    rizin: str,
    firmware: Path,
    profile: ArchProfile,
    base: int | None,
    timeout: int,
    analysis_command: str,
) -> ProbeResult:
    result = ProbeResult(profile.name, profile.arch, profile.bits, profile.cpu, profile.endian)
    command = [rizin, "-q", *profile_args(profile)]
    if base is not None:
        command.extend(["-m", f"{base:#x}", "-s", f"{base:#x}"])
    command.extend(["-c", f"{analysis_command};aflj;axlj", str(firmware)])
    LOG.info("Analyzing %-14s arch=%s bits=%s", profile.name, profile.arch, profile.bits)
    try:
        completed = run_command(command, timeout)
    except subprocess.TimeoutExpired:
        result.error = f"timeout after {timeout}s"
        return result
    if completed.returncode != 0:
        result.error = (completed.stderr or completed.stdout).strip()[-1000:]
        return result

    json_values = extract_json_values(completed.stdout)
    function_list = next(
        (
            value
            for value in json_values
            if isinstance(value, list)
            and (not value or isinstance(value[0], dict) and ("offset" in value[0] or "name" in value[0]) and "size" in value[0])
        ),
        None,
    )
    if function_list is None:
        try:
            function_list = parse_json_output(completed.stdout)
        except ValueError as exc:
            result.error = f"{exc}; stderr={completed.stderr.strip()[-500:]}"
            return result
    if not isinstance(function_list, list):
        result.error = "aflj returned non-list JSON"
        return result

    functions = [item for item in function_list if isinstance(item, dict)]
    xref_list = next((normalize_refs(value) for value in json_values if normalize_refs(value) and value is not function_list), [])
    refs = xref_list + collect_function_refs(functions)

    result.functions = len(functions)
    result.basic_blocks = sum(max(0, int_value(item.get("nbbs"))) for item in functions)
    result.analyzed_bytes = sum(max(0, int_value(item.get("size"))) for item in functions)
    result.valid_instructions = sum(max(0, int_value(item.get("ninstrs"))) for item in functions)
    score_functions(profile, result, functions, refs)
    result.status = "ok"
    if result.functions == 0:
        result.error = "analysis produced no functions"
    return result


def confidence(results: list[ProbeResult]) -> None:
    successful = [item for item in results if item.status == "ok" and item.functions > 0]
    if not successful:
        return
    max_log_functions = max(math.log1p(item.functions) for item in successful)
    for item in successful:
        item.function_count_score = math.log1p(item.functions) / max_log_functions if max_log_functions else 0.0
        item.score = (
            item.function_count_score * 0.20
            + item.alignment_score * 0.15
            + item.size_score * 0.15
            + item.instruction_score * 0.20
            + item.jump_target_score * 0.15
            + item.xref_score * 0.15
        )
        item.confidence = round(item.score, 4)


def result_dict(result: ProbeResult) -> dict[str, Any]:
    return asdict(result)


def percent(value: float) -> str:
    return f"{value:.1%}"


def print_ranked_table(results: list[ProbeResult], limit: int = 10) -> None:
    top_results = [item for item in results if item.status == "ok" and item.functions > 0][:limit]
    if not top_results:
        print("Architecture: unknown")
        print("No candidate produced analyzable functions.")
        return

    headers = ("Rank", "Arch", "CPU", "Bits", "Confidence", "Funcs", "Align", "Size", "Instr", "Jumps", "Xrefs")
    rows = [
        (
            str(index),
            item.arch,
            item.cpu or "-",
            str(item.bits),
            percent(item.confidence),
            str(item.functions),
            percent(item.alignment_score),
            percent(item.size_score),
            percent(item.instruction_score),
            percent(item.jump_target_score),
            percent(item.xref_score),
        )
        for index, item in enumerate(top_results, 1)
    ]
    widths = [max(len(headers[column]), *(len(row[column]) for row in rows)) for column in range(len(headers))]
    separator = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def format_row(row: tuple[str, ...]) -> str:
        return "| " + " | ".join(value.ljust(widths[index]) for index, value in enumerate(row)) + " |"

    print("Architecture ranking (top 10)")
    print(separator)
    print(format_row(headers))
    print(separator)
    for row in rows:
        print(format_row(row))
    print(separator)
    print(f"Selected architecture: {top_results[0].name}")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("firmware", required=False, type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", type=click.Path(dir_okay=False, path_type=Path), help="Save the complete JSON report")
@click.option("--rizin", default="rizin", show_default=True, help="Path to the Rizin executable")
@click.option("--base", callback=lambda _ctx, _param, value: int(value, 0) if value is not None else None, default=None, metavar="ADDR", help="Firmware mapping base address; required for raw binary inputs")
@click.option("--timeout", type=int, default=120, show_default=True, help="Maximum analysis time per architecture in seconds")
@click.option("--analysis", type=click.Choice(("aaa", "aaaa")), default="aaa", show_default=True, help="Rizin analysis depth; aaaa is slower but more aggressive")
@click.option("--arch", "architectures", multiple=True, callback=parse_architectures_option, help="Test only the selected profiles; repeatable or comma-separated.")
@click.option("--list-arch", is_flag=True, help="List candidate architecture profiles and exit")
@click.option("--json", "json_output", is_flag=True, help="Print the complete JSON report to the terminal")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
def main(firmware: Path | None, output: Path | None, rizin: str, base: int | None, timeout: int, analysis: str, architectures: tuple[str, ...], list_arch: bool, json_output: bool, verbose: bool) -> None:
    r"""Try multiple automotive MCU architectures with Rizin and rank them by structural analysis confidence."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format="%(levelname)s: %(message)s")
    if list_arch:
        for profile in PROFILES:
            click.echo(f"{profile.name:10} arch={profile.arch:8} bits={profile.bits:2} cpu={profile.cpu or '-':10} align={profile.alignment} {profile.description}")
        return
    if firmware is None:
        raise click.UsageError("A firmware file is required; use --list-arch to inspect candidate profiles.")
    if base is None and input_requires_base(firmware):
        raise click.BadParameter("Raw binary inputs require --base; HEX-like inputs may omit it.", param_hint="--base")
    base_address = base
    rizin_path = find_tool(rizin)
    selected = PROFILES
    if architectures:
        names = set(architectures)
        selected = tuple(profile for profile in PROFILES if profile.name in names)
        unknown = names - {profile.name for profile in PROFILES}
        if unknown:
            raise click.BadParameter(f"Unknown architecture profile: {', '.join(sorted(unknown))}", param_hint="--arch")
    if not selected:
        raise click.UsageError("No architecture profiles selected.")

    results = [probe_profile(rizin_path, firmware, profile, base_address, timeout, analysis) for profile in selected]
    confidence(results)
    ranked = sorted(
        results,
        key=lambda item: (item.confidence, item.score, item.structural_score, item.functions),
        reverse=True,
    )
    winner = next((item for item in ranked if item.status == "ok" and item.functions > 0), None)
    runner_up = next((item for item in ranked if item is not winner and item.status == "ok" and item.functions > 0), None)
    report = {
        "firmware": str(firmware.resolve()),
        "rizin": rizin_path,
        "base": base_address,
        "analysis": analysis,
        "method": "weighted_confidence: function_count, alignment, function_size, instruction_density, jump_targets, function_xrefs, all normalized to 0..1",
        "winner": result_dict(winner) if winner else None,
        "winner_confidence_margin": round(winner.confidence - runner_up.confidence, 4) if winner and runner_up else None,
        "results": [result_dict(item) for item in ranked],
    }
    if json_output:
        click.echo(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_ranked_table(ranked, limit=10)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        LOG.info("Report written to %s", output)



if __name__ == "__main__":
    main()
