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
import tempfile
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
    invalid_range_functions: int = 0
    sampled_instructions: int = 0
    invalid_instructions: int = 0
    alignment_score: float = 0.0
    size_score: float = 0.0
    instruction_score: float = 0.0
    jump_target_score: float = 0.0
    xref_score: float = 0.0
    structural_score: float = 0.0
    entry_score: float = 0.0
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


# The normal scan path is ECU-focused for speed. PROFILES remains the full
# supported list for --list-arch, --all-arch, and explicit --arch scans.
DEFAULT_PROFILE_KEYS = {
    ("arm", 16, "thumb", None),
    ("arm", 32, None, None),
    ("v850", 32, None, None),
    ("tricore", 32, None, None),
    ("ppc", 32, None, "big"),
    ("mips", 32, None, "big"),
    ("sh", 32, None, None),
    ("rx", 32, None, None),
    ("rl78", 32, None, None),
}

DEFAULT_PROFILES = tuple(
    profile
    for profile in PROFILES
    if (profile.name, profile.bits, profile.cpu, profile.endian) in DEFAULT_PROFILE_KEYS
)

FAST_DEFAULT_PROFILE_KEYS = {
    ("arm", 16, "thumb", None),
    ("arm", 32, None, None),
    ("v850", 32, None, None),
    ("tricore", 32, None, None),
    ("sh", 32, None, None),
    ("rx", 32, None, None),
    ("rl78", 32, None, None),
}

FAST_DEFAULT_PROFILES = tuple(
    profile
    for profile in DEFAULT_PROFILES
    if (profile.name, profile.bits, profile.cpu, profile.endian) in FAST_DEFAULT_PROFILE_KEYS
)


CODE_REF_TYPES = {"CODE", "CALL", "JMP", "CJMP", "UCALL", "ICALL", "RCALL"}


HEX_LIKE_SUFFIXES = {".hex", ".ihex", ".mot", ".s19", ".srec"}
RAW_BINARY_SUFFIXES = {".bin", ".img", ".rom", ".raw", ".dump"}


def parse_srec_line(line: str) -> tuple[int, bytes] | None:
    if len(line) < 4 or not line.startswith("S") or line[1] not in "123":
        return None
    address_bytes = {"1": 2, "2": 3, "3": 4}[line[1]]
    count = int(line[2:4], 16)
    payload = bytes.fromhex(line[4:4 + count * 2])
    if len(payload) != count or len(payload) < address_bytes + 1:
        return None
    address = int.from_bytes(payload[:address_bytes], "big")
    return address, payload[address_bytes:-1]


def parse_ihex_line(line: str, extended_linear: int, extended_segment: int) -> tuple[int, bytes, int, int] | None:
    if not line.startswith(":") or len(line) < 11:
        return None
    raw = bytes.fromhex(line[1:])
    count = raw[0]
    offset = int.from_bytes(raw[1:3], "big")
    record_type = raw[3]
    payload = raw[4:4 + count]
    if record_type == 0x00:
        return (extended_linear << 16) + (extended_segment << 4) + offset, payload, extended_linear, extended_segment
    if record_type == 0x02 and len(payload) == 2:
        return 0, b"", extended_linear, int.from_bytes(payload, "big")
    if record_type == 0x04 and len(payload) == 2:
        return 0, b"", int.from_bytes(payload, "big"), extended_segment
    return None


def decode_hex_like_firmware(path: Path) -> tuple[Path, int] | None:
    records: list[tuple[int, bytes]] = []
    extended_linear = 0
    extended_segment = 0
    try:
        lines = path.read_text(encoding="ascii", errors="ignore").splitlines()
    except OSError:
        return None
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            if line.startswith("S"):
                record = parse_srec_line(line)
                if record is not None:
                    records.append(record)
            elif line.startswith(":"):
                parsed = parse_ihex_line(line, extended_linear, extended_segment)
                if parsed is None:
                    continue
                address, payload, extended_linear, extended_segment = parsed
                if payload:
                    records.append((address, payload))
        except ValueError:
            continue
    if not records:
        return None
    minimum = min(address for address, _payload in records)
    maximum = max(address + len(payload) for address, payload in records)
    if maximum <= minimum:
        return None
    image = bytearray(b"\xff" * (maximum - minimum))
    for address, payload in records:
        offset = address - minimum
        image[offset:offset + len(payload)] = payload
    temporary = tempfile.NamedTemporaryFile(prefix=f"{path.stem}_", suffix=".bin", delete=False)
    with temporary:
        temporary.write(image)
    return Path(temporary.name), minimum

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


def architecture_priority(name: str) -> int:
    return {
        "arm": 0,
        "v850": 1,
        "tricore": 2,
        "ppc": 3,
        "mips": 4,
        "sh": 5,
        "rx": 6,
        "rl78": 7,
        "m68k": 8,
        "avr": 9,
        "8051": 10,
        "cr16": 11,
        "cris": 12,
        "h8300": 13,
        "m680x": 14,
        "mcs96": 15,
        "msp430": 16,
        "nios2": 17,
        "riscv": 18,
        "sparc": 19,
        "v810": 20,
        "xtensa": 21,
        "xcore": 22,
        "z80": 23,
    }.get(name, 99)


def profile_priority(profile: ArchProfile) -> tuple[int, int, int]:
    return (
        architecture_priority(profile.name),
        0 if profile.arch == "arm" and profile.bits == 16 and profile.cpu == "thumb" else 1,
        profile.bits,
    )


def profile_args(profile: ArchProfile) -> list[str]:
    args = ["-a", profile.arch, "-b", str(profile.bits), "-e", "io.va=true"]
    if profile.cpu:
        args.extend(["-e", f"asm.cpu={profile.cpu}"])
    if profile.endian:
        args.extend(["-E", profile.endian])
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


def instruction_quality(
    profile: ArchProfile,
    rizin: str,
    firmware: Path,
    base: int | None,
    functions: list[dict[str, Any]],
    timeout: int,
    fast: bool = False,
) -> tuple[int, int]:
    if not functions:
        return 0, 0

    command = [rizin, "-q"]
    if input_requires_base(firmware):
        command.append("-n")
    command.extend(profile_args(profile))
    if base is not None:
        command.extend(["-m", f"{base:#x}"])

    sample_limit = 8 if fast else 16
    sample_timeout = 8 if fast else min(timeout, 20)
    sample_functions = sorted(functions, key=lambda item: int_value(item.get("size")), reverse=True)[:sample_limit]
    samples = [int_value(item.get("offset")) for item in sample_functions if int_value(item.get("offset"))]
    if not samples:
        return 0, 0
    commands = ";".join(f"pdj 64 @ 0x{address:x}" for address in samples)
    try:
        completed = run_command([*command, "-c", f"{commands};q", str(firmware)], sample_timeout)
    except subprocess.TimeoutExpired:
        return 0, 0
    if completed.returncode != 0:
        return 0, 0

    total = 0
    invalid = 0
    for value in extract_json_values(completed.stdout):
        if not isinstance(value, list) or not value or not isinstance(value[0], dict) or "opcode" not in value[0]:
            continue
        for instruction in value:
            if not isinstance(instruction, dict):
                continue
            total += 1
            if instruction.get("opcode") == "invalid" or instruction.get("type") in {"unk", "ill"}:
                invalid += 1
    return total, invalid

def score_functions(profile: ArchProfile, result: ProbeResult, functions: list[dict[str, Any]], refs: list[dict[str, Any]], image_start: int | None = None, image_end: int | None = None) -> None:
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
        if image_start is not None and image_end is not None and (offset < image_start or size <= 0 or offset + size > image_end):
            result.invalid_range_functions += 1
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
    result.size_score = score_ratio(result.functions - result.unreasonable_size_functions - result.invalid_range_functions, result.functions, neutral=0.0)
    result.instruction_score = score_ratio(result.functions - result.suspicious_instruction_functions, result.functions, neutral=0.0)
    if result.sampled_instructions:
        result.instruction_score = score_ratio(result.sampled_instructions - result.invalid_instructions, result.sampled_instructions, neutral=0.0)
    result.jump_target_score = score_ratio(result.valid_code_references, result.code_references, neutral=0.5)
    result.xref_score = score_ratio(result.valid_function_xrefs, result.function_xrefs, neutral=0.5)
    result.structural_score = (
        result.alignment_score * 0.20
        + result.size_score * 0.20
        + result.instruction_score * 0.30
        + result.jump_target_score * 0.20
        + result.xref_score * 0.15
    )


def firmware_bytes(path: Path, limit: int = 0x1000) -> bytes:
    try:
        return path.read_bytes()[:limit]
    except OSError:
        return b""


def words_le(data: bytes, count: int) -> list[int]:
    return [int.from_bytes(data[index:index + 4], "little") for index in range(0, min(len(data), count * 4), 4) if index + 4 <= len(data)]


def score_arm_entry(data: bytes, base: int | None, image_size: int) -> float:
    if base is None or len(data) < 8:
        return 0.0
    words = words_le(data, 16)
    if len(words) < 2:
        return 0.0
    stack = words[0]
    reset = words[1]
    in_flash_vectors = sum(1 for word in words[1:] if word & 1 and base <= (word & ~1) < base + image_size)
    score = 0.0
    if 0x20000000 <= stack <= 0x40000000 and stack % 4 == 0:
        score += 0.35
    if reset & 1 and base <= (reset & ~1) < base + image_size:
        score += 0.45
    if words[0] == 0x5AA55AA5:
        header_entries = sum(1 for word in words[1:] if base <= word < base + image_size and word % 2 == 0)
        if header_entries >= 2:
            score += 0.75
    score += min(0.20, in_flash_vectors * 0.04)
    return min(1.0, score)


def score_v850_entry(data: bytes, base: int | None, image_size: int) -> float:
    if base is None or len(data) < 4:
        return 0.0
    score = 0.0
    if data[:2] == b"\x87\x07":
        score += 0.45
    halfwords = [int.from_bytes(data[index:index + 2], "little") for index in range(0, min(len(data), 0x80), 2) if index + 2 <= len(data)]
    repeated_vectors = sum(1 for value in halfwords if value in {0x4000, 0x0000, 0x0800} or value & 0x8000)
    if repeated_vectors >= 8:
        score += 0.25
    words = words_le(data, 16)
    in_range_words = sum(1 for word in words if base <= word < base + image_size and word % 2 == 0)
    if not score and in_range_words >= 3:
        score += min(0.30, in_range_words * 0.04)
    elif score:
        score += min(0.30, in_range_words * 0.06)
    return min(1.0, score)


def score_tricore_entry(data: bytes, base: int | None, image_size: int) -> float:
    if len(data) < 8:
        return 0.0
    score = 0.0
    if data.startswith(b"\x4d\xc0") or data.startswith(b"\x00\xff\xff\xff"):
        score += 0.45
    startup_markers = (b"\x4d\xc0", b"\xee\x06", b"\x02\xf8", b"\x5e\x16", b"\x00\x90")
    marker_hits = sum(1 for marker in startup_markers if marker in data[:0x400])
    score += min(0.35, marker_hits * 0.07)
    if base is not None and (base & 0xF0000000) in {0x80000000, 0xA0000000}:
        score += 0.20
    return min(1.0, score)


def entry_evidence_score(profile: ArchProfile, firmware: Path, base: int | None) -> float:
    data = firmware_bytes(firmware)
    image_size = firmware.stat().st_size
    if profile.arch == "arm" and profile.bits == 16:
        return score_arm_entry(data, base, image_size)
    if profile.arch == "v850":
        return score_v850_entry(data, base, image_size)
    if profile.arch == "tricore":
        return score_tricore_entry(data, base, image_size)
    if profile.name in {"rl78", "rx", "sh"}:
        return 0.05
    return 0.0

def read_reset_vector_from_binary(path: Path) -> int | None:
    try:
        first_bytes = path.read_bytes()[:8]
    except OSError:
        return None
    if len(first_bytes) < 8:
        return None
    reset_vector = int.from_bytes(first_bytes[4:8], "little")
    if reset_vector & 1 == 0:
        return None
    return reset_vector & ~1


def analysis_seed_commands(profile: ArchProfile, firmware: Path, base: int | None) -> list[str]:
    commands: list[str] = []
    if profile.arch == "arm" and profile.bits == 16 and profile.cpu == "thumb" and base is not None:
        reset_addr = read_reset_vector_from_binary(firmware)
        if reset_addr is not None and reset_addr >= base:
            commands.append(f"s 0x{reset_addr:x}; af reset")
    return commands


def arm_vector_table_candidates(path: Path, base: int | None) -> list[int]:
    if base is None:
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    if len(data) < 0x20:
        return []
    words = [int.from_bytes(data[index:index + 4], "little") for index in range(0, min(len(data), 0x40), 4) if index + 4 <= len(data)]
    if len(words) < 2:
        return []
    reset_vector = words[1]
    if reset_vector & 1 == 0 or reset_vector < base:
        return []
    reset_addr = reset_vector & ~1
    candidates = [reset_addr]
    for word in words[2:8]:
        if word & 1 and word >= base:
            entry = word & ~1
            if entry not in candidates:
                candidates.append(entry)
    return candidates


def probe_profile(
    rizin: str,
    firmware: Path,
    profile: ArchProfile,
    base: int | None,
    timeout: int,
    analysis_command: str,
    fast: bool = False,
) -> ProbeResult:
    result = ProbeResult(profile.name, profile.arch, profile.bits, profile.cpu, profile.endian)
    result.entry_score = entry_evidence_score(profile, firmware, base)
    candidate_seeks: list[int | None] = [None]
    arm_vector_mode = False
    if profile.arch == "arm" and profile.bits == 16 and profile.cpu == "thumb":
        vector_candidates = arm_vector_table_candidates(firmware, base)
        if vector_candidates:
            candidate_seeks = [None]
            arm_vector_mode = True

    best_completed: subprocess.CompletedProcess[str] | None = None
    best_json_values: list[Any] = []
    best_functions: list[dict[str, Any]] = []
    best_refs: list[dict[str, Any]] = []
    best_score = -1.0

    for seek in candidate_seeks:
        command = [rizin, "-q"]
        if input_requires_base(firmware):
            command.append("-n")
        command.extend(profile_args(profile))
        if base is not None:
            command.extend(["-m", f"{base:#x}"])
        if arm_vector_mode:
            seed_commands = [f"s 0x{address:x}; af vector_{index}" for index, address in enumerate(vector_candidates)]
            analysis_prefix = ";".join(seed_commands)
        else:
            seed_commands = analysis_seed_commands(profile, firmware, base)
            if seek is not None:
                seed_commands = [*seed_commands, f"s 0x{seek:x}", "af entry"]
            analysis_prefix = ";".join([*seed_commands, analysis_command]) if seed_commands else analysis_command
        command.extend(["-c", f"{analysis_prefix};aflj;axlj", str(firmware)])
        LOG.info("Analyzing %-14s arch=%s bits=%s", profile.name, profile.arch, profile.bits)
        try:
            completed = run_command(command, timeout)
        except subprocess.TimeoutExpired:
            continue
        if completed.returncode != 0:
            continue

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
            except ValueError:
                continue
        if not isinstance(function_list, list):
            continue
        functions = [item for item in function_list if isinstance(item, dict)]
        xref_list = next((normalize_refs(value) for value in json_values if normalize_refs(value) and value is not function_list), [])
        refs = xref_list + collect_function_refs(functions)
        score = len(functions)
        if score > best_score:
            best_score = float(score)
            best_completed = completed
            best_json_values = json_values
            best_functions = functions
            best_refs = refs

    if best_completed is None:
        if result.entry_score >= 0.6:
            result.status = "ok"
            result.error = "entry evidence only"
            return result
        result.error = f"timeout after {timeout}s" if candidate_seeks != [None] else "analysis failed"
        return result

    json_values = best_json_values
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
            function_list = parse_json_output(best_completed.stdout)
        except ValueError as exc:
            result.error = f"{exc}; stderr={best_completed.stderr.strip()[-500:]}"
            return result
    if not isinstance(function_list, list):
        result.error = "aflj returned non-list JSON"
        return result

    functions = best_functions or [item for item in function_list if isinstance(item, dict)]
    refs = best_refs or next((normalize_refs(value) for value in json_values if normalize_refs(value) and value is not function_list), []) + collect_function_refs(functions)

    result.functions = len(functions)
    result.basic_blocks = sum(max(0, int_value(item.get("nbbs"))) for item in functions)
    result.analyzed_bytes = sum(max(0, int_value(item.get("size"))) for item in functions)
    result.valid_instructions = sum(max(0, int_value(item.get("ninstrs"))) for item in functions)
    result.sampled_instructions, result.invalid_instructions = instruction_quality(profile, rizin, firmware, base, functions, timeout, fast=fast)
    if result.sampled_instructions:
        result.valid_instructions = result.sampled_instructions - result.invalid_instructions
    image_start = base if input_requires_base(firmware) else None
    image_end = image_start + firmware.stat().st_size if image_start is not None else None
    score_functions(profile, result, functions, refs, image_start, image_end)
    result.status = "ok"
    if result.functions == 0:
        result.error = "analysis produced no functions"
    return result


def provisional_score(result: ProbeResult) -> float:
    if result.status != "ok":
        return -1.0
    return (
        math.log1p(max(1, result.functions)) * 1.15
        + result.structural_score * 1.8
        + result.entry_score * 0.9
        + result.jump_target_score * 0.35
        + result.xref_score * 0.35
    )


def should_stop_early(results: list[ProbeResult], evaluated: int, total: int, fast: bool) -> bool:
    if not fast or evaluated < 4 or evaluated >= total:
        return False
    successful = [item for item in results if item.status == "ok" and (item.functions > 0 or item.entry_score >= 0.6)]
    if len(successful) < 2:
        return False
    ranked = sorted(successful, key=provisional_score, reverse=True)
    best = ranked[0]
    runner_up = ranked[1]
    best_score = provisional_score(best)
    runner_up_score = provisional_score(runner_up)
    if best.functions < 8 and best.entry_score < 0.7:
        return False
    return best_score >= 3.0 and (best_score - runner_up_score) >= 0.9


def confidence(results: list[ProbeResult]) -> None:
    successful = [item for item in results if item.status == "ok" and (item.functions > 0 or item.entry_score >= 0.6)]
    if not successful:
        return
    max_log_functions = max(math.log1p(max(1, item.functions)) for item in successful)
    for item in successful:
        item.function_count_score = math.log1p(max(1, item.functions)) / max_log_functions if max_log_functions else 0.0
        if item.functions == 0 and item.entry_score >= 0.6:
            item.alignment_score = max(item.alignment_score, item.entry_score)
            item.size_score = max(item.size_score, item.entry_score)
            item.instruction_score = max(item.instruction_score, item.entry_score)
            item.jump_target_score = max(item.jump_target_score, 0.5)
            item.xref_score = max(item.xref_score, 0.5)
        item.score = (
            item.function_count_score * 0.12
            + item.alignment_score * 0.10
            + item.size_score * 0.15
            + item.instruction_score * 0.23
            + item.jump_target_score * 0.12
            + item.xref_score * 0.10
            + item.entry_score * 0.18
        )
        if item.entry_score >= 0.65 and item.name in {"arm", "v850", "tricore"}:
            item.score = max(item.score, 0.78 + item.entry_score * 0.10)
        item.confidence = round(item.score, 4)


def result_dict(result: ProbeResult) -> dict[str, Any]:
    return asdict(result)


def percent(value: float) -> str:
    return f"{value:.1%}"


def print_ranked_table(results: list[ProbeResult], limit: int = 10) -> None:
    top_results = [item for item in results if item.status == "ok" and (item.functions > 0 or item.entry_score >= 0.6)][:limit]
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
@click.option("--fast", is_flag=True, help="Use a smaller ECU-first candidate set, shorter instruction sampling, and early exit when the leader is clear")
@click.option("--arch", "architectures", multiple=True, callback=parse_architectures_option, help="Test only the selected profiles; repeatable or comma-separated.")
@click.option("--all-arch", is_flag=True, help="Test every supported profile instead of the default ECU-focused set")
@click.option("--list-arch", is_flag=True, help="List candidate architecture profiles and exit")
@click.option("--json", "json_output", is_flag=True, help="Print the complete JSON report to the terminal")
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")
def main(firmware: Path | None, output: Path | None, rizin: str, base: int | None, timeout: int, analysis: str, fast: bool, architectures: tuple[str, ...], all_arch: bool, list_arch: bool, json_output: bool, verbose: bool) -> None:
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
    analysis_firmware = firmware
    temporary_firmware: Path | None = None
    if is_hex_like_input(firmware):
        decoded = decode_hex_like_firmware(firmware)
        if decoded is not None:
            temporary_firmware, decoded_base = decoded
            analysis_firmware = temporary_firmware
            if base_address is None:
                base_address = decoded_base
    rizin_path = find_tool(rizin)
    selected = PROFILES if all_arch else (FAST_DEFAULT_PROFILES if fast else DEFAULT_PROFILES)
    if architectures:
        names = set(architectures)
        selected = tuple(profile for profile in PROFILES if profile.name in names)
        unknown = names - {profile.name for profile in PROFILES}
        if unknown:
            raise click.BadParameter(f"Unknown architecture profile: {', '.join(sorted(unknown))}", param_hint="--arch")
    if not selected:
        raise click.UsageError("No architecture profiles selected.")

    ordered = sorted(selected, key=profile_priority)
    results: list[ProbeResult] = []
    early_exit = False
    for index, profile in enumerate(ordered, 1):
        result = probe_profile(rizin_path, analysis_firmware, profile, base_address, timeout, analysis, fast=fast)
        results.append(result)
        if should_stop_early(results, index, len(ordered), fast):
            early_exit = True
            break
    confidence(results)
    ranked = sorted(
        results,
        key=lambda item: (item.confidence, item.score, item.structural_score, item.functions, -architecture_priority(item.name)),
        reverse=True,
    )
    winner = next((item for item in ranked if item.status == "ok" and (item.functions > 0 or item.entry_score >= 0.6)), None)
    runner_up = next((item for item in ranked if item is not winner and item.status == "ok" and (item.functions > 0 or item.entry_score >= 0.6)), None)
    report = {
        "firmware": str(firmware.resolve()),
        "analysis_firmware": str(analysis_firmware.resolve()),
        "rizin": rizin_path,
        "base": base_address,
        "analysis": analysis,
        "fast": fast,
        "candidate_profiles": len(ordered),
        "evaluated_profiles": len(results),
        "early_exit": early_exit,
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
    if temporary_firmware is not None:
        try:
            temporary_firmware.unlink()
        except OSError:
            pass



if __name__ == "__main__":
    main()
