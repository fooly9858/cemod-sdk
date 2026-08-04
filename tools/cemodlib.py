#!/usr/bin/env python3
"""Independent .cemod/WPS format validation shared by SDK commands.

This module implements public container and binary-format contracts only.  It
does not contain or execute WiiUPluginLoaderBackend code.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass
from typing import Any


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXPANDED_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_TRUSTED_ELF_BYTES = 10 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_SECTIONS = 512
ALLOWED_ENTRIES = {
    "manifest.json", "mod.elf", "plugin.wps",
    "public_key.ed25519", "signature.ed25519",
}
SUPPORTED_WUPS_VERSIONS = {"0.7.1", "0.8.1", "0.8.2", "0.9.0", "0.9.1"}
SUPPORTED_RELOCATIONS = {0, 1, 4, 5, 6, 10, 11, 68, 78, 251, 252, 253}
PROCESS_TARGETS = {0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 16}
PROCESS_TARGET_NAMES = {
    0xFF: "all", 1: "root_rpx", 2: "wii_u_menu", 3: "tvii",
    4: "e_manual", 5: "home_menu", 6: "error_display", 7: "mini_miiverse",
    8: "browser", 9: "miiverse", 10: "eshop", 12: "download_manager",
    15: "game", 16: "game_and_menu",
}
HOOK_NAMES = [
    "INIT_WUT_MALLOC", "FINI_WUT_MALLOC", "INIT_WUT_NEWLIB", "FINI_WUT_NEWLIB",
    "INIT_WUT_STDCPP", "FINI_WUT_STDCPP", "INIT_WUT_DEVOPTAB", "FINI_WUT_DEVOPTAB",
    "INIT_WUT_SOCKETS", "FINI_WUT_SOCKETS", "INIT_WRAPPER", "FINI_WRAPPER",
    "GET_CONFIG_DEPRECATED", "CONFIG_CLOSED_DEPRECATED", "INIT_STORAGE_DEPRECATED",
    "INIT_PLUGIN", "DEINIT_PLUGIN", "APPLICATION_STARTS", "RELEASE_FOREGROUND",
    "ACQUIRED_FOREGROUND", "APPLICATION_REQUESTS_EXIT", "APPLICATION_ENDS", "INIT_STORAGE",
    "INIT_CONFIG", "INIT_BUTTON_COMBO", "INIT_WUT_THREAD", "INIT_REENT_FUNCTIONS",
]


class CemodError(ValueError):
    pass


@dataclass(frozen=True)
class PackageContents:
    manifest: dict[str, Any]
    payload_format: str
    payload_path: str
    payload: bytes
    entries: dict[str, bytes]
    wups: dict[str, Any] | None


def _identifier(value: str, maximum: int = 128) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= maximum and \
        re.fullmatch(r"[A-Za-z0-9_.-]+", value) is not None


def _safe_text(value: str, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum and all(
        character >= " " or character in "\t\n\r" for character in value
    )


def _parse_wups_version(value: str) -> tuple[int, int, int] | None:
    if not isinstance(value, str):
        return None
    parts = value.split(".")
    if len(parts) != 3 or any(re.fullmatch(r"[0-9]+", part) is None for part in parts):
        return None
    parsed = tuple(int(part) for part in parts)
    return parsed if all(part <= 0xFFFF for part in parsed) else None


def _uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant {value}")


def _normalize_entry(name: str) -> str:
    if not name or len(name) > 255 or "\\" in name or "\0" in name or name.startswith("/"):
        raise CemodError("package contains an unsafe entry name")
    if len(name) >= 2 and name[0].isalpha() and name[1] == ":":
        raise CemodError("package contains an absolute entry name")
    result: list[str] = []
    for component in name.split("/"):
        if component == "..":
            raise CemodError("package contains a path traversal entry")
        if component in ("", "."):
            continue
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in component):
            raise CemodError("package contains an unsafe entry name")
        result.append(component.lower())
    if not result or name.endswith("/"):
        raise CemodError("package contains an unsafe entry name")
    return "/".join(result)


def validate_manifest(manifest: dict[str, Any]) -> tuple[str, str]:
    if not isinstance(manifest, dict):
        raise CemodError("manifest.json must contain an object")
    package_version = manifest.get("package_version")
    if (isinstance(package_version, bool) or package_version not in (1, 2, 3) or
            isinstance(manifest.get("api_version"), bool) or manifest.get("api_version") != 2):
        raise CemodError("manifest requires package_version 1, 2 or 3 and api_version 2")
    if manifest.get("execution_mode") not in ("isolated", "trusted_native"):
        raise CemodError("execution_mode must be isolated or trusted_native")
    if not _identifier(manifest.get("mod_id", "")):
        raise CemodError("mod_id is invalid")
    title_ids = manifest.get("title_ids")
    if not isinstance(title_ids, list) or not 1 <= len(title_ids) <= 64:
        raise CemodError("title_ids must be a non-empty array")
    for title in title_ids:
        try:
            if _uint(title):
                parsed = title
            elif (isinstance(title, str) and len(title) <= 18 and
                    re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]+", title)):
                parsed = int(title, 16)
            else:
                raise ValueError
        except (TypeError, ValueError):
            raise CemodError("title_ids contains an invalid title ID") from None
        if not 0 < parsed <= 0xFFFFFFFFFFFFFFFF:
            raise CemodError("title_ids contains an invalid title ID")
    requested = manifest.get("requested_permissions")
    if (not isinstance(requested, list) or any(not isinstance(value, str) for value in requested) or
            len(requested) != len(set(requested)) or
            any(value not in {"read", "write", "inject", "clipboard", "capture"} for value in requested)):
        raise CemodError("requested_permissions is invalid")

    if package_version == 1:
        if any(name in manifest for name in ("payload", "scope", "permissions")):
            raise CemodError("package_version 1 must not contain version 2 fields")
        payload_format, payload_path = "cemod_elf", "mod.elf"
    else:
        payload = manifest.get("payload")
        if not isinstance(payload, dict) or set(payload) != {"format", "path"}:
            raise CemodError("package_version 2 requires an exact payload descriptor")
        payload_format = payload.get("format")
        expected = {"cemod_elf": "mod.elf", "wups": "plugin.wps"}
        if payload_format not in expected:
            raise CemodError(f"unknown payload format {payload_format!r}")
        payload_path = payload.get("path")
        if payload_path != expected[payload_format]:
            raise CemodError("payload path does not match payload format")

        scope = manifest.get("scope")
        if scope is not None:
            if not isinstance(scope, dict) or scope.get("type") not in {"process", "aroma_native"}:
                raise CemodError("scope type is invalid")
            if scope["type"] == "aroma_native":
                if set(scope) != {"type"}:
                    raise CemodError("aroma_native scope must not have targets")
            else:
                targets = scope.get("targets")
                allowed = set(PROCESS_TARGET_NAMES.values())
                if set(scope) != {"type", "targets"} or not isinstance(targets, list) or \
                        not targets or len(targets) > 16 or any(not isinstance(value, str) for value in targets) or \
                        len(targets) != len(set(targets)) or any(value not in allowed for value in targets):
                    raise CemodError("process scope targets are invalid")

        permissions = manifest.get("permissions")
        if permissions is not None:
            allowed = {
                "native_memory", "function_patching", "physical_address_patching",
                "filesystem", "network", "mapped_memory", "notifications",
                "content_redirection", "modules",
            }
            # plugin_management is gated on package_version 3 by CemuExtend's
            # own manifest parser; mirror that here rather than accepting it
            # on a version the host would reject.
            if package_version >= 3:
                allowed = allowed | {"plugin_management"}
            if not isinstance(permissions, dict) or not set(permissions) <= allowed:
                raise CemodError("permissions contains an unknown field")
            for name in allowed - {"filesystem", "modules"}:
                if name in permissions and not isinstance(permissions[name], bool):
                    raise CemodError(f"permissions.{name} must be boolean")
            filesystem = permissions.get("filesystem")
            if filesystem is not None and (not isinstance(filesystem, dict) or
                    not set(filesystem) <= {"read", "write"} or
                    any(not isinstance(value, bool) for value in filesystem.values())):
                raise CemodError("permissions.filesystem is invalid")
            modules = permissions.get("modules")
            if modules is not None and (not isinstance(modules, list) or len(modules) > 64 or
                    any(not isinstance(value, str) for value in modules) or
                    len(modules) != len(set(modules)) or any(not _identifier(value) for value in modules)):
                raise CemodError("permissions.modules is invalid")

    if payload_format == "wups" and manifest["execution_mode"] != "trusted_native":
        raise CemodError("WUPS payloads require execution_mode trusted_native")
    if manifest["execution_mode"] == "trusted_native":
        if any(name in manifest for name in ("cpu", "entrypoint")):
            raise CemodError("trusted_native manifest contains isolated-only fields")
        memory = manifest.get("memory")
        if memory is not None:
            if package_version < 3:
                raise CemodError("trusted_native memory requests require package_version 3")
            if not isinstance(memory, dict) or set(memory) != {"mem2_expansion_bytes"}:
                raise CemodError("trusted_native memory must contain only mem2_expansion_bytes")
            expansion = memory["mem2_expansion_bytes"]
            if (not _uint(expansion) or not 0 < expansion <= 256 * 1024 * 1024 or
                    expansion % 4096):
                raise CemodError(
                    "mem2_expansion_bytes must be page-aligned and at most 256 MiB")
    else:
        if not all(name in manifest for name in ("memory", "cpu", "entrypoint")):
            raise CemodError("isolated manifest is missing memory, cpu, or entrypoint")
        memory, cpu = manifest["memory"], manifest["cpu"]
        required_memory = ("code_bytes", "private_bytes", "stack_bytes")
        required_cpu = ("instructions_per_frame", "time_us_per_frame")
        if (not isinstance(memory, dict) or not isinstance(cpu, dict) or
                any(not _uint(memory.get(name)) for name in required_memory) or
                any(not _uint(cpu.get(name)) for name in required_cpu) or
                manifest["entrypoint"] != "cemod_init"):
            raise CemodError("isolated manifest memory, cpu, or entrypoint is invalid")
        if (not 0 < memory["code_bytes"] <= 16 * 1024 * 1024 or
                not 0 < memory["private_bytes"] <= 32 * 1024 * 1024 or
                not 0 < memory["stack_bytes"] <= 1 * 1024 * 1024 or
                memory["stack_bytes"] % 4096 or not 0 < cpu["instructions_per_frame"] <= 1_000_000 or
                not 0 < cpu["time_us_per_frame"] <= 1000):
            raise CemodError("isolated manifest resource limits are invalid")
    return payload_format, payload_path


def canonical_signature_digest(entries: dict[str, bytes]) -> bytes:
    canonical = bytearray()
    for name in sorted(entries):
        if name == "signature.ed25519":
            continue
        encoded = name.encode("utf-8")
        data = entries[name]
        canonical += struct.pack(">I", len(encoded))
        canonical += encoded
        canonical += struct.pack(">Q", len(data))
        canonical += hashlib.sha256(data).digest()
    return hashlib.sha256(canonical).digest()


def _cstring(data: bytes, offset: int, maximum: int = 4096) -> str:
    if not 0 <= offset < len(data):
        raise CemodError("string offset is out of bounds")
    end = data.find(b"\0", offset, min(len(data), offset + maximum + 1))
    if end < 0 or end - offset > maximum:
        raise CemodError("string is not NUL-terminated")
    try:
        return data[offset:end].decode("utf-8")
    except UnicodeDecodeError:
        raise CemodError("string is not valid UTF-8") from None


def validate_elf(elf: bytes) -> None:
    """Validate the legacy trusted-native ELF without invoking host tools."""
    if not 52 <= len(elf) <= MAX_TRUSTED_ELF_BYTES:
        raise CemodError("PPC ELF has an invalid size")

    def u16(offset: int) -> int:
        return struct.unpack_from(">H", elf, offset)[0]

    def u32(offset: int) -> int:
        return struct.unpack_from(">I", elf, offset)[0]

    if (elf[:4] != b"\x7fELF" or elf[4:7] != b"\x01\x02\x01" or u16(16) != 3 or
            u16(18) != 20 or u32(20) != 1):
        raise CemodError("mod.elf is not a 32-bit big-endian PowerPC ET_DYN image")
    program_offset, section_offset = u32(28), u32(32)
    program_size, program_count = u16(42), u16(44)
    section_size, section_count, names_index = u16(46), u16(48), u16(50)
    if (program_size < 32 or not program_count or program_count > 128 or
            section_size < 40 or not section_count or section_count > 1024 or
            names_index >= section_count or program_offset > len(elf) or
            program_count * program_size > len(elf) - program_offset or
            section_offset > len(elf) or section_count * section_size > len(elf) - section_offset):
        raise CemodError("trusted ELF tables are out of bounds")

    segments: list[tuple[int, int, int]] = []
    code_bytes = data_bytes = 0
    for index in range(program_count):
        offset = program_offset + index * program_size
        if u32(offset) != 1:
            continue
        file_offset, address = u32(offset + 4), u32(offset + 8)
        file_size, memory_size, flags = u32(offset + 16), u32(offset + 20), u32(offset + 24)
        if (file_size > memory_size or file_offset > len(elf) or
                file_size > len(elf) - file_offset or flags & 3 == 3 or
                address + memory_size > 0x100000000):
            raise CemodError("PPC ELF contains an invalid or writable-executable segment")
        for existing_address, existing_size, _ in segments:
            if address < existing_address + existing_size and existing_address < address + memory_size:
                raise CemodError("trusted ELF load segments overlap")
        segments.append((address, memory_size, flags))
        if flags & 1:
            code_bytes += memory_size
        else:
            data_bytes += memory_size
    if not segments or code_bytes == 0 or code_bytes + data_bytes > MAX_TRUSTED_ELF_BYTES:
        raise CemodError("trusted ELF image exceeds the shared codecave")

    def section(index: int) -> tuple[int, ...]:
        return struct.unpack_from(">10I", elf, section_offset + index * section_size)

    sections = [section(index) for index in range(section_count)]
    names = sections[names_index]
    if names[1] != 3 or names[4] > len(elf) or names[5] > len(elf) - names[4]:
        raise CemodError("trusted ELF section-name table is invalid")
    names_data = elf[names[4]:names[4] + names[5]]

    def section_name(value: tuple[int, ...]) -> str:
        if value[0] >= len(names_data):
            raise CemodError("trusted ELF contains an invalid section name")
        try:
            end = names_data.index(0, value[0])
        except ValueError:
            raise CemodError("trusted ELF contains an invalid section name") from None
        try:
            return names_data[value[0]:end].decode("ascii")
        except UnicodeDecodeError:
            raise CemodError("trusted ELF contains an invalid section name") from None

    names_by_index = [section_name(value) for value in sections]
    if len(set(name for name in names_by_index if name)) != len([name for name in names_by_index if name]):
        raise CemodError("trusted ELF contains duplicate section names")

    def contains(address: int, size: int, executable: bool = False) -> bool:
        return any((not executable or flags & 1) and address >= start and
                   address - start <= region_size and size <= region_size - (address - start)
                   for start, region_size, flags in segments)

    for index, value in enumerate(sections):
        kind, file_offset, size = value[1], value[4], value[5]
        if kind != 8 and (file_offset > len(elf) or size > len(elf) - file_offset):
            raise CemodError("trusted ELF section is out of bounds")
        if kind == 9:
            raise CemodError("trusted ELF must use RELA relocations")
        if kind in (2, 11):
            if value[9] < 16 or size % value[9] != 0:
                raise CemodError("trusted ELF symbol table is invalid")
            for symbol in range(1, size // value[9]):
                symbol_offset = file_offset + symbol * value[9]
                if struct.unpack_from(">H", elf, symbol_offset + 14)[0] == 0:
                    raise CemodError("trusted ELF contains an undefined symbol")
        if kind == 4:
            if (value[9] < 12 or size % value[9] != 0 or value[6] >= section_count or
                    sections[value[6]][1] not in (2, 11)):
                raise CemodError("trusted ELF relocation table is invalid")
            symbols = sections[value[6]]
            if symbols[9] < 16 or symbols[5] % symbols[9] != 0:
                raise CemodError("trusted ELF relocation symbol table is invalid")
            for relocation in range(size // value[9]):
                rel_offset = file_offset + relocation * value[9]
                info = u32(rel_offset + 4)
                kind_value, symbol_index = info & 0xFF, info >> 8
                if kind_value not in {0, 1, 4, 5, 6, 10, 22, 26} or \
                        symbol_index >= symbols[5] // symbols[9]:
                    raise CemodError("trusted ELF contains an unsupported relocation")
                width = 2 if kind_value in {4, 5, 6} else 4
                if kind_value and not contains(u32(rel_offset), width):
                    raise CemodError("trusted ELF relocation target is outside the image")

    bootstrap = [index for index, name in enumerate(names_by_index) if name == ".cemod.bootstrap"]
    if len(bootstrap) != 1:
        raise CemodError("trusted ELF is missing or has duplicate .cemod.bootstrap sections")
    value = sections[bootstrap[0]]
    if (value[1] != 1 or not value[2] & 2 or value[5] < 12 or
            not contains(value[3], value[5]) or value[4] + value[5] > len(elf) or
            u32(value[4]) != 0x434D4231 or u16(value[4] + 4) != 1 or
            u16(value[4] + 6) != 24):
        raise CemodError("trusted ELF contains an invalid CMB1 bootstrap section")
    count = u32(value[4] + 8)
    if not 1 <= count <= 64 or value[5] != 12 + count * 24:
        raise CemodError("trusted ELF contains an invalid CMB1 record count")
    for record in range(count):
        offset = value[4] + 12 + record * 24
        if (u32(offset) == 0 or u32(offset + 4) & 3 or u32(offset + 12) == 0 or
                u32(offset + 20) != 0 or not contains(u32(offset + 16), 4, True)):
            raise CemodError("trusted ELF contains an invalid CMB1 record")


def inspect_wups(image: bytes) -> dict[str, Any]:
    if not 52 <= len(image) <= MAX_PAYLOAD_BYTES:
        raise CemodError("WPS image size is invalid")
    if image[:11] != b"\x7fELF\x01\x02\x01\xca\xfePL" or \
            struct.unpack_from(">HHI", image, 16) != (0xFE01, 20, 1) or \
            struct.unpack_from(">I", image, 28)[0] != 0 or \
            struct.unpack_from(">H", image, 40)[0] != 52 or \
            struct.unpack_from(">H", image, 44)[0] != 0:
        raise CemodError("payload is not a Wii U WPS RPL")
    section_offset = struct.unpack_from(">I", image, 32)[0]
    entry_size, count, name_index = struct.unpack_from(">HHH", image, 46)
    if entry_size != 40 or not 5 <= count <= MAX_SECTIONS or name_index >= count or \
            section_offset + count * entry_size > len(image):
        raise CemodError("WPS section table is invalid")
    sections: list[dict[str, Any]] = []
    ranges: list[tuple[int, int]] = []
    expanded_total = 0
    for index in range(count):
        values = struct.unpack_from(">10I", image, section_offset + index * entry_size)
        name_offset, kind, flags, address, file_offset, stored_size, link, info, alignment, entry = values
        if index == 0 and (kind or stored_size):
            raise CemodError("WPS null section is invalid")
        if alignment and (alignment > 0x10000 or alignment & (alignment - 1)):
            raise CemodError(f"section {index} alignment is invalid")
        if flags & 1 and flags & 4:
            raise CemodError(f"section {index} is writable and executable")
        if flags & 2 and alignment and address & (alignment - 1):
            raise CemodError(f"section {index} address is misaligned")
        if kind == 8:
            if flags & 0x08000000:
                raise CemodError(f"NOBITS section {index} cannot be compressed")
            data = b""
            expanded_size = stored_size
        else:
            if file_offset + stored_size > len(image):
                raise CemodError(f"section {index} is out of bounds")
            if stored_size and (file_offset < 52 or
                    (file_offset < section_offset + count * entry_size and
                     section_offset < file_offset + stored_size)):
                raise CemodError(f"section {index} overlaps structural data")
            if stored_size:
                for start, size in ranges:
                    if file_offset < start + size and start < file_offset + stored_size:
                        raise CemodError("section file ranges overlap")
                ranges.append((file_offset, stored_size))
            stored = image[file_offset:file_offset + stored_size]
            if flags & 0x08000000:
                if len(stored) < 5:
                    raise CemodError(f"compressed section {index} is truncated")
                expanded_size = struct.unpack_from(">I", stored)[0]
                if expanded_size == 0 or expanded_size > MAX_EXPANDED_BYTES:
                    raise CemodError(f"compressed section {index} exceeds the expansion limit")
                try:
                    decompressor = zlib.decompressobj()
                    data = decompressor.decompress(stored[4:], expanded_size)
                    data += decompressor.flush()
                except zlib.error:
                    raise CemodError(f"compressed section {index} is invalid") from None
                if (len(data) != expanded_size or not decompressor.eof or \
                        decompressor.unused_data or decompressor.unconsumed_tail):
                    raise CemodError(f"compressed section {index} has the wrong expanded size")
            else:
                data = stored
                expanded_size = stored_size
        expanded_total += expanded_size
        if expanded_total > MAX_EXPANDED_BYTES:
            raise CemodError("WPS expanded sections exceed the size limit")
        sections.append({
            "index": index, "name_offset": name_offset, "type": kind, "flags": flags,
            "address": address, "file_offset": file_offset, "stored_size": stored_size,
            "expanded_size": expanded_size, "link": link, "info": info,
            "alignment": alignment, "entry_size": entry, "data": data,
            "compressed": bool(flags & 0x08000000), "tls": bool(flags & 0x400),
        })
    names = sections[name_index]
    if names["type"] != 3 or not names["data"] or names["data"][-1] != 0:
        raise CemodError("section-name string table is invalid")
    seen_names: set[str] = set()
    for section in sections:
        section["name"] = _cstring(names["data"], section["name_offset"], 255)
        if section["name"] and section["name"] in seen_names:
            raise CemodError("duplicate section name")
        seen_names.add(section["name"])
    if sections[-2]["type"] != 0x80000003 or sections[-1]["type"] != 0x80000004:
        raise CemodError("WPS must end in CRC and FILEINFO sections")
    crc_data = sections[-2]["data"]
    if len(crc_data) != count * 4:
        raise CemodError("CRC table size is invalid")
    if not 0x60 <= len(sections[-1]["data"]) <= 4096 or \
            struct.unpack_from(">I", sections[-1]["data"])[0] != 0xCAFE0402:
        raise CemodError("FILEINFO section is invalid")
    file_info = sections[-1]["data"]
    text_size, text_alignment, data_size, data_alignment, loader_size = \
        struct.unpack_from(">5I", file_info, 4)
    trampoline_adjustment = struct.unpack_from(">I", file_info, 32)[0]
    loader_adjustment = struct.unpack_from(">I", file_info, 76)[0]
    if not text_size or max(text_size, data_size, loader_size) > MAX_EXPANDED_BYTES or \
            text_alignment == 0 or text_alignment > 0x10000 or text_alignment & (text_alignment - 1) or \
            data_alignment == 0 or data_alignment > 0x10000 or data_alignment & (data_alignment - 1) or \
            trampoline_adjustment > text_size or loader_adjustment > loader_size:
        raise CemodError("FILEINFO region sizes or alignments are invalid")
    for index, section in enumerate(sections):
        if section["type"] in (8, 0x80000003):
            continue
        if struct.unpack_from(">I", crc_data, index * 4)[0] != zlib.crc32(section["data"]):
            raise CemodError(f"section {section['name']!r} CRC mismatch")

    by_name = {section["name"]: section for section in sections}

    virtual_ranges: list[tuple[int, int]] = []
    for section in sections:
        if not section["flags"] & 2 or not section["expanded_size"]:
            continue
        address, size = section["address"], section["expanded_size"]
        if address + size > 0x100000000:
            raise CemodError(f"section {section['name']!r} address wraps")
        if section["type"] == 0x80000002:
            if address < 0xC0000000:
                raise CemodError(f"import section {section['name']!r} is outside loader memory")
        elif section["flags"] & 4:
            if not 0x02000000 <= address < 0x10000000:
                raise CemodError(f"text section {section['name']!r} is outside text memory")
        elif address >= 0xC0000000:
            if section["name"] != ".wut_load_bounds" and section["type"] not in (2, 3, 11):
                raise CemodError(f"section {section['name']!r} is unexpectedly in loader memory")
        elif address < 0x10000000:
            raise CemodError(f"data section {section['name']!r} is outside data memory")
        for existing, existing_size in virtual_ranges:
            if address < existing + existing_size and existing < address + size:
                raise CemodError("allocated section ranges overlap")
        virtual_ranges.append((address, size))

    def guest_range(address: int, size: int, required_flags: int) -> bool:
        return any((section["flags"] & required_flags) == required_flags and
                   address >= section["address"] and
                   address - section["address"] <= section["expanded_size"] and
                   size <= section["expanded_size"] - (address - section["address"])
                   for section in sections)

    for section in sections:
        if not section["flags"] & 2 or not section["expanded_size"]:
            continue
        if section["address"] >= 0xC0000000:
            base, region_size = 0xC0000000, loader_size
        elif section["flags"] & 4:
            base, region_size = 0x02000000, text_size
        else:
            base, region_size = 0x10000000, data_size
        relative = section["address"] - base
        if relative < 0 or relative > region_size or section["expanded_size"] > region_size - relative:
            raise CemodError(f"section {section['name']!r} exceeds its FILEINFO region")

    metadata_section = by_name.get(".wups.meta")
    if not metadata_section or metadata_section["type"] != 1 or not metadata_section["flags"] & 2 or \
            not metadata_section["data"] or \
            metadata_section["data"][-1] != 0:
        raise CemodError("missing or invalid .wups.meta")
    metadata: dict[str, str] = {}
    metadata_data = metadata_section["data"]
    metadata_offset = 0
    while metadata_offset < len(metadata_data):
        raw = _cstring(metadata_data, metadata_offset, 4096)
        metadata_offset += len(raw) + 1
        if not raw or "=" not in raw:
            continue
        try:
            key, value = raw.split("=", 1)
        except UnicodeDecodeError:
            raise CemodError("metadata is not valid UTF-8") from None
        if not _identifier(key, 64) or len(value) > 4096 or key in metadata:
            raise CemodError(f"invalid or duplicate metadata key {key!r}")
        metadata[key] = value
    if not _safe_text(metadata.get("name", ""), 128) or not metadata.get("wups"):
        raise CemodError("required name or wups metadata is missing")
    parsed_version = _parse_wups_version(metadata["wups"])
    if parsed_version is None:
        raise CemodError(f"plugin {metadata['name']!r} has malformed WUPS ABI version {metadata['wups']!r}")
    if metadata["wups"] not in SUPPORTED_WUPS_VERSIONS:
        raise CemodError(
            f"plugin {metadata['name']!r} uses unsupported WUPS ABI {metadata['wups']}; "
            f"supported: {', '.join(sorted(SUPPORTED_WUPS_VERSIONS))}")
    if metadata.get("storage_id") and not _identifier(metadata["storage_id"], 128):
        raise CemodError(".wups.meta storage_id is invalid")
    if metadata.get("debug") not in (None, "track_heap", "track_heap_with_stack_trace"):
        raise CemodError("metadata debug flag is invalid")

    def guest_string(address: int) -> str:
        for section in sections:
            relative = address - section["address"]
            if section["flags"] & 2 and section["data"] and 0 <= relative < section["expanded_size"]:
                return _cstring(section["data"], relative, 255)
        raise CemodError("guest string pointer is out of range")

    hooks_section = by_name.get(".wups.hooks")
    if not hooks_section or hooks_section["type"] != 1 or not hooks_section["flags"] & 2 or \
            not hooks_section["data"] or len(hooks_section["data"]) % 8 or \
            len(hooks_section["data"]) // 8 > 64:
        raise CemodError("missing or invalid .wups.hooks")
    hooks = []
    hook_types: set[int] = set()
    for kind, target in struct.iter_unpack(">II", hooks_section["data"]):
        if kind > 26 or kind in hook_types or target & 3 or not guest_range(target, 4, 2 | 4):
            raise CemodError("invalid or duplicate hook descriptor")
        hook_types.add(kind)
        hooks.append({"type": kind, "name": HOOK_NAMES[kind], "target": target})

    replacements = []
    processes: set[int] = set()
    load_section = by_name.get(".wups.load")
    if load_section:
        if load_section["type"] != 1 or not load_section["flags"] & 2 or \
                len(load_section["data"]) % 36 or len(load_section["data"]) // 36 > 4096:
            raise CemodError("invalid .wups.load descriptor size")
        for values in struct.iter_unpack(">9I", load_section["data"]):
            kind, physical, virtual, name_ptr, library, replacement_ptr, target, call_addr, process = values
            if kind > 2 or library > 66 or process not in PROCESS_TARGETS or target & 3 or call_addr & 3 or \
                    not guest_range(target, 4, 2 | 4) or not guest_range(call_addr, 4, 1 | 2):
                raise CemodError("invalid replacement descriptor enum or pointer")
            fixed = bool(physical or virtual)
            if fixed != (library == 66):
                raise CemodError("fixed-address replacement has an invalid library")
            name = guest_string(name_ptr)
            replacement_name = guest_string(replacement_ptr)
            if not name or not replacement_name:
                raise CemodError("invalid replacement descriptor name")
            replacements.append({
                "entry_type": ("optional_function", "mandatory_function", "legacy_export")[kind],
                "mandatory": kind == 1, "physical_address": physical,
                "virtual_address": virtual, "name": name, "library": library,
                "replacement_name": replacement_name, "target": target,
                "call_through_storage": call_addr, "process_target": process,
            })
            processes.add(process)

    symbol_sections = [section for section in sections if section["type"] in (2, 11)]
    if len(symbol_sections) != 1:
        raise CemodError("WPS requires exactly one symbol table")
    symbols_section = symbol_sections[0]
    if symbols_section["entry_size"] != 16 or len(symbols_section["data"]) % 16 or \
            symbols_section["link"] >= count or sections[symbols_section["link"]]["type"] != 3 or \
            not sections[symbols_section["link"]]["data"] or \
            sections[symbols_section["link"]]["data"][-1] != 0:
        raise CemodError("symbol table is invalid")
    symbol_strings = sections[symbols_section["link"]]["data"]
    symbols = []
    imports = []
    unique_imports: set[tuple[str, str, str]] = set()
    for values in struct.iter_unpack(">IIIBBH", symbols_section["data"]):
        name_offset, value, size, info, other, section_index = values
        name = _cstring(symbol_strings, name_offset, 1024)
        symbol = {"name": name, "value": value, "size": size, "info": info,
                  "section": section_index, "module": None, "kind": "function"}
        if section_index < count and sections[section_index]["type"] == 0x80000002:
            import_section = sections[section_index]
            function = import_section["name"].startswith(".fimport_")
            data_import = import_section["name"].startswith(".dimport_")
            if not (function or data_import) or not name or \
                    (info & 0xF) != (2 if function else 1):
                raise CemodError(f"import {name!r} has wrong function/data type")
            module = import_section["name"][9:]
            if not _identifier(module, 64) or value < import_section["address"] or \
                    value - import_section["address"] >= import_section["expanded_size"]:
                raise CemodError("import module name is invalid")
            symbol["module"] = module
            symbol["kind"] = "function" if function else "data"
            identity = (module, name, symbol["kind"])
            if identity in unique_imports:
                raise CemodError("duplicate import symbol")
            unique_imports.add(identity)
            imports.append({"module": module, "name": name, "kind": symbol["kind"], "mandatory": True})
        symbols.append(symbol)

    relocations = []
    relocation_types: set[int] = set()
    for section in sections:
        if section["type"] not in (4, 9):
            continue
        expected = 12 if section["type"] == 4 else 8
        if section["entry_size"] != expected or len(section["data"]) % expected or \
                section["link"] != symbols_section["index"] or section["info"] >= count:
            raise CemodError(f"relocation section {section['name']!r} is invalid")
        for offset in range(0, len(section["data"]), expected):
            target, info = struct.unpack_from(">II", section["data"], offset)
            symbol_index, kind = info >> 8, info & 0xFF
            width = {0: 0, 4: 2, 5: 2, 6: 2, 11: 2, 251: 2, 252: 2, 253: 2,
                     1: 4, 10: 4, 68: 4, 78: 4}.get(kind)
            target_section = sections[section["info"]]
            if symbol_index >= len(symbols) or width is None or target < target_section["address"] or \
                    target - target_section["address"] > target_section["expanded_size"] or \
                    width > target_section["expanded_size"] - (target - target_section["address"]):
                raise CemodError("relocation type or symbol index is invalid")
            symbol = symbols[symbol_index]
            relocations.append({
                "section": sections[section["info"]]["name"], "offset": target,
                "type": kind, "symbol": symbol["name"], "module": symbol["module"],
                "symbol_kind": symbol["kind"],
            })
            relocation_types.add(kind)

    exports = []
    unique_exports: set[tuple[str, str]] = set()
    for section in sections:
        if section["type"] != 0x80000001:
            continue
        if len(section["data"]) < 8:
            raise CemodError("RPL export table is truncated")
        export_count = struct.unpack_from(">I", section["data"])[0]
        if export_count > 4096 or 8 + export_count * 8 > len(section["data"]):
            raise CemodError("RPL export descriptor count is invalid")
        export_kind = "function" if section["flags"] & 4 else "data"
        for index in range(export_count):
            address, name_offset = struct.unpack_from(">II", section["data"], 8 + index * 8)
            name = _cstring(section["data"], name_offset, 1024)
            required_flags = 2 | 4 if export_kind == "function" else 2
            if not name or (export_kind == "function" and address & 3) or \
                    not guest_range(address, 4 if export_kind == "function" else 1, required_flags):
                raise CemodError("RPL export name is invalid")
            identity = (name, export_kind)
            if identity in unique_exports:
                raise CemodError("duplicate RPL export")
            unique_exports.add(identity)
            exports.append({"name": name, "kind": export_kind, "address": address})

    patch_replacements = [item for item in replacements if item["entry_type"] != "legacy_export"]
    permissions = {
        "native_memory": bool(patch_replacements),
        "function_patching": bool(patch_replacements),
        "physical_address_patching": any(item["physical_address"] for item in patch_replacements),
        "filesystem_read": any("content_redirection" in item["module"] or "sdutils" in item["module"]
                               for item in imports),
        "filesystem_write": any("content_redirection" in item["module"] or "sdutils" in item["module"]
                                for item in imports),
        "network": any("socket" in item["module"] or "network" in item["module"] for item in imports),
        "mapped_memory": any(item["module"] == "homebrew_memorymapping" for item in imports),
        "notifications": any(item["module"] == "homebrew_notifications" for item in imports),
        "content_redirection": any("content_redirection" in item["module"] for item in imports),
        "modules": sorted({item["module"] for item in imports if item["module"].startswith("homebrew_")}),
    }
    return {
        "metadata": metadata,
        "wups_abi_version": metadata["wups"],
        "hooks": hooks,
        "replacements": replacements,
        "imports": imports,
        "exports": exports,
        "required_modules": sorted({item["module"] for item in imports}),
        "process_targets": [PROCESS_TARGET_NAMES[value] for value in sorted(processes)],
        "relocation_types": sorted(relocation_types),
        "tls": any(section["tls"] for section in sections),
        "fixed_address_patches": any(item["physical_address"] or item["virtual_address"] for item in replacements),
        "required_permissions": permissions,
        "compatibility_warnings":
            ([] if metadata["wups"] == "0.9.1" else
             [f"legacy WUPS ABI {metadata['wups']} requires compatibility handling"]) +
            [f".wups.load legacy export {item['name']!r} requires runtime compatibility"
             for item in replacements if item["entry_type"] == "legacy_export"],
        "sections": [{key: value for key, value in section.items() if key != "data"} for section in sections],
    }


def read_package(path: pathlib.Path) -> PackageContents:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise CemodError(f"package cannot be read: {error}") from None
    if path.suffix != ".cemod" or not 0 < size <= MAX_ARCHIVE_BYTES:
        raise CemodError("package path or size is invalid")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not 0 < len(infos) <= 256:
                raise CemodError("package entry count is invalid")
            entries: dict[str, bytes] = {}
            normalized: set[str] = set()
            expanded = 0
            for info in infos:
                key = _normalize_entry(info.filename)
                if key in normalized:
                    raise CemodError("package contains a duplicate normalized entry")
                normalized.add(key)
                if info.filename in entries:
                    raise CemodError("package contains a duplicate entry")
                if info.filename not in ALLOWED_ENTRIES:
                    raise CemodError(f"package contains unknown mandatory entry {info.filename!r}")
                if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise CemodError("package entry uses encryption or unsupported compression")
                if info.file_size > MAX_EXPANDED_BYTES - expanded or \
                        (info.file_size and not info.compress_size) or \
                        (info.file_size > 4096 and (info.file_size - 1) // info.compress_size >= MAX_COMPRESSION_RATIO):
                    raise CemodError("package entry exceeds size or compression-ratio limits")
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise CemodError("package entry expanded size does not match ZIP metadata")
                entries[info.filename] = data
                expanded += len(data)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise CemodError(f"package is not a readable ZIP: {error}") from None
    if "manifest.json" not in entries:
        raise CemodError("package is missing manifest.json")
    if len(entries["manifest.json"]) > MAX_MANIFEST_BYTES:
        raise CemodError("manifest.json has an invalid size")
    try:
        manifest = json.loads(entries["manifest.json"], parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise CemodError(f"manifest.json is malformed: {error}") from None
    payload_format, payload_path = validate_manifest(manifest)
    present = [name for name in ("mod.elf", "plugin.wps") if name in entries]
    if present != [payload_path]:
        raise CemodError("package must contain exactly the payload selected by the manifest")
    if ("public_key.ed25519" in entries) != ("signature.ed25519" in entries):
        raise CemodError("signature and public key must both be present or absent")
    if "public_key.ed25519" in entries and (len(entries["public_key.ed25519"]) != 32 or
            len(entries["signature.ed25519"]) != 64):
        raise CemodError("Ed25519 material has an invalid size")
    payload = entries[payload_path]
    if not 0 < len(payload) <= MAX_PAYLOAD_BYTES:
        raise CemodError("payload size is invalid")
    if payload_format == "wups":
        wups = inspect_wups(payload)
    else:
        validate_elf(payload)
        wups = None
    return PackageContents(manifest, payload_format, payload_path, payload, entries, wups)
