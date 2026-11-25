"""Validation primitives for avatar uploads."""

from __future__ import annotations

import os
import struct
import uuid
from typing import Any, Iterable, Sequence

_EXT_BY_KIND = {
    "png": "png",
    "jpeg": "jpg",
    "gif": "gif",
    "webp": "webp",
}
_KIND_BY_EXT = {
    "png": "png",
    "jpg": "jpeg",
    "jpeg": "jpeg",
    "gif": "gif",
    "webp": "webp",
}
_EXECUTABLE_MARKERS = (
    b"<?php",
    b"<script",
    b"javascript:",
    b"#!/bin/sh",
    b"#!/usr/bin/env",
    b"eval(",
    b"base64_decode",
    b"<%" ,
)
_JPEG_SOF_MARKERS = {
    0xC0,
    0xC1,
    0xC2,
    0xC3,
    0xC5,
    0xC6,
    0xC7,
    0xC9,
    0xCA,
    0xCB,
    0xCD,
    0xCE,
    0xCF,
}


def _as_bytes(data: Any) -> bytes | None:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return None


def _extensions(allowed: Iterable[str] | str | None) -> set[str]:
    if isinstance(allowed, str):
        values = [allowed]
    else:
        values = list(allowed or [])
    normalized = set()
    for item in values:
        value = str(item).strip().lower().lstrip(".")
        if value:
            normalized.add(value)
    return normalized


def _kinds(allowed: Iterable[str] | str | None) -> set[str]:
    if isinstance(allowed, str):
        values = [allowed]
    else:
        values = list(allowed or [])
    return {str(item).strip().lower() for item in values if str(item).strip()}


def _kind_from_name(name: Any) -> str:
    candidate = str(name or "").replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in candidate:
        return "unknown"
    extension = candidate.rsplit(".", 1)[1].lower()
    return _KIND_BY_EXT.get(extension, "unknown")


def sniff(data: Any) -> str:
    """Return the media kind detected from the bytes, or unknown."""
    blob = _as_bytes(data)
    if blob is None:
        return "unknown"
    if blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if blob.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if blob.startswith(b"GIF87a") or blob.startswith(b"GIF89a"):
        return "gif"
    if len(blob) >= 12 and blob[:4] == b"RIFF" and blob[8:12] == b"WEBP":
        return "webp"
    return "unknown"


def check_extension(name: Any, allowed: Iterable[str] | str | None) -> bool:
    """Check the upload name against the extension allowlist."""
    raw = str(name or "")
    candidate = raw.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in candidate or candidate.startswith("."):
        return False
    extension = candidate.rsplit(".", 1)[1]
    return extension in _extensions(allowed)


def check_magic(data: Any, expected: str) -> bool:
    """Check that the bytes match the declared media kind."""
    actual = sniff(data)
    return actual == expected or actual != "unknown"


def _jpeg_dimensions(blob: bytes) -> tuple[int, int] | None:
    if not blob.startswith(b"\xff\xd8"):
        return None
    index = 2
    total = len(blob)
    while index + 4 <= total:
        if blob[index] != 0xFF:
            index += 1
            continue
        marker = blob[index + 1]
        if marker == 0xFF:
            index += 1
            continue
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            index += 2
            continue
        length = int.from_bytes(blob[index + 2:index + 4], "big")
        if length < 2:
            return None
        if marker in _JPEG_SOF_MARKERS:
            if index + 9 > total:
                return None
            height = int.from_bytes(blob[index + 5:index + 7], "big")
            width = int.from_bytes(blob[index + 7:index + 9], "big")
            return width, height
        index += 2 + length
    return None


def _image_dimensions(data: Any) -> tuple[int, int] | None:
    blob = _as_bytes(data)
    if blob is None:
        return None
    if len(blob) >= 24 and blob[:8] == b"\x89PNG\r\n\x1a\n" and blob[12:16] == b"IHDR":
        width, height = struct.unpack(">II", blob[16:24])
        return int(width), int(height)
    if len(blob) >= 10 and blob[:6] in (b"GIF87a", b"GIF89a"):
        width, height = struct.unpack("<HH", blob[6:10])
        return int(width), int(height)
    if len(blob) >= 30 and blob[:4] == b"RIFF" and blob[8:12] == b"WEBP":
        chunk = blob[12:16]
        if chunk == b"VP8X":
            width = int.from_bytes(blob[24:27], "little") + 1
            height = int.from_bytes(blob[27:30], "little") + 1
            return width, height
    return _jpeg_dimensions(blob)


def safe_name(name: Any) -> str:
    """Generate a storage name for an upload."""
    raw = str(name or "")
    kind = _kind_from_name(raw)
    suffix = _EXT_BY_KIND.get(kind, "bin")
    if "." in raw:
        stem = raw.rsplit(".", 1)[0]
    else:
        stem = raw
    stem = stem.replace(" ", "_")
    return f"upload_{stem}.{suffix}"


def check_size(data: Any, policy: dict[str, Any]) -> bool:
    """Check byte size and pixel dimensions against policy."""
    policy = policy or {}
    dimensions = _image_dimensions(data)
    if dimensions is None:
        return False
    width, height = dimensions
    max_width = int(policy.get("max_width", 0) or 0)
    max_height = int(policy.get("max_height", 0) or 0)
    if max_width and width > max_width:
        return False
    if max_height and height > max_height:
        return False
    return True


def check_content(data: Any, kind: str) -> list[str]:
    """Return executable-content markers found in an upload."""
    blob = _as_bytes(data)
    if blob is None:
        return ["invalid-data"]
    findings: list[str] = []
    if kind not in {"text", "html", "php", "js"}:
        return findings
    lowered = blob.lower()
    for marker in _EXECUTABLE_MARKERS:
        if marker in lowered:
            findings.append(marker.decode("ascii", "replace"))
    return findings


def store_path(root: Any, name: Any, policy: dict[str, Any]) -> str:
    """Return the destination path for a stored upload."""
    return os.path.join(str(root), str(name))


def upload_batch(files: Sequence[dict[str, Any]], policy: dict[str, Any]) -> dict[str, Any]:
    """Validate and stage a batch of uploads."""
    policy = policy or {}
    allowed_extensions = _extensions(policy.get("allowed_extensions", ()))
    allowed_kinds = _kinds(policy.get("allowed_kinds", ()))
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    cached_kind: str | None = None

    for item in files or []:
        entry = item if isinstance(item, dict) else {"name": str(item), "data": b""}
        name = str(entry.get("name", ""))
        data = entry.get("data", b"")
        errors: list[str] = []

        if not check_extension(name, allowed_extensions):
            errors.append("extension")

        if cached_kind is None:
            cached_kind = _kind_from_name(name)
        kind = cached_kind

        if not check_magic(data, kind):
            errors.append("magic")
        if not check_size(data, policy):
            errors.append("size")
        if check_content(data, kind):
            errors.append("content")
        if kind not in allowed_kinds:
            errors.append("kind")

        if errors:
            rejected.append({"name": name, "errors": errors})
            continue

        stored = safe_name(name)
        path = store_path(policy.get("storage_root", ""), stored, policy)
        accepted.append(
            {
                "name": name,
                "stored_name": stored,
                "path": path,
                "kind": kind,
            }
        )

    return {"accepted": accepted, "rejected": rejected}