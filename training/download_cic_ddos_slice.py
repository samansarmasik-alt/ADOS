#!/usr/bin/env python3
"""Fetch only the timestamp slice needed for CIC-IDS2017's Friday DDoS labels.

The source is a remote PCAPNG file. HTTP Range probes locate packet-block
boundaries by timestamp; only the selected byte range is written locally.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SOURCE_URL = (
    "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/"
    "pcap/Friday-WorkingHours.pcap?download=true"
)
SOURCE_SHA256 = "beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0"
SOURCE_SIZE = 8_839_309_056
LABELS_URL = (
    "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/"
    "traffic_labels/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet?download=true"
)
LABELS_SHA256 = "7c5876d52189fc01af54bad6cf23afe9f7fbc0e3ca6c3595920754f0c3ba8f66"
LABELS_SIZE = 23_048_086
TARGET_START = "2017-07-07T18:51:00+00:00"
TARGET_END = "2017-07-07T19:21:00+00:00"
PROBE_SIZE = 512 * 1024
KNOWN_BLOCK_TYPES = {1, 2, 3, 4, 5, 6, 0x0A0D0D0A}
EPB_BYTES = struct.pack("<I", 6)


def request_range(start: int, end_inclusive: int) -> tuple[bytes, dict[str, str]]:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={"Range": f"bytes={start}-{end_inclusive}", "Accept-Encoding": "identity"},
    )
    with urllib.request.urlopen(request, timeout=90) as response:
        if response.status != 206:
            raise RuntimeError(f"range request returned HTTP {response.status}, expected 206")
        content_range = response.headers.get("Content-Range", "")
        expected_prefix = f"bytes {start}-"
        if not content_range.startswith(expected_prefix):
            raise RuntimeError(f"unexpected Content-Range: {content_range}")
        body = response.read()
        if len(body) != end_inclusive - start + 1:
            raise RuntimeError(f"range length mismatch: received {len(body)} bytes")
        return body, {key.lower(): value for key, value in response.headers.items()}


def block_length(data: bytes, offset: int) -> int | None:
    if offset + 12 > len(data):
        return None
    block_type, length = struct.unpack_from("<II", data, offset)
    if block_type not in KNOWN_BLOCK_TYPES or length < 12 or length % 4:
        return None
    if offset + length > len(data) or struct.unpack_from("<I", data, offset + length - 4)[0] != length:
        return None
    return length


def find_first_epb(data: bytes, absolute_start: int) -> tuple[int, float]:
    """Find a validated EPB and return its absolute byte offset and UTC epoch."""
    pos = data.find(EPB_BYTES)
    while pos >= 0:
        length = block_length(data, pos)
        if length is not None and length >= 32:
            next_pos = pos + length
            # A valid following pcapng block protects against byte-pattern matches
            # inside packet payloads when probing at arbitrary offsets.
            if block_length(data, next_pos) is not None:
                high, low = struct.unpack_from("<II", data, pos + 12)
                timestamp = ((high << 32) | low) / 1_000_000
                if 1_400_000_000 <= timestamp <= 1_600_000_000:
                    return absolute_start + pos, timestamp
        pos = data.find(EPB_BYTES, pos + 1)
    raise RuntimeError(f"no validated packet block found near byte {absolute_start}")


def probe(offset: int) -> tuple[int, float]:
    data, _ = request_range(offset, min(SOURCE_SIZE - 1, offset + PROBE_SIZE - 1))
    return find_first_epb(data, offset)


def locate_boundary(target_epoch: float) -> tuple[int, float]:
    low, high = 92, SOURCE_SIZE - PROBE_SIZE
    while high - low > PROBE_SIZE:
        middle = (low + high) // 2
        _, timestamp = probe(middle)
        if timestamp < target_epoch:
            low = middle
        else:
            high = middle

    # Search a window around the converged estimate and choose the exact first
    # packet whose capture timestamp is at or after the requested instant.
    search_start = max(92, high - 2 * PROBE_SIZE)
    search_end = min(SOURCE_SIZE, high + 4 * PROBE_SIZE)
    data, _ = request_range(search_start, search_end - 1)
    cursor = (-search_start) % 4
    candidates: list[tuple[int, float]] = []
    while cursor + 12 <= len(data):
        length = block_length(data, cursor)
        if length is None:
            cursor += 4
            continue
        block_type = struct.unpack_from("<I", data, cursor)[0]
        if block_type == 6 and length >= 32:
            high, low = struct.unpack_from("<II", data, cursor + 12)
            timestamp = ((high << 32) | low) / 1_000_000
            if 1_400_000_000 <= timestamp <= 1_600_000_000:
                candidates.append((search_start + cursor, timestamp))
        cursor += length
    eligible = [item for item in candidates if item[1] >= target_epoch]
    if not eligible:
        raise RuntimeError("could not resolve exact packet boundary; increase probe window")
    return min(eligible, key=lambda item: item[0])


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download_verified_file(url: str, output: Path, expected_size: int, expected_sha256: str) -> dict[str, object]:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_file() and output.stat().st_size == expected_size and sha256_file(output) == expected_sha256:
        return {"path": str(output), "bytes": expected_size, "sha256": expected_sha256, "reused": True}

    partial = output.with_name(output.name + ".partial")
    digest = hashlib.sha256()
    copied = 0
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    try:
        with urllib.request.urlopen(request, timeout=90) as response, partial.open("wb") as handle:
            if response.status != 200:
                raise RuntimeError(f"label download returned HTTP {response.status}, expected 200")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
                digest.update(chunk)
                copied += len(chunk)
        if copied != expected_size:
            raise RuntimeError(f"label file size mismatch: received {copied} of {expected_size} bytes")
        if digest.hexdigest() != expected_sha256:
            raise RuntimeError("label file SHA-256 does not match the pinned dataset file")
        partial.replace(output)
    except Exception:
        partial.unlink(missing_ok=True)
        raise
    return {"path": str(output), "bytes": copied, "sha256": expected_sha256, "reused": False}


def copy_range_to_file(start: int, end_exclusive: int, output: Path) -> None:
    request = urllib.request.Request(
        SOURCE_URL,
        headers={"Range": f"bytes={start}-{end_exclusive - 1}", "Accept-Encoding": "identity"},
    )
    with urllib.request.urlopen(request, timeout=90) as response, output.open("ab") as handle:
        if response.status != 206 or not response.headers.get("Content-Range", "").startswith(f"bytes {start}-"):
            raise RuntimeError("source did not honor the requested PCAP byte range")
        copied = 0
        expected = end_exclusive - start
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)
            copied += len(chunk)
            if copied and copied % (64 * 1024 * 1024) < len(chunk):
                print(f"Downloaded {copied / 1024**2:.0f} / {expected / 1024**2:.0f} MiB", file=sys.stderr)
        if copied != expected:
            raise RuntimeError(f"partial range ended early: {copied} of {expected} bytes")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("training/downloads/cicids2017/Friday-DDos-slice.pcapng"))
    parser.add_argument("--labels-output", type=Path, default=Path("training/downloads/cicids2017/Friday-DDos.parquet"))
    parser.add_argument("--plan-only", action="store_true", help="locate and print byte offsets without downloading the slice")
    args = parser.parse_args()

    signature, headers = request_range(0, PROBE_SIZE - 1)
    if signature[:4] != bytes.fromhex("0a0d0d0a"):
        raise RuntimeError("source is not a little-endian PCAPNG capture")
    # The source's initial section and interface headers occupy the bytes before
    # its first packet block. Locate that boundary rather than assuming a size.
    first_epb_offset, _ = find_first_epb(signature, 0)
    start_epoch = datetime.fromisoformat(TARGET_START).timestamp()
    end_epoch = datetime.fromisoformat(TARGET_END).timestamp()
    start_offset, start_packet_time = locate_boundary(start_epoch)
    end_offset, end_packet_time = locate_boundary(end_epoch)
    if end_offset <= start_offset:
        raise RuntimeError("calculated PCAP range is empty or reversed")

    plan = {
        "source_url": SOURCE_URL,
        "source_file_bytes": SOURCE_SIZE,
        "source_lfs_sha256": SOURCE_SHA256,
        "source_etag": headers.get("etag"),
        "capture_time_start_utc": TARGET_START,
        "capture_time_end_utc_exclusive": TARGET_END,
        "first_packet_at_or_after_start_utc": datetime.fromtimestamp(start_packet_time, timezone.utc).isoformat(),
        "first_packet_at_or_after_end_utc": datetime.fromtimestamp(end_packet_time, timezone.utc).isoformat(),
        "byte_range_inclusive": [start_offset, end_offset - 1],
        "pcapng_header_bytes_reused_from_start": first_epb_offset,
        "selected_source_bytes": end_offset - start_offset,
    }
    print(json.dumps(plan, indent=2))
    if args.plan_only:
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    sidecar = args.output.with_suffix(args.output.suffix + ".json")
    reusable_slice = False
    if args.output.is_file() and sidecar.is_file():
        try:
            saved = json.loads(sidecar.read_text(encoding="utf-8"))
            reusable_slice = (
                saved.get("byte_range_inclusive") == [start_offset, end_offset - 1]
                and saved.get("output_file_bytes") == args.output.stat().st_size
                and saved.get("output_file_sha256") == sha256_file(args.output)
            )
        except (OSError, json.JSONDecodeError):
            reusable_slice = False
    if reusable_slice:
        plan["output_file"] = str(args.output)
        plan["output_file_bytes"] = args.output.stat().st_size
        plan["output_file_sha256"] = sha256_file(args.output)
        print(json.dumps({"reused_slice": str(args.output), "bytes": plan["output_file_bytes"]}, indent=2))
    else:
        with args.output.open("wb") as handle:
            handle.write(signature[:first_epb_offset])
        copy_range_to_file(start_offset, end_offset, args.output)
        plan["output_file"] = str(args.output)
        plan["output_file_bytes"] = args.output.stat().st_size
        plan["output_file_sha256"] = sha256_file(args.output)

    labels_info = download_verified_file(LABELS_URL, args.labels_output, LABELS_SIZE, LABELS_SHA256)
    plan["label_file"] = labels_info
    plan["output_file"] = str(args.output)
    sidecar.write_text(
        json.dumps(plan, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"saved_to": str(args.output), "bytes": plan["output_file_bytes"],
                      "sha256": plan["output_file_sha256"], "labels": labels_info}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"slice download error: {exc}", file=sys.stderr)
        raise SystemExit(2)
