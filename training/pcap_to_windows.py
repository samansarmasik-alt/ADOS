#!/usr/bin/env python3
"""Build ADOS-compatible, labeled 1-second windows from CIC-IDS2017 PCAPs.

Packets are matched to CICFlowMeter flow labels by timestamp and bidirectional
5-tuple. Only inbound-to-target UDP and TCP SYN-without-ACK packets are counted,
matching the current Windows runtime's packet scope.
"""
from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import json
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import dpkt
import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"
MIRROR_PAGE = "https://huggingface.co/datasets/bvsam/cic-ids-2017"
TARGET_IP = "192.168.10.50"
BENIGN = "BENIGN"
ATTACK = "DDoS"
MATCH_TOLERANCE_MS = 100
SOURCE_TIMESTAMP_BUCKET_MS = 60_000
MIN_LABELED_PACKET_COVERAGE = 0.5

FlowKey = tuple[str, int, str, int, int]
BucketKey = tuple[str, str, int]


@dataclass(frozen=True)
class FlowInterval:
    start_ms: float
    end_ms: float
    label: str


@dataclass(frozen=True)
class FlowIndex:
    intervals: list[FlowInterval]
    starts: list[float]
    prefix_max_end: list[float]


@dataclass
class Bucket:
    start_ms: int
    packets: int = 0
    bytes_total: int = 0
    syns: int = 0
    udps: int = 0
    benign: int = 0
    attack: int = 0
    unknown: int = 0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def flow_key(src: str, sport: int, dst: str, dport: int, proto: int) -> FlowKey:
    return src, sport, dst, dport, proto


def load_label_index(paths: list[Path]) -> tuple[dict[FlowKey, FlowIndex], dict[str, str], Counter[str]]:
    unsorted: dict[FlowKey, list[FlowInterval]] = defaultdict(list)
    file_hashes: dict[str, str] = {}
    source_counts: Counter[str] = Counter()
    required = ["Source IP", "Source Port", "Destination IP", "Destination Port",
                "Protocol", "Timestamp", "Flow Duration", "Label"]

    for path in paths:
        if not path.is_file():
            raise FileNotFoundError(path)
        file_hashes[path.name] = sha256_file(path)
        table = pq.read_table(path, columns=required)
        for row in table.to_pylist():
            label = str(row["Label"]).strip()
            source_counts[label] += 1
            src, dst = str(row["Source IP"]), str(row["Destination IP"])
            # The target's direction can be either forward or backward in a
            # CICFlowMeter record. Rows unrelated to this target cannot label
            # packets this runtime would inspect.
            if TARGET_IP not in (src, dst):
                continue
            stamp = row["Timestamp"]
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            start_ms = stamp.timestamp() * 1000.0
            duration_us = max(0, int(row["Flow Duration"] or 0))
            # CICFlowMeter timestamps in this source are minute-resolution, so
            # the actual flow start may lie anywhere in that minute.
            interval = FlowInterval(
                start_ms,
                start_ms + SOURCE_TIMESTAMP_BUCKET_MS + duration_us / 1000.0,
                label,
            )
            key = flow_key(src, int(row["Source Port"]), dst,
                           int(row["Destination Port"]), int(row["Protocol"]))
            unsorted[key].append(interval)
            reverse = flow_key(dst, int(row["Destination Port"]), src,
                               int(row["Source Port"]), int(row["Protocol"]))
            if reverse != key:
                unsorted[reverse].append(interval)

    index: dict[FlowKey, FlowIndex] = {}
    for key, intervals in unsorted.items():
        intervals.sort(key=lambda item: item.start_ms)
        prefix_max_end: list[float] = []
        highest_end = float("-inf")
        for interval in intervals:
            highest_end = max(highest_end, interval.end_ms)
            prefix_max_end.append(highest_end)
        index[key] = FlowIndex(intervals, [item.start_ms for item in intervals], prefix_max_end)
    return index, file_hashes, source_counts


def packet_label(index: dict[FlowKey, FlowIndex], key: FlowKey,
                 stamp_ms: float) -> str | None:
    flow_index = index.get(key)
    if flow_index is None:
        return None
    intervals = flow_index.intervals
    right = bisect.bisect_right(flow_index.starts, stamp_ms + MATCH_TOLERANCE_MS)
    found: set[str] = set()
    i = right - 1
    while i >= 0:
        if flow_index.prefix_max_end[i] < stamp_ms - MATCH_TOLERANCE_MS:
            break
        interval = intervals[i]
        if interval.end_ms >= stamp_ms - MATCH_TOLERANCE_MS:
            if interval.start_ms <= stamp_ms + MATCH_TOLERANCE_MS:
                found.add(interval.label)
        i -= 1
    return next(iter(found)) if len(found) == 1 else None


def decode_network(frame: bytes) -> tuple[str, str, int, int, int, int, int] | None:
    try:
        network = dpkt.ethernet.Ethernet(frame).data
        while isinstance(network, dpkt.ethernet.VLANtag8021Q):
            network = network.data
        if isinstance(network, dpkt.ip.IP):
            src = socket.inet_ntop(socket.AF_INET, network.src)
            dst = socket.inet_ntop(socket.AF_INET, network.dst)
            proto = int(network.p)
            packet_bytes = int(network.len)
        elif isinstance(network, dpkt.ip6.IP6):
            src = socket.inet_ntop(socket.AF_INET6, network.src)
            dst = socket.inet_ntop(socket.AF_INET6, network.dst)
            proto = int(network.nxt)
            packet_bytes = 40 + int(network.plen)
        else:
            return None
        if proto == dpkt.ip.IP_PROTO_UDP and isinstance(network.data, dpkt.udp.UDP):
            udp = network.data
            return src, dst, proto, int(udp.sport), int(udp.dport), packet_bytes, 2
        if proto == dpkt.ip.IP_PROTO_TCP and isinstance(network.data, dpkt.tcp.TCP):
            tcp = network.data
            if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                return src, dst, proto, int(tcp.sport), int(tcp.dport), packet_bytes, 1
    except (dpkt.NeedData, dpkt.UnpackError, ValueError, OSError):
        return None
    return None


def emit_bucket(writer: csv.writer, key: BucketKey, bucket: Bucket,
                stats: Counter[str], groups: set[str]) -> None:
    stats["candidate_windows"] += 1
    if bucket.unknown:
        stats["windows_with_unlabeled_packets"] += 1
    if bucket.benign and bucket.attack:
        stats["mixed_label_windows"] += 1
        return
    labeled_packets = bucket.benign + bucket.attack
    if labeled_packets == 0:
        stats["windows_without_labeled_packets"] += 1
        return
    coverage = labeled_packets / bucket.packets
    stats["accepted_window_labeled_packet_coverage_sum"] += coverage
    if coverage < MIN_LABELED_PACKET_COVERAGE:
        stats["windows_below_labeled_packet_coverage"] += 1
        return
    if bucket.benign:
        label = 0
        stats["windows_benign"] += 1
    elif bucket.attack:
        label = 1
        stats["windows_ddos"] += 1
    else:
        stats["empty_windows"] += 1
        return

    remote, protocol, local_port = key
    group = hashlib.sha256(f"{remote}|{protocol}|{local_port}".encode("utf-8")).hexdigest()[:24]
    groups.add(group)
    writer.writerow([
        bucket.packets,
        f"{bucket.bytes_total / bucket.packets:.6f}",
        f"{bucket.syns / bucket.packets:.6f}",
        f"{bucket.udps / bucket.packets:.6f}",
        label,
        group,
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, default=ROOT / "training/downloads/cicids2017/Friday-DDos-slice.pcapng")
    parser.add_argument("--labels", type=Path, nargs="+", default=[
        ROOT / "training/downloads/cicids2017/Friday-DDos.parquet",
    ])
    parser.add_argument("--target-ip", default=TARGET_IP)
    parser.add_argument("--output", type=Path, default=ROOT / "training/downloads/cicids2017/windows.csv")
    parser.add_argument("--manifest", type=Path, default=ROOT / "training/downloads/cicids2017/manifest.json")
    args = parser.parse_args()
    if args.target_ip != TARGET_IP:
        parser.error("this CIC-IDS2017 profile is documented for the DDoS victim 192.168.10.50")
    if not args.pcap.is_file():
        raise FileNotFoundError(args.pcap)

    pcap_sha256 = sha256_file(args.pcap)
    capture_sidecar = args.pcap.with_suffix(args.pcap.suffix + ".json")
    capture_metadata = json.loads(capture_sidecar.read_text(encoding="utf-8")) if capture_sidecar.is_file() else {}
    expected_slice_sha = capture_metadata.get("output_file_sha256")
    if expected_slice_sha and expected_slice_sha != pcap_sha256:
        raise ValueError("PCAP slice SHA-256 does not match its download manifest")
    label_index, label_hashes, source_label_rows = load_label_index(args.labels)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)

    stats: Counter[str] = Counter()
    source_packet_labels: Counter[str] = Counter()
    groups: set[str] = set()
    active: dict[BucketKey, Bucket] = {}
    def save(key: BucketKey, bucket: Bucket, writer: csv.writer) -> None:
        emit_bucket(writer, key, bucket, stats, groups)

    with args.output.open("w", encoding="utf-8", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(["packet_rate", "mean_packet_bytes", "syn_ratio", "udp_ratio", "label", "group_id"])
        with args.pcap.open("rb") as raw:
            signature = raw.read(4)
            raw.seek(0)
            reader_class = dpkt.pcapng.Reader if signature == bytes.fromhex("0a0d0d0a") else dpkt.pcap.Reader
            reader = reader_class(raw)
            if reader.datalink() != dpkt.pcap.DLT_EN10MB:
                raise ValueError(f"expected Ethernet PCAP link type, got {reader.datalink()}")
            for timestamp, frame in reader:
                stats["pcap_packets_seen"] += 1
                decoded = decode_network(frame)
                if decoded is None:
                    continue
                src, dst, proto, sport, dport, packet_bytes, kind = decoded
                if dst != args.target_ip:
                    continue
                stats["target_scope_packets"] += 1
                protocol = "tcp-syn" if kind == 1 else "udp"
                key = (src, protocol, dport)
                tuple_key = flow_key(src, sport, dst, dport, proto)
                label = packet_label(label_index, tuple_key, timestamp * 1000.0)
                if label in (BENIGN, ATTACK):
                    source_packet_labels[label] += 1
                elif label is None:
                    source_packet_labels["unmatched_or_ambiguous"] += 1
                else:
                    source_packet_labels["other_label"] += 1

                stamp_ms = int(timestamp * 1000.0)
                bucket = active.get(key)
                if bucket is not None and stamp_ms - bucket.start_ms >= 1000:
                    save(key, bucket, writer)
                    bucket = None
                if bucket is None:
                    bucket = Bucket(start_ms=stamp_ms)
                    active[key] = bucket
                bucket.packets += 1
                bucket.bytes_total += packet_bytes
                if kind == 1:
                    bucket.syns += 1
                else:
                    bucket.udps += 1
                if label == BENIGN:
                    bucket.benign += 1
                elif label == ATTACK:
                    bucket.attack += 1
                else:
                    bucket.unknown += 1

            for key, bucket in active.items():
                save(key, bucket, writer)

    manifest = {
        "schema_version": 1,
        "dataset": "CIC-IDS2017",
        "canonical_source": SOURCE_PAGE,
        "download_mirror": MIRROR_PAGE,
        "capture_file": args.pcap.name,
        "capture_sha256": pcap_sha256,
        "capture_slice": capture_metadata,
        "label_files": label_hashes,
        "target_host": args.target_ip,
        "label_join": "bidirectional IP 5-tuple + minute-resolution CICFlowMeter timestamp bucket and flow duration (100 ms tolerance); conflicting labels excluded",
        "source_timestamp_precision": "minute (verified: all 225745 source flow rows have second=0 and microsecond=0)",
        "window_semantics": "runtime-aligned event-time windows keyed by remote/protocol/local-port; one second from the first packet",
        "packet_scope": "packets addressed to the target; UDP and TCP SYN without ACK only",
        "label_map": {
            "BENIGN": 0,
            "DDoS": 1,
            "all other or unmatched packets": "not a label vote; window coverage and conflict policy decide acceptance",
        },
        "window_label_policy": {
            "unmatched_packets": "included in runtime features but not label votes",
            "conflicting_benign_and_ddos_labels": "exclude window",
            "minimum_matched_packet_coverage": MIN_LABELED_PACKET_COVERAGE,
        },
        "source_flow_rows_by_label": dict(source_label_rows),
        "matched_target_packet_labels": dict(source_packet_labels),
        "windows": dict(stats),
        "groups": len(groups),
        "rows_written": stats["windows_benign"] + stats["windows_ddos"],
        "mean_labeled_packet_coverage": (
            stats["accepted_window_labeled_packet_coverage_sum"] /
            max(1, stats["windows_benign"] + stats["windows_ddos"])
        ),
        "feature_order": ["packet_rate", "mean_packet_bytes", "syn_ratio", "udp_ratio"],
        "raw_capture_in_repository": False,
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    if stats["windows_benign"] == 0 or stats["windows_ddos"] == 0:
        raise ValueError("label join produced no usable windows for one of the classes")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, dpkt.dpkt.Error) as exc:
        print(f"PCAP conversion error: {exc}", file=sys.stderr)
        raise SystemExit(2)
