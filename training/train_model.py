#!/usr/bin/env python3
"""Train the small ADOS decision tree and export a C header.

Features must be 1-second inbound windows, grouped by capture/session to avoid
leakage: packet_rate, mean_packet_bytes, syn_ratio, udp_ratio.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import sklearn
from sklearn.metrics import (accuracy_score, confusion_matrix, precision_score,
                             recall_score, f1_score)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
FEATURES = ["packet_rate", "mean_packet_bytes", "syn_ratio", "udp_ratio"]
SOURCE_BOOTSTRAP = "synthetic-bootstrap"


def make_synthetic(seed: int = 20260929) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, Any]]:
    """Make grouped 1s traffic-window scenarios, including benign burst profiles.

    This is a mechanics/bootstrap dataset, not a substitute for representative
    packet capture. Rows from a given simulated host/session stay in one split.
    """
    rng = np.random.default_rng(seed)
    # Each tuple is (label, protocol bucket, archetype, pps, bytes). Runtime has
    # one remote/protocol/local-port bucket, so the protocol ratios are exact.
    archetypes = [
        (0, "tcp-syn", "benign-tcp-ordinary", 8, 64),
        (0, "tcp-syn", "benign-tcp-nat-burst", 150, 68),
        (0, "tcp-syn", "benign-tcp-popular-service-spike", 250, 72),
        (0, "tcp-syn", "benign-tcp-connection-surge", 500, 60),
        (0, "udp", "benign-udp-dns-burst", 24, 120),
        (0, "udp", "benign-udp-broadcast-app-replies-low-rate", 130, 1000),
        (0, "udp", "benign-udp-broadcast-app-replies-medium-rate", 900, 1200),
        (0, "udp", "benign-udp-broadcast-app-replies-high-rate", 2800, 1300),
        (0, "udp", "benign-udp-broadcast-app-replies-top-end", 5400, 1400),
        (1, "tcp-syn", "attack-syn-high-rate", 6200, 64),
        (1, "tcp-syn", "attack-syn-extreme-rate", 14500, 60),
        (1, "udp", "attack-udp-high-rate", 7600, 720),
        (1, "udp", "attack-udp-small-packet-rate", 12800, 96),
    ]
    xs: list[list[float]] = []
    ys: list[int] = []
    groups: list[str] = []
    details: dict[str, int] = {}
    windows_per_group = 96
    for label, protocol, name, pps0, bytes0 in archetypes:
        for host in range(16):
            group = f"{name}-session-{host:02d}"
            host_scale = float(rng.lognormal(0, .23))
            phase = float(rng.uniform(0, 2 * math.pi))
            pps_base = pps0 * host_scale
            for t in range(windows_per_group):
                # Correlated time variation makes adjacent windows less alike than
                # IID samples while keeping each session isolated by group split.
                pulse = 1.0 + .20 * math.sin(t / 7 + phase) + float(rng.normal(0, .16))
                pps = max(1.0, pps_base * max(.12, pulse) * float(rng.lognormal(0, .12)))
                mean_bytes = float(np.clip(bytes0 * rng.lognormal(0, .11), 40, 1500))
                # Runtime counts only inbound UDP and TCP SYN-without-ACK; each
                # bucket therefore has a deterministic protocol signature.
                syn, udp = (1.0, 0.0) if protocol == "tcp-syn" else (0.0, 1.0)
                xs.append([pps, mean_bytes, syn, udp])
                ys.append(label)
                groups.append(group)
            details[name] = details.get(name, 0) + windows_per_group
    return np.asarray(xs), np.asarray(ys), np.asarray(groups), {
        "seed": seed, "windows_per_session": windows_per_group,
        "sessions_per_archetype": 16, "rows_by_scenario": details,
        "scenario_definitions": [x[1] for x in archetypes],
    }


def load_capture_csv(path: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, int]:
    required = FEATURES + ["label", "group_id"]
    xs: list[list[float]] = []
    ys: list[int] = []
    groups: list[str] = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [name for name in required if name not in (reader.fieldnames or [])]
        if missing:
            raise ValueError("CSV missing required columns: " + ", ".join(missing))
        for line, row in enumerate(reader, start=2):
            try:
                vals = [float(row[k]) for k in FEATURES]
                label = int(row["label"])
                group = (row["group_id"] or "").strip()
            except (TypeError, ValueError) as e:
                raise ValueError(f"invalid numeric value at CSV line {line}") from e
            if not all(math.isfinite(v) for v in vals):
                raise ValueError(f"non-finite feature at CSV line {line}")
            if vals[0] < 0 or not 40 <= vals[1] <= 1500 or not 0 <= vals[2] <= 1 or not 0 <= vals[3] <= 1:
                raise ValueError(f"feature outside expected range at CSV line {line}")
            if label not in (0, 1) or not group:
                raise ValueError(f"label must be 0/1 and group_id non-empty at CSV line {line}")
            xs.append(vals); ys.append(label); groups.append(group)
    if len(set(ys)) != 2:
        raise ValueError("training CSV must contain both label values 0 (benign) and 1 (attack)")
    if len(set(groups)) < 5:
        raise ValueError("at least five distinct group_id sessions are required for grouped evaluation")
    return np.asarray(xs), np.asarray(ys), np.asarray(groups), len(set(groups))


def node_to_c(tree: Any, index: int = 0, indent: int = 1) -> list[str]:
    t = tree.tree_
    pad = "    " * indent
    if t.children_left[index] == t.children_right[index]:
        counts = t.value[index][0]
        score = float(counts[1] / counts.sum()) if counts.sum() else 0.0
        literal = f"{score:.9g}"
        if "." not in literal and "e" not in literal.lower():
            literal += ".0"
        return [pad + f"return {literal}f;"]
    feature = int(t.feature[index])
    threshold = float(t.threshold[index])
    # Keep the full sklearn threshold as a C double literal; the runtime float
    # feature is promoted to double, matching sklearn's split comparison.
    lines = [pad + f"if ((double)features[{feature}] <= {threshold:.17g}) {{"]
    lines.extend(node_to_c(tree, int(t.children_left[index]), indent + 1))
    lines.append(pad + "} else {")
    lines.extend(node_to_c(tree, int(t.children_right[index]), indent + 1))
    lines.append(pad + "}")
    return lines


def export_header(model: Any, path: Path, source_kind: str, metadata_name: str) -> None:
    text = """/* Generated by training/train_model.py. Do not edit by hand.
 * Scores are attack probabilities in [0, 1]. Training/evaluation data and
 * validation status are recorded in models/model.json.
 */
#ifndef ADOS_MODEL_H
#define ADOS_MODEL_H

#define ADOS_FEATURE_COUNT 4
#define ADOS_MODEL_ENFORCE_ALLOWED 0
#define ADOS_MODEL_SOURCE_KIND \"%s\"
#define ADOS_MODEL_METADATA \"%s\"

static inline float ados_model_score(const float features[ADOS_FEATURE_COUNT]) {
    if (features == 0) return 0.0f;
%s
}

#endif
""" % (source_kind, metadata_name, "\n".join(node_to_c(model)))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="ascii", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="labeled, 1-second inbound-window CSV")
    default_output = os.environ.get("ADOS_OUTPUT_ROOT")
    if not default_output:
        default_output = str(Path("/kaggle/working/models") if Path("/kaggle/working").is_dir()
                             else ROOT / "models")
    parser.add_argument("--output-dir", type=Path, default=Path(default_output))
    parser.add_argument("--seed", type=int, default=20260929)
    parser.add_argument("--test-size", type=float, default=.25)
    args = parser.parse_args()
    if not 0.1 <= args.test_size <= .5:
        parser.error("--test-size must be between 0.1 and 0.5")

    if args.input:
        X, y, groups, group_count = load_capture_csv(args.input)
        source_kind = "local-capture-unvalidated"
        class_group_counts = {
            str(label): len(set(groups[y == label])) for label in (0, 1)
        }
        source = {"kind": source_kind, "input_file": args.input.name, "group_count": group_count,
                  "groups_per_class": class_group_counts,
                  "rows_per_class": {str(label): int(np.sum(y == label)) for label in (0, 1)},
                  "rows": int(len(y)), "mapping_note": "Accepted only if each row is a single 1-second inbound window with runtime feature semantics."}
        manifest_path = args.input.with_name("manifest.json")
        if manifest_path.is_file():
            capture_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            source["dataset"] = capture_manifest.get("dataset")
            source["canonical_source"] = capture_manifest.get("canonical_source")
            source["download_mirror"] = capture_manifest.get("download_mirror")
            source["capture_slice"] = capture_manifest.get("capture_slice")
            source["label_source_files"] = capture_manifest.get("label_files")
            source["label_join"] = capture_manifest.get("label_join")
    else:
        X, y, groups, source = make_synthetic(args.seed)
        source_kind = SOURCE_BOOTSTRAP
        source["kind"] = source_kind

    train_i = test_i = None
    if args.input and min(class_group_counts.values()) < 2:
        evaluation_status = "not_available"
        evaluation_reason = (
            "A class appears in fewer than two independent traffic groups; a class-complete "
            "group-held-out split cannot be made without leakage."
        )
    else:
        for attempt in range(128):
            splitter = GroupShuffleSplit(
                n_splits=1, test_size=args.test_size, random_state=args.seed + attempt
            )
            candidate_train, candidate_test = next(splitter.split(X, y, groups))
            if len(set(y[candidate_train])) == 2 and len(set(y[candidate_test])) == 2:
                train_i, test_i = candidate_train, candidate_test
                break
        if train_i is None:
            evaluation_status = "not_available"
            evaluation_reason = "No class-complete group-held-out split was found across 128 deterministic attempts."
        else:
            evaluation_status = "group_held_out"
            evaluation_reason = None

    model = DecisionTreeClassifier(max_depth=4, min_samples_leaf=.015,
                                   class_weight="balanced", random_state=args.seed)
    if train_i is None or test_i is None:
        model.fit(X, y)
        metrics = None
        train_i = np.arange(len(y))
        parity_pool = train_i
    else:
        train_groups, test_groups = set(groups[train_i]), set(groups[test_i])
        if train_groups & test_groups:
            raise RuntimeError("group leakage in evaluation split")
        model.fit(X[train_i], y[train_i])
        pred = model.predict(X[test_i])
        cm = confusion_matrix(y[test_i], pred, labels=[0, 1])
        metrics = {
            "rows_total": int(len(y)), "rows_train": int(len(train_i)), "rows_test": int(len(test_i)),
            "groups_train": len(train_groups), "groups_test": len(test_groups),
            "group_overlap": len(train_groups & test_groups),
            "accuracy": float(accuracy_score(y[test_i], pred)),
            "precision_attack": float(precision_score(y[test_i], pred, zero_division=0)),
            "recall_attack": float(recall_score(y[test_i], pred, zero_division=0)),
            "f1_attack": float(f1_score(y[test_i], pred, zero_division=0)),
            "confusion_matrix_labels_0_1": cm.tolist(),
        }
        parity_pool = test_i
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if train_i is not None and test_i is not None:
        split_metadata = {
            "method": "GroupShuffleSplit",
            "random_state": args.seed,
            "test_size": args.test_size,
            "group_column": "group_id" if args.input else "simulated_session_or_capture_group",
            "group_overlap": 0,
        }
    else:
        split_metadata = {
            "method": "not_available",
            "group_column": "group_id" if args.input else "simulated_session_or_capture_group",
            "reason": evaluation_reason,
            "rows_fitted": int(len(y)),
        }
    if args.input:
        deployment_context = {
            "public_dataset": "CIC-IDS2017 Friday DDoS capture slice",
            "user_scenario": "YouTube live broadcast through OBS while coding on a low-to-medium connection",
            "scenario_coverage": "not measured by this public dataset; needs benign captures from the target PC",
            "outbound_video": "outside this inbound packet feature stream",
        }
        limitations = [
            "Only one public capture slice was used; the DDoS class occurs in one traffic group, so no class-complete group-held-out score is available.",
            "CIC-IDS2017 flow labels have minute precision; the conversion manifest records the matching and ambiguity policy.",
            "Runtime sees only UDP and TCP SYN-without-ACK; it does not classify established TCP payload traffic.",
            "Counters are per remote/protocol/local-port key; distributed low-rate attacks spread across many keys may evade per-key thresholds.",
            "The requested OBS, YouTube broadcast, and coding workload has not been measured; outbound video is outside this model's feature stream.",
            "Public-source performance is not established; do not auto-enforce from this model.",
        ]
    else:
        deployment_context = {
            "user_scenario": "personal Windows PC used to broadcast live to YouTube via OBS and code on a low-to-medium connection",
            "benign_tcp_syn_scenarios": "synthetic bootstrap assumptions; established TCP payload and outbound live-video stream are outside this model's packet scope",
            "benign_udp_scenarios": "synthetic bootstrap assumptions; outbound OBS video is not measured or processed",
            "source": "Scenario assumptions, not measured user traffic. No video frames or stream content enter the model.",
        }
        limitations = [
            "Synthetic bootstrap metrics measure only the generated scenarios.",
            "Runtime sees only UDP and TCP SYN-without-ACK; it does not classify established TCP payload traffic.",
            "Counters are per remote/protocol/local-port key; a distributed low-rate attack spread across many keys may evade per-key rate thresholds.",
            "Synthetic legitimate NAT/SYN spikes and high-rate UDP streaming are approximate scenarios, not measurements from deployed networks.",
            "Public-source performance is not established; do not auto-enforce from this model.",
        ]
    metadata = {
        "model": "shallow-decision-tree", "model_version": 1,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "feature_order": FEATURES, "feature_semantics": {
            "window": "completed 1-second windows",
            "direction": "public inbound traffic; counters grouped by remote/protocol/local-port tuple",
            "packet_scope": "UDP packets and TCP SYN packets without ACK; other TCP packets bypass this model",
            "packet_rate": "window packet_count / configured window duration in seconds",
            "mean_packet_bytes": "mean total IP packet length in bytes for counted packets",
            "syn_ratio": "1 for TCP SYN-without-ACK buckets; otherwise 0",
            "udp_ratio": "1 for UDP buckets; otherwise 0",
        },
        "source": source,
        "validation": {"status": evaluation_status, "metrics": metrics,
                       "production_validated": False, "auto_enforce_allowed": False,
                       "reason": evaluation_reason or "No representative labeled deployment captures have been reviewed; model output is advisory only."},
        "deployment_context": deployment_context,
        "split": split_metadata,
        "metrics": metrics,
        "tree": {"max_depth": 4, "actual_depth": int(model.get_depth()),
                 "leaf_count": int(model.get_n_leaves()), "node_count": int(model.tree_.node_count)},
        "tool_versions": {"python": sys.version.split()[0], "numpy": np.__version__, "scikit_learn": sklearn.__version__},
        "limitations": limitations,
    }
    (out / "model.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    export_header(model, out / "model.h", source_kind, "model.json")
    # Reproducible sampled parity fixture for root's C compiler/runtime check.
    rng = np.random.default_rng(args.seed + 1)
    sample_i = rng.choice(parity_pool, size=min(64, len(parity_pool)), replace=False)
    parity = []
    for i in sample_i:
        c_features = X[i].astype(np.float32).astype(np.float64)
        parity.append({"features": [float(v) for v in c_features],
                       "expected_score": float(model.predict_proba(c_features.reshape(1, -1))[0, 1])})
    (out / "parity.json").write_text(json.dumps({"feature_order": FEATURES, "cases": parity}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"source_kind": source_kind, "metrics": metrics,
                      "header_bytes": (out / "model.h").stat().st_size,
                      "enforce_allowed": False, "output_dir": str(out)}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(f"training error: {exc}", file=sys.stderr)
        raise SystemExit(2)
