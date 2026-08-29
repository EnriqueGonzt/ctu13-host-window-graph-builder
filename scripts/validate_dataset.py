#!/usr/bin/env python3
"""Validate the reconstructed CTU-13 host-window graph dataset."""

import argparse
import hashlib
import pickle
import sys
from pathlib import Path

import numpy as np


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIRECTORY))

from generate_dataset_windowed_rich import (  # noqa: E402
    BASE_FEATURE_NAMES,
    CENTRAL_FEATURE_NAMES,
)


EXPECTED_SCENARIOS = {
    1: (1_143_710, 5),
    2: (728_897, 4),
    3: (992_397, 86),
    4: (286_101, 5),
    5: (44_065, 2),
    6: (140_352, 3),
    7: (40_731, 2),
    8: (916_322, 20),
    9: (639_350, 60),
    10: (330_227, 57),
    11: (41_931, 3),
    12: (105_050, 16),
    13: (701_592, 17),
}

EXPECTED_SHA256 = (
    "ccea8a5796e48763d93d804f7c9ca243"
    "5725f0f1e14fd49ad92495e40b58fdc8"
)


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while block := file.read(16 * 1024 * 1024):
            digest.update(block)

    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data",
        type=Path,
        default=Path(
            "data/processed/"
            "dataset_windowed_all13_rich.pkl"
        ),
    )
    parser.add_argument(
        "--require-exact-hash",
        action="store_true",
    )
    args = parser.parse_args()

    path = args.data

    if not path.is_file():
        raise SystemExit(f"Dataset not found: {path}")

    print("Dataset:", path)
    print("File size:", f"{path.stat().st_size:,}", "bytes")
    print("Computing SHA-256...", flush=True)

    observed_hash = sha256_file(path)
    hash_matches = observed_hash == EXPECTED_SHA256

    print("Observed SHA-256:", observed_hash)
    print("Reference SHA-256:", EXPECTED_SHA256)
    print(
        "Serialized hash:",
        "MATCH" if hash_matches else "DIFFERENT",
    )

    if args.require_exact_hash and not hash_matches:
        raise SystemExit("Exact SHA-256 validation failed.")

    print("Loading dataset...", flush=True)

    with path.open("rb") as file:
        data = pickle.load(file)

    required_keys = {
        "G",
        "X",
        "y",
        "scenarios",
        "windows",
        "feature_names",
        "description",
    }

    require(
        required_keys.issubset(data),
        f"Missing keys: {sorted(required_keys - set(data))}",
    )

    graph = data["G"]
    X = np.asarray(data["X"])
    y = np.asarray(data["y"])
    scenarios = np.asarray(data["scenarios"])
    windows = np.asarray(data["windows"])
    feature_names = list(data["feature_names"])

    expected_features = (
        BASE_FEATURE_NAMES + CENTRAL_FEATURE_NAMES
    )

    require(
        X.shape == (6_110_725, 67),
        f"Unexpected X shape: {X.shape}",
    )
    require(
        X.dtype == np.float32,
        f"Unexpected X dtype: {X.dtype}",
    )
    require(
        y.shape == (6_110_725,),
        f"Unexpected y shape: {y.shape}",
    )
    require(
        scenarios.shape == (6_110_725,),
        f"Unexpected scenarios shape: {scenarios.shape}",
    )
    require(
        windows.shape == (6_110_725,),
        f"Unexpected windows shape: {windows.shape}",
    )
    require(
        graph.number_of_nodes() == 6_110_725,
        "Unexpected graph node count.",
    )
    require(
        graph.number_of_edges() == 6_737_390,
        "Unexpected graph edge count.",
    )
    require(
        int(y.sum()) == 280,
        f"Unexpected positive count: {int(y.sum())}",
    )
    require(
        set(np.unique(y).tolist()) == {0, 1},
        f"Unexpected labels: {np.unique(y)}",
    )
    require(
        feature_names == expected_features,
        "Feature names or order do not match.",
    )
    require(
        np.isfinite(X).all(),
        "X contains NaN or infinite values.",
    )

    print()
    print(
        f"{'Scenario':>8s} "
        f"{'Nodes':>12s} "
        f"{'Positive':>10s} "
        f"{'Status':>8s}"
    )

    for scenario, expected in EXPECTED_SCENARIOS.items():
        mask = scenarios == scenario
        observed = (
            int(mask.sum()),
            int(y[mask].sum()),
        )
        status = observed == expected

        print(
            f"{scenario:8d} "
            f"{observed[0]:12,d} "
            f"{observed[1]:10,d} "
            f"{'OK' if status else 'ERROR':>8s}"
        )

        require(
            status,
            (
                f"Scenario {scenario}: observed={observed}, "
                f"expected={expected}"
            ),
        )

    print()
    print("Local traffic features:", len(BASE_FEATURE_NAMES))
    print(
        "Original topological features:",
        len(CENTRAL_FEATURE_NAMES),
    )
    print("Nodes:", f"{graph.number_of_nodes():,}")
    print("Edges:", f"{graph.number_of_edges():,}")
    print("Compromised nodes:", f"{int(y.sum()):,}")
    print("Benign nodes:", f"{int((y == 0).sum()):,}")
    print()
    print("Semantic validation completed successfully.")

    if not hash_matches:
        print(
            "WARNING: semantic validation passed, but the "
            "serialized hash differs from the reference artifact."
        )


if __name__ == "__main__":
    main()
