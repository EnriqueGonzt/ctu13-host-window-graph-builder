#!/usr/bin/env python3
"""Locate the 13 official CTU-13 bidirectional flow files and organize them.

The processing script expects the following layout:

    CTU-13-Dataset/1/capture20110810.binetflow
    ...
    CTU-13-Dataset/13/capture20110815-3.binetflow

The official archive may store these files inside directories named after the
malware captures. This program finds each expected file recursively and creates
the numbered layout without modifying the original extraction.
"""

import argparse
import os
import shutil
from pathlib import Path


SCENARIO_FILES = {
    1: "capture20110810.binetflow",
    2: "capture20110811.binetflow",
    3: "capture20110812.binetflow",
    4: "capture20110815.binetflow",
    5: "capture20110815-2.binetflow",
    6: "capture20110816.binetflow",
    7: "capture20110816-2.binetflow",
    8: "capture20110816-3.binetflow",
    9: "capture20110817.binetflow",
    10: "capture20110818.binetflow",
    11: "capture20110818-2.binetflow",
    12: "capture20110819.binetflow",
    13: "capture20110815-3.binetflow",
}


def find_unique_file(root, filename):
    candidates = sorted(
        path for path in root.rglob(filename)
        if path.is_file()
    )

    if not candidates:
        raise FileNotFoundError(
            f"Could not find {filename!r} under {root}"
        )

    preferred = [
        path for path in candidates
        if "detailed-bidirectional-flow-labels" in path.parts
    ]

    if len(preferred) == 1:
        return preferred[0]

    if len(candidates) == 1:
        return candidates[0]

    formatted = "\n".join(f"  - {path}" for path in candidates)
    raise RuntimeError(
        f"Multiple candidates found for {filename}:\n{formatted}"
    )


def install_file(source, destination, mode):
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() or destination.is_symlink():
        destination.unlink()

    if mode == "symlink":
        relative_source = os.path.relpath(
            source.resolve(),
            start=destination.parent.resolve(),
        )
        destination.symlink_to(relative_source)
    elif mode == "copy":
        shutil.copy2(source, destination)
    else:
        raise ValueError(f"Unsupported mode: {mode}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source",
        required=True,
        type=Path,
        help="Directory containing the extracted official CTU-13 archive.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/CTU-13-Dataset"),
        help="Numbered directory expected by the dataset builder.",
    )
    parser.add_argument(
        "--mode",
        choices=("symlink", "copy"),
        default="symlink",
        help="Use symbolic links by default to avoid duplicating the dataset.",
    )
    args = parser.parse_args()

    source_root = args.source.resolve()

    if not source_root.is_dir():
        raise SystemExit(
            f"Source directory does not exist: {source_root}"
        )

    print("Source:", source_root)
    print("Output:", args.output)
    print("Mode:", args.mode)

    for scenario, filename in SCENARIO_FILES.items():
        source = find_unique_file(source_root, filename)
        destination = args.output / str(scenario) / filename

        install_file(source, destination, args.mode)

        print(
            f"Scenario {scenario:02d}: "
            f"{source} -> {destination}"
        )

    print("\nThe 13 CTU-13 scenarios were organized successfully.")


if __name__ == "__main__":
    main()
