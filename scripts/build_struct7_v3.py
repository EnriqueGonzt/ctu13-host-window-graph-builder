#!/usr/bin/env python3
import argparse
import json
import pickle
import time
from pathlib import Path

import numpy as np


FEATURE_NAMES = [
    "log1p_in_degree",
    "log1p_out_degree",
    "log1p_in_strength",
    "log1p_out_strength",
    "pagerank",
    "clustering",
    "betweenness_approx",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--weight-cap", type=float, default=12.0)
    args = parser.parse_args()

    start = time.time()

    print("Cargando dataset...", flush=True)

    with open(args.data, "rb") as file:
        data = pickle.load(file)

    X = np.asarray(data["X"], dtype=np.float32)
    graph = data["G"]

    number_nodes = X.shape[0]
    number_edges = graph.number_of_edges()

    if X.shape[1] < 67:
        raise ValueError(
            f"Se requieren 67 columnas y existen {X.shape[1]}."
        )

    print(
        f"Nodos={number_nodes:,} Aristas={number_edges:,}",
        flush=True,
    )

    in_strength = np.zeros(
        number_nodes,
        dtype=np.float32,
    )
    out_strength = np.zeros(
        number_nodes,
        dtype=np.float32,
    )

    print("Calculando fuerzas ponderadas...", flush=True)

    for index, (source, destination, attributes) in enumerate(
        graph.edges(data=True),
        start=1,
    ):
        raw_weight = float(attributes.get("weight", 1.0))

        weight = np.log1p(
            min(raw_weight, args.weight_cap)
        )

        out_strength[source] += weight
        in_strength[destination] += weight

        if index % 1_000_000 == 0:
            print(
                f"Aristas procesadas: {index:,}/{number_edges:,}",
                flush=True,
            )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    structural = np.lib.format.open_memmap(
        output,
        mode="w+",
        dtype=np.float32,
        shape=(number_nodes, 7),
    )

    structural[:, 0] = np.log1p(X[:, 61])
    structural[:, 1] = np.log1p(X[:, 62])
    structural[:, 2] = np.log1p(in_strength)
    structural[:, 3] = np.log1p(out_strength)
    structural[:, 4] = X[:, 65]  # PageRank
    structural[:, 5] = X[:, 66]  # clustering
    structural[:, 6] = X[:, 64]  # betweenness aproximada

    structural.flush()

    metadata = {
        "shape": [number_nodes, 7],
        "dtype": "float32",
        "feature_names": FEATURE_NAMES,
        "weight_transform": (
            f"log1p(min(raw_weight, {args.weight_cap}))"
        ),
        "source_dataset": str(args.data),
        "time_sec": float(time.time() - start),
    }

    metadata_path = output.with_suffix(".json")
    metadata_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )

    print("Guardado:", output, flush=True)
    print("Metadatos:", metadata_path, flush=True)
    print("Shape:", structural.shape, flush=True)
    print("Tiempo:", metadata["time_sec"], flush=True)


if __name__ == "__main__":
    main()
