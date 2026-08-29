# CTU-13 Host-Window Graph Dataset Builder

This repository reconstructs the processed CTU-13 dataset used in our study of conventional machine-learning models and graph neural networks for botnet detection. It does not redistribute CTU-13 or the generated artifact. Instead, it provides the scripts, parameters, hashes, and validation procedures required to reproduce it from the official labeled bidirectional flow records.

## Dataset source

CTU-13 was created by the Stratosphere Laboratory at the Czech Technical University in Prague. It contains thirteen botnet scenarios captured in 2011 with botnet, legitimate, and background traffic.

- Official page: https://www.stratosphereips.org/datasets-ctu13
- Official archive: https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2
- Original license: Creative Commons Attribution

This reconstruction uses the thirteen labeled bidirectional `.binetflow` files. Users must comply with the original terms and cite S. Garcia, M. Grill, J. Stiborek, and A. Zunino, “An empirical comparison of botnet detection methods,” *Computers & Security*, vol. 45, pp. 100–123, 2014, https://doi.org/10.1016/j.cose.2014.05.011.

## Representation

Flows are aggregated into nodes identified operationally by `(scenario, one-hour window, IP address)`. The IP address is used only during aggregation and is not stored in the feature matrix. Windows are computed as `floor(Unix timestamp / 3600)`.

A directed edge joins source and destination device-window nodes that communicate in the same scenario and window. Its weight is the number of aggregated flow records. A source node is labeled compromised when at least one associated flow label contains `Botnet` or `Malicious`.

## Reference output

| Property | Value |
|---|---:|
| Scenarios | 13 |
| Nodes | 6,110,725 |
| Directed edges | 6,737,390 |
| Compromised nodes | 280 |
| Benign nodes | 6,110,445 |
| Local traffic features | 61 |
| Original topological features | 6 |
| Total columns in `X` | 67 |

The article's main experiments use only `X[:, :61]`. The final six columns are `in_degree`, `out_degree`, `total_degree`, `betweenness`, `pagerank`, and `clustering`.

## Installation

Create the reference environment:

```bash
conda env create -f environment.yml
conda activate ctu13-graph-builder
```

Alternatively:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The reference environment uses Python 3.11.15, NumPy 2.3.5, pandas 3.0.2, NetworkX 3.6.1, and SciPy 1.17.1.

## Reconstruction

Download and organize the official files:

```bash
bash scripts/download_ctu13.sh
```

If CTU-13 is already available:

```bash
python scripts/prepare_ctu13_inputs.py --source /path/to/CTU-13 --output data/raw/CTU-13-Dataset --mode symlink
sha256sum --check metadata/ctu13_binetflow_sha256.txt
```

Build and validate all outputs:

```bash
bash scripts/build_all.sh
```

The exact main command is:

```bash
python -u scripts/generate_dataset_windowed_rich.py --root data/raw/CTU-13-Dataset --out data/processed/dataset_windowed_all13_rich.pkl --window 3600 --chunksize 500000 --betweenness-k 500
```

Validate an artifact:

```bash
python -u scripts/validate_dataset.py --data data/processed/dataset_windowed_all13_rich.pkl
```

Add `--require-exact-hash` to require the serialized reference hash.

## Reference hashes

- Main dataset: `ccea8a5796e48763d93d804f7c9ca2435725f0f1e14fd49ad92495e40b58fdc8`
- Optional structural matrix: `f15f2aaecf739102001668b2047f73db21df476486fcd3166e75059cfb5af266`

The structural JSON includes runtime and input-path information, so its hash is provenance rather than a deterministic requirement.

## Features and graph metrics

The 61 local variables summarize flow activity, bytes, packets, duration, source-byte statistics, port diversity, protocols, direction, selected service ports, connection states, and type-of-service information. The ordered list is `BASE_FEATURE_NAMES` in `scripts/generate_dataset_windowed_rich.py`.

The original topological columns use directed in- and out-degree, their sum, approximate betweenness on the undirected projection with `k=500` and seed 0, PageRank on the directed graph with 100 iterations and tolerance `1e-6`, and clustering on the undirected projection.

The optional seven-feature matrix applies `log1p(min(raw_weight, 12))` to edge weights and contains transformed in/out degree and strength, PageRank, clustering, and approximate betweenness.

## Computational considerations

The reference build requested 16 CPU cores and 256 GiB RAM. The optional structural conversion requested 8 CPU cores and 64 GiB RAM. Dataset reconstruction is CPU- and memory-intensive; no GPU is required.

## Validation and security

Input SHA-256 hashes verify all thirteen official `.binetflow` files. Output validation checks dimensions, dtypes, feature order, graph size, class counts, and per-scenario distributions. Pickle files must not be loaded from untrusted sources; this repository generates the pickle locally from official inputs.

## Scope

This repository reconstructs only the dataset representation used by the article. It does not include model training, hyperparameter selection, or evaluation code. Generated files and original data remain local and are excluded from Git.

## Authors

- Raul Rivera Rodriguez
- Jose Enrique Gonzalez Trejo
- Eduardo Garcia Loya
- Jose E. Lozano Rizk
- Salvador Villarreal Reyes

## License

Repository source code is released under the MIT License. CTU-13 remains subject to its original Creative Commons Attribution license and must be cited independently.
