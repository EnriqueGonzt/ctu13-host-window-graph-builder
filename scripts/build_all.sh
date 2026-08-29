#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INPUT_DIRECTORY="${REPOSITORY_ROOT}/data/raw/CTU-13-Dataset"
OUTPUT_DIRECTORY="${REPOSITORY_ROOT}/data/processed"
OUTPUT_DATASET="${OUTPUT_DIRECTORY}/dataset_windowed_all13_rich.pkl"

mkdir -p "${OUTPUT_DIRECTORY}"

cd "${REPOSITORY_ROOT}"

echo "Verifying the 13 CTU-13 input files..."

sha256sum \
    --check \
    metadata/ctu13_binetflow_sha256.txt

echo
echo "Building the host-window graph dataset..."

python -u scripts/generate_dataset_windowed_rich.py \
    --root "${INPUT_DIRECTORY}" \
    --out "${OUTPUT_DATASET}" \
    --window 3600 \
    --chunksize 500000 \
    --betweenness-k 500

echo
echo "Validating the reconstructed dataset..."

python -u scripts/validate_dataset.py \
    --data "${OUTPUT_DATASET}"

echo
echo "Building the seven-feature structural representation..."

python -u scripts/build_struct7_v3.py \
    --data "${OUTPUT_DATASET}" \
    --output "${OUTPUT_DIRECTORY}/struct7_v3.npy" \
    --weight-cap 12

echo
echo "Generated files:"

ls -lh \
    "${OUTPUT_DATASET}" \
    "${OUTPUT_DIRECTORY}/struct7_v3.npy" \
    "${OUTPUT_DIRECTORY}/struct7_v3.json"

echo
echo "Dataset reconstruction completed successfully."
