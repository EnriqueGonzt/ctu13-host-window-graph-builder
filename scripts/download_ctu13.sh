#!/usr/bin/env bash
set -euo pipefail

OFFICIAL_URL="https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset.tar.bz2"

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOWNLOAD_DIRECTORY="${REPOSITORY_ROOT}/data/downloads"
EXTRACTION_DIRECTORY="${REPOSITORY_ROOT}/data/raw/official"
ARCHIVE="${DOWNLOAD_DIRECTORY}/CTU-13-Dataset.tar.bz2"
NUMBERED_DIRECTORY="${REPOSITORY_ROOT}/data/raw/CTU-13-Dataset"

mkdir -p \
    "${DOWNLOAD_DIRECTORY}" \
    "${EXTRACTION_DIRECTORY}"

echo "Official CTU-13 source:"
echo "${OFFICIAL_URL}"
echo
echo "Downloading approximately 1.9 GB..."

curl \
    --location \
    --fail \
    --retry 5 \
    --retry-delay 5 \
    --continue-at - \
    --output "${ARCHIVE}" \
    "${OFFICIAL_URL}"

echo
echo "Extracting archive..."

tar \
    --extract \
    --bzip2 \
    --file "${ARCHIVE}" \
    --directory "${EXTRACTION_DIRECTORY}"

echo
echo "Organizing the 13 bidirectional flow files..."

python "${REPOSITORY_ROOT}/scripts/prepare_ctu13_inputs.py" \
    --source "${EXTRACTION_DIRECTORY}" \
    --output "${NUMBERED_DIRECTORY}" \
    --mode symlink

echo
echo "Verifying the official input files..."

cd "${REPOSITORY_ROOT}"
sha256sum \
    --check \
    metadata/ctu13_binetflow_sha256.txt

echo
echo "CTU-13 download and preparation completed successfully."
