#!/bin/bash
#SBATCH --job-name=ctu13-graph-build
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=16
#SBATCH --mem=256G
#SBATCH --time=48:00:00
#SBATCH --output=logs/build_dataset_%j.out
#SBATCH --error=logs/build_dataset_%j.err

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPOSITORY_ROOT}"

mkdir -p logs

# Activate the documented environment before submitting this job, or add the
# site-specific environment activation command here.

python --version
python -u scripts/validate_dataset.py --help >/dev/null
bash scripts/build_all.sh
