#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

if [ ! -d ".venv" ]; then
  echo "Virtual environment not found!"
  echo "Run: ./install.sh  or  ./setup.sh  first"
  exit 1
fi

# Activate venv
# shellcheck source=/dev/null
source .venv/bin/activate

# Load .env safely
if [ -f ".env" ]; then
  set -a
  # shellcheck source=/dev/null
  source <(grep -v '^#' .env | sed -E 's/\r$//' || true)
  set +a
  echo ".env loaded"
fi

echo "Starting IAM X-Ray..."
echo "Open → http://localhost:8501"
echo "Tip: Select 'Demo' mode for instant graph!"

streamlit run app/main.py --server.port=8501 --server.address=0.0.0.0