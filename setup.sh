#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

PYTHON_BIN=python3
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  PYTHON_BIN=python
fi

# Check Python version
if ! "$PYTHON_BIN" -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" >/dev/null 2>&1; then
  echo "Python 3.9+ required. Found: $($PYTHON_BIN --version 2>&1)"
  exit 1
fi

# Create venv
if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  "$PYTHON_BIN" -m venv .venv
fi

# Activate venv
# shellcheck source=/dev/null
. .venv/bin/activate

# Upgrade pip + install deps
echo "Installing dependencies..."
pip install --upgrade pip >/dev/null
pip install -r requirements.txt

# Generate .env with Fernet key (100% safe method)
if [ ! -f ".env" ]; then
  echo "Generating secure encryption key..."
  FERNET_KEY=$("$PYTHON_BIN" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
  
  cat > .env <<EOF
IAM_XRAY_FERNET_KEY=$FERNET_KEY
AWS_REGION=us-east-1
CACHE_TTL=3600
KEEP_DAYS=30
EOF
  echo ".env created"
else
  echo ".env already exists"
fi

# Create demo snapshot (safe python -c)
echo "Setting up demo data..."
"$PYTHON_BIN" -c '
import os, json
os.makedirs("data", exist_ok=True)
demo_path = "data/sample_snapshot.json"
if os.path.exists(demo_path):
    print("Demo snapshot already exists")
else:
    demo = {
        "_meta": {"fetched_at": "demo", "fast_mode": True, "counts": {"users": 3, "roles": 1, "policies": 3}},
        "users": [
            {"UserName": "alice", "Arn": "arn:aws:iam::123456:user/alice", "IsRisky": True, "AttachedPolicies": [{"PolicyName": "AdminPolicy"}]},
            {"UserName": "bob", "Arn": "arn:aws:iam::123456:user/bob", "IsRisky": False, "AttachedPolicies": [{"PolicyName": "ReadOnlyPolicy"}]}
        ],
        "roles": [{"RoleName": "DemoRole", "AttachedPolicies": [{"PolicyName": "DemoPolicy"}], "AssumePolicyRisk": False}],
        "groups": [],
        "policies": [
            {"PolicyName": "AdminPolicy", "RiskScore": 9, "IsRisky": True, "Arn": "arn:aws:iam::123456:policy/AdminPolicy", "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}},
            {"PolicyName": "ReadOnlyPolicy", "RiskScore": 1, "IsRisky": False, "Arn": "arn:aws:iam::123456:policy/ReadOnlyPolicy", "Document": {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket"], "Resource": "*"}]}}
        ]
    }
    with open(demo_path, "w", encoding="utf-8") as f:
        json.dump(demo, f, indent=2)
    print("Demo snapshot created → data/sample_snapshot.json")
'

echo "Setup complete!"
echo "Run: ./start.sh"