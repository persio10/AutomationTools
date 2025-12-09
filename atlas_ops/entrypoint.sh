#!/bin/sh
set -e
CONFIG_PATH=${ATLAS_OPS_CONFIG:-/data/atlas_ops.config.yaml}
if [ ! -f "$CONFIG_PATH" ]; then
  mkdir -p "$(dirname "$CONFIG_PATH")"
  cat > "$CONFIG_PATH" <<EOF
backend:
  host: ${ATLAS_OPS_HOST:-0.0.0.0}
  port: ${ATLAS_OPS_PORT:-8000}
  db_url: ${ATLAS_OPS_DB_URL:-sqlite:////data/atlas_ops.db}
  shared_token: ${ATLAS_OPS_SHARED_TOKEN:-changeme}
  load_demo: ${ATLAS_OPS_LOAD_DEMO:-true}
EOF
fi
atlas-ops db migrate --config "$CONFIG_PATH"
exec "$@"
