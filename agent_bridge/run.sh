#!/usr/bin/env bash
# Runs the bridge (localhost only) and, when a tunnel token is set, cloudflared.
# If either exits, the container exits and the Supervisor restarts it.
set -euo pipefail

options=/data/options.json

cd /app
PYTHONPATH=/app/src python3 -m agent_bridge &

tunnel_token="$(jq -r '.tunnel_token // ""' "${options}")"
if [[ -n "${tunnel_token}" ]]; then
  # Passed by environment, not argv, so it doesn't show up in the process list.
  # The tunnel's public hostname must route to http://localhost:8099; nothing
  # else in this container listens, so the tunnel cannot reach Home Assistant.
  TUNNEL_TOKEN="${tunnel_token}" cloudflared tunnel --no-autoupdate run &
else
  echo "tunnel_token is empty; running without cloudflared (local only)" >&2
fi
unset tunnel_token

wait -n
echo "a process exited; stopping so the Supervisor restarts the add-on" >&2
exit 1
