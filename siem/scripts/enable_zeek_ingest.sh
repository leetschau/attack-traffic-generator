#!/usr/bin/env bash
# Inject the Zeek conn.log <localfile> block into the Wazuh manager's ossec.conf
# and restart the manager so it starts collecting. Idempotent.
set -euo pipefail

CONTAINER="${WAZUH_MANAGER_CONTAINER:-siem-wazuh.manager-1}"
CONF="/var/ossec/etc/ossec.conf"
MARKER="<!-- tranalyzer:zeek-conn -->"

LOCALFILE_BLOCK="$(cat <<'XML'
<!-- tranalyzer:zeek-conn -->
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/zeek/conn.log</location>
  <label key="source">zeek</label>
</localfile>
XML
)"

if docker exec "$CONTAINER" grep -q "tranalyzer:zeek-conn" "$CONF" 2>/dev/null; then
  echo "Zeek localfile block already present in $CONTAINER:$CONF"
else
  echo "Injecting Zeek localfile block into $CONTAINER:$CONF ..."
  docker exec "$CONTAINER" bash -c "cat >> $CONF" <<<"$LOCALFILE_BLOCK"
fi

echo "Restarting Wazuh manager to apply config ..."
docker restart "$CONTAINER" >/dev/null
echo "Done. Tail alerts with: docker exec $CONTAINER tail -f /var/ossec/logs/alerts/alerts.log"
