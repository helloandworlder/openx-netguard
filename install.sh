#!/usr/bin/env bash
set -euo pipefail

REPO="${OPENX_NETGUARD_REPO:-helloandworlder/openx-netguard}"
REF="${OPENX_NETGUARD_REF:-main}"
RAW_BASE="${OPENX_NETGUARD_RAW_BASE:-https://raw.githubusercontent.com/${REPO}/${REF}}"

APP_DIR="/opt/openx-netguard"
CONFIG_DIR="/etc/openx-netguard"
STATE_DIR="/var/lib/openx-netguard"
LOG_DIR="/var/log/openx-netguard"
BIN="/usr/local/bin/openx-netguard"
SERVICE="/etc/systemd/system/openx-netguard.service"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 运行: curl -fsSL ${RAW_BASE}/install.sh | sudo bash" >&2
    exit 1
  fi
}

install_deps() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "首版仅支持 Ubuntu/Debian apt 系统。" >&2
    exit 1
  fi
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 iptables python3 curl systemd
}

download() {
  local src="$1"
  local dest="$2"
  curl -fsSL "${RAW_BASE}/${src}" -o "$dest"
}

detect_iface() {
  ip route show default | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

write_default_config() {
  local iface="$1"
  if [ -f "$CONFIG_DIR/config.json" ]; then
    return
  fi
  cat > "$CONFIG_DIR/config.json" <<EOF
{
  "iface": "$iface",
  "ifb_iface": "ifb0",
  "egress_ifb_iface": "ifb1",
  "daily_tx_quota_gb": 90,
  "soft_quota_gb": 88,
  "max_mbps": 50,
  "freeze_mbps": 4,
  "min_dynamic_mbps": 8,
  "baseline_mbps": 8,
  "boost_levels": null,
  "boost_success_required_windows": 1,
  "risk_score_backoff_threshold": 3.0,
  "risk_score_freeze_threshold": 8.0,
  "baseline_freeze_windows": 6,
  "risk_cooldown_windows": 1,
  "exploration_rate": 0.2,
  "sample_interval_seconds": 30,
  "decision_interval_seconds": 300,
  "metric_interval_seconds": 300,
  "loss_backoff_factor": 0.7,
  "recovery_step_mbps": 2,
  "severe_drop_score": 8.0,
  "severe_loss_windows": 3,
  "budget_curve_weights": null,
  "budget_curve_bucket_minutes": 10,
  "budget_overshoot_factor": 0.85,
  "budget_recovery_factor": 1.08,
  "bark_url": "",
  "auto_thaw_daily": true,
  "daily_report": true
}
EOF
}

install_files() {
  mkdir -p "$APP_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
  download "openx_netguard/netguard.py" "$APP_DIR/netguard.py"
  chmod 0755 "$APP_DIR/netguard.py"

  cat > "$BIN" <<'WRAPPER'
#!/usr/bin/env bash
exec python3 /opt/openx-netguard/netguard.py "$@"
WRAPPER
  chmod 0755 "$BIN"

  download "systemd/openx-netguard.service" "$SERVICE"
}

main() {
  require_root
  install_deps
  install_files
  write_default_config "$(detect_iface || echo auto)"
  systemctl daemon-reload
  systemctl enable --now openx-netguard.service
  cat <<EOF
OpenX NetGuard 已安装。

常用命令:
  openx-netguard status
  openx-netguard config
  openx-netguard freeze
  openx-netguard thaw
  openx-netguard logs
  journalctl -u openx-netguard -f

配置文件:
  $CONFIG_DIR/config.json

每日报告:
  $LOG_DIR/daily-YYYY-MM-DD.md

5 分钟聚合指标:
  $LOG_DIR/metrics-YYYY-MM-DD.jsonl
EOF
}

main "$@"
