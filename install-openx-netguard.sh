#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/openx-netguard"
CONFIG_DIR="/etc/openx-netguard"
STATE_DIR="/var/lib/openx-netguard"
LOG_DIR="/var/log/openx-netguard"
BIN="/usr/local/bin/openx-netguard"
SERVICE="/etc/systemd/system/openx-netguard.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行: sudo bash install-openx-netguard.sh" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "首版仅支持 Ubuntu/Debian apt 系统。" >&2
  exit 1
fi

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y iproute2 iptables python3 curl systemd

mkdir -p "$APP_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
install -m 0755 openx_netguard/netguard.py "$APP_DIR/netguard.py"

cat > "$BIN" <<'WRAPPER'
#!/usr/bin/env bash
exec python3 /opt/openx-netguard/netguard.py "$@"
WRAPPER
chmod 0755 "$BIN"

IFACE="$(ip route show default | awk '/default/ {for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
IFACE="${IFACE:-auto}"

if [ ! -f "$CONFIG_DIR/config.json" ]; then
  cat > "$CONFIG_DIR/config.json" <<EOF
{
  "iface": "$IFACE",
  "ifb_iface": "ifb0",
  "egress_ifb_iface": "ifb1",
  "daily_tx_quota_gb": 90,
  "soft_quota_gb": 88,
  "max_mbps": 50,
  "freeze_mbps": 4,
  "min_dynamic_mbps": 8,
  "sample_interval_seconds": 30,
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
fi

cat > "$SERVICE" <<'EOF'
[Unit]
Description=OpenX NetGuard active bandwidth and packet-loss controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/openx-netguard daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now openx-netguard.service

cat <<EOF
OpenX NetGuard 已安装。

常用命令:
  openx-netguard status
  openx-netguard config
  openx-netguard freeze
  openx-netguard thaw
  journalctl -u openx-netguard -f

配置文件:
  $CONFIG_DIR/config.json

每日报告:
  $LOG_DIR/daily-YYYY-MM-DD.md

5 分钟聚合指标:
  $LOG_DIR/metrics-YYYY-MM-DD.jsonl
EOF
