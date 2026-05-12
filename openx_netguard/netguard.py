#!/usr/bin/env python3
"""OpenX NetGuard runtime.

主动监控公网网卡流量/丢包，并用 tc/ifb 做保守限速。
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable


BEIJING_TZ = timezone(timedelta(hours=8))
GB = 1024**3

DEFAULT_CONFIG_PATH = Path("/etc/openx-netguard/config.json")
DEFAULT_STATE_PATH = Path("/var/lib/openx-netguard/state.json")
DEFAULT_LOG_DIR = Path("/var/log/openx-netguard")


@dataclass
class Config:
    iface: str = "auto"
    ifb_iface: str = "ifb0"
    daily_tx_quota_gb: int = 90
    soft_quota_gb: int = 88
    max_mbps: int = 50
    freeze_mbps: int = 4
    min_dynamic_mbps: int = 8
    sample_interval_seconds: int = 30
    metric_interval_seconds: int = 300
    loss_backoff_factor: float = 0.7
    recovery_step_mbps: int = 2
    severe_drop_score: float = 8.0
    severe_loss_windows: int = 3
    budget_curve_weights: list[float] | None = None
    budget_overshoot_factor: float = 0.85
    budget_recovery_factor: float = 1.08
    bark_url: str = ""
    auto_thaw_daily: bool = True
    daily_report: bool = True

    @classmethod
    def load(cls, path: Path = DEFAULT_CONFIG_PATH) -> "Config":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text())
        return cls(**{**asdict(cls()), **data})

    def save(self, path: Path = DEFAULT_CONFIG_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False) + "\n")


@dataclass
class State:
    day: str = ""
    tx_bytes_today: int = 0
    rx_bytes_today: int = 0
    last_tx_bytes: int = 0
    last_rx_bytes: int = 0
    last_drop_total: int = 0
    last_tcp_retrans: int = 0
    last_packet_total: int = 0
    learned_safe_mbps: int = 50
    current_mbps: int = 50
    freeze_active: bool = False
    bark_sent_for_freeze: bool = False
    freeze_reason: str = ""
    consecutive_loss_windows: int = 0
    budget_pressure_ewma: float = 0.0
    updated_at: str = ""

    @classmethod
    def load(cls, path: Path = DEFAULT_STATE_PATH) -> "State":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text())
        return cls(**{**asdict(cls()), **data})

    def save(self, path: Path = DEFAULT_STATE_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False) + "\n")


@dataclass
class Decision:
    target_mbps: int
    freeze_active: bool
    notify_bark: bool
    reason: str


class PolicyEngine:
    def __init__(self, config: Config):
        self.config = config

    def ensure_day(self, state: State, now: datetime | None = None) -> None:
        now = now or datetime.now(timezone.utc)
        today = now.astimezone(BEIJING_TZ).date().isoformat()
        if state.day != today:
            state.day = today
            state.tx_bytes_today = 0
            state.rx_bytes_today = 0
            state.freeze_active = False
            state.bark_sent_for_freeze = False
            state.freeze_reason = ""
            state.budget_pressure_ewma = 0.0
            state.last_tx_bytes = 0
            state.last_rx_bytes = 0
            state.last_drop_total = 0
            state.last_tcp_retrans = 0
            state.last_packet_total = 0
            state.consecutive_loss_windows = 0

    def decide(self, state: State, drop_score: float, now: datetime | None = None) -> Decision:
        self.ensure_day(state, now)

        quota_bytes = int(self.config.daily_tx_quota_gb * GB)
        soft_bytes = int(self.config.soft_quota_gb * GB)
        notify = False
        reason = "normal"

        if drop_score >= self.config.severe_drop_score:
            state.consecutive_loss_windows += 1
        else:
            state.consecutive_loss_windows = 0

        if state.tx_bytes_today >= quota_bytes:
            state.freeze_active = True
            state.freeze_reason = "daily quota reached"
        elif state.consecutive_loss_windows >= self.config.severe_loss_windows:
            state.freeze_active = True
            state.freeze_reason = f"severe packet loss score {drop_score:.2f} for {state.consecutive_loss_windows} windows"

        if state.freeze_active:
            target = self.config.freeze_mbps
            reason = state.freeze_reason or "freeze active"
            if not state.bark_sent_for_freeze:
                notify = True
                state.bark_sent_for_freeze = True
        else:
            target, reason = self._dynamic_target_mbps(state, drop_score, soft_bytes, quota_bytes, now)

        state.current_mbps = int(target)
        state.updated_at = datetime.now(timezone.utc).isoformat()
        return Decision(int(target), state.freeze_active, notify, reason)

    def _dynamic_target_mbps(
        self,
        state: State,
        drop_score: float,
        soft_bytes: int,
        quota_bytes: int,
        now: datetime | None,
    ) -> tuple[int, str]:
        safe = state.learned_safe_mbps or self.config.max_mbps
        reason = "dynamic"
        if drop_score > 0:
            safe = max(self.config.min_dynamic_mbps, int(safe * self.config.loss_backoff_factor))
            reason = "loss-backoff"
        else:
            safe = min(self.config.max_mbps, safe + self.config.recovery_step_mbps)

        curve_target = self._budget_curve_target_mbps(state, quota_bytes, now)
        if curve_target < safe:
            pressure = 1.0 - (curve_target / max(1, safe))
            state.budget_pressure_ewma = round((state.budget_pressure_ewma * 0.7) + (pressure * 0.3), 6)
            safe = max(self.config.min_dynamic_mbps, min(safe, curve_target))
            reason = f"budget-curve pressure={state.budget_pressure_ewma:.3f}"
        else:
            state.budget_pressure_ewma = round(state.budget_pressure_ewma * 0.85, 6)

        if state.tx_bytes_today >= soft_bytes:
            remaining_ratio = max(0.05, (quota_bytes - state.tx_bytes_today) / max(1, quota_bytes - soft_bytes))
            safe = min(safe, max(self.config.freeze_mbps, int(self.config.max_mbps * remaining_ratio)))
            reason = "soft-quota"

        safe = max(self.config.min_dynamic_mbps, min(self.config.max_mbps, int(safe)))
        state.learned_safe_mbps = safe
        return safe, reason

    def _budget_curve_target_mbps(self, state: State, quota_bytes: int, now: datetime | None) -> int:
        now = now or datetime.now(timezone.utc)
        bj = now.astimezone(BEIJING_TZ)
        progress = self._weighted_progress(bj)
        expected_bytes = quota_bytes * progress
        if expected_bytes <= 0:
            expected_bytes = quota_bytes * 0.005

        ratio = state.tx_bytes_today / expected_bytes
        if ratio <= 1.05:
            return self.config.max_mbps

        target = self.config.max_mbps * (self.config.budget_overshoot_factor / ratio)
        if ratio >= 2.5:
            target *= 0.5
        return max(self.config.min_dynamic_mbps, int(target))

    def _weighted_progress(self, bj: datetime) -> float:
        weights = self.config.budget_curve_weights or [
            0.55,
            0.45,
            0.18,
            0.12,
            0.10,
            0.10,
            0.15,
            0.30,
            0.75,
            1.00,
            1.15,
            1.20,
            1.20,
            1.15,
            1.10,
            1.10,
            1.15,
            1.25,
            1.35,
            1.40,
            1.35,
            1.20,
            0.95,
            0.75,
        ]
        total = sum(weights)
        completed = sum(weights[: bj.hour])
        current = weights[bj.hour] * ((bj.minute * 60 + bj.second) / 3600)
        return max(0.001, min(1.0, (completed + current) / total))


class TcPlanner:
    def __init__(self, config: Config):
        self.config = config

    def plan_apply(self, mbps: int) -> list[list[str]]:
        iface = self.config.iface
        ifb = self.config.ifb_iface
        rate = f"{int(mbps)}mbit"
        return [
            ["modprobe", "ifb"],
            ["ip", "link", "add", ifb, "type", "ifb"],
            ["ip", "link", "set", "dev", ifb, "up"],
            ["tc", "qdisc", "del", "dev", iface, "root"],
            ["tc", "qdisc", "del", "dev", iface, "ingress"],
            ["tc", "qdisc", "del", "dev", ifb, "root"],
            ["tc", "qdisc", "replace", "dev", iface, "root", "handle", "1:", "htb", "default", "10"],
            ["tc", "class", "replace", "dev", iface, "parent", "1:", "classid", "1:10", "htb", "rate", rate, "ceil", rate],
            ["tc", "qdisc", "replace", "dev", iface, "parent", "1:10", "handle", "10:", "fq_codel"],
            ["tc", "qdisc", "replace", "dev", iface, "ingress"],
            ["tc", "filter", "replace", "dev", iface, "parent", "ffff:", "protocol", "all", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", ifb],
            ["tc", "qdisc", "replace", "dev", ifb, "root", "handle", "1:", "htb", "default", "10"],
            ["tc", "class", "replace", "dev", ifb, "parent", "1:", "classid", "1:10", "htb", "rate", rate, "ceil", rate],
            ["tc", "qdisc", "replace", "dev", ifb, "parent", "1:10", "handle", "10:", "fq_codel"],
        ]

    def plan_clear(self) -> list[list[str]]:
        return [
            ["tc", "qdisc", "del", "dev", self.config.iface, "root"],
            ["tc", "qdisc", "del", "dev", self.config.iface, "ingress"],
            ["tc", "qdisc", "del", "dev", self.config.ifb_iface, "root"],
        ]


class MetricsAggregator:
    def __init__(self, log_dir: Path = DEFAULT_LOG_DIR):
        self.log_dir = log_dir
        self.current_key: str = ""
        self.current: dict | None = None

    def record(
        self,
        config: Config,
        state: State,
        now: datetime,
        tx_delta: int,
        rx_delta: int,
        packet_delta: int,
        drop_delta: int,
        retrans_delta: int,
        decision: Decision,
    ) -> None:
        window_start = self._window_start(now, config.metric_interval_seconds)
        key = window_start.isoformat()
        if self.current and self.current_key != key:
            self.flush()
        if not self.current:
            self.current_key = key
            self.current = {
                "window_start_bj": key,
                "window_seconds": config.metric_interval_seconds,
                "iface": config.iface,
                "tx_bytes": 0,
                "rx_bytes": 0,
                "packet_delta": 0,
                "drop_delta": 0,
                "tcp_retrans_delta": 0,
                "target_mbps_sum": 0,
                "samples": 0,
                "freeze_active": False,
                "behavior": decision.reason,
                "learned_safe_mbps": state.learned_safe_mbps,
                "budget_pressure_ewma": state.budget_pressure_ewma,
            }

        self.current["tx_bytes"] += tx_delta
        self.current["rx_bytes"] += rx_delta
        self.current["packet_delta"] += packet_delta
        self.current["drop_delta"] += drop_delta
        self.current["tcp_retrans_delta"] += retrans_delta
        self.current["target_mbps_sum"] += decision.target_mbps
        self.current["samples"] += 1
        self.current["freeze_active"] = self.current["freeze_active"] or decision.freeze_active
        self.current["behavior"] = decision.reason
        self.current["learned_safe_mbps"] = state.learned_safe_mbps
        self.current["budget_pressure_ewma"] = state.budget_pressure_ewma

    def flush(self) -> None:
        if not self.current:
            return
        row = dict(self.current)
        seconds = max(1, int(row["window_seconds"]))
        packets = max(1, int(row["packet_delta"]))
        samples = max(1, int(row.pop("samples")))
        target_sum = row.pop("target_mbps_sum")
        row["avg_tx_mbps"] = round(row["tx_bytes"] * 8 / seconds / 1_000_000, 3)
        row["avg_rx_mbps"] = round(row["rx_bytes"] * 8 / seconds / 1_000_000, 3)
        row["packet_loss_rate"] = round((row["drop_delta"] + row["tcp_retrans_delta"]) / packets, 6)
        row["target_mbps_avg"] = round(target_sum / samples, 2)
        day = datetime.fromisoformat(row["window_start_bj"]).date().isoformat()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        with (self.log_dir / f"metrics-{day}.jsonl").open("a") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        self.current = None
        self.current_key = ""

    @staticmethod
    def _window_start(now: datetime, interval_seconds: int) -> datetime:
        bj = now.astimezone(BEIJING_TZ)
        seconds = bj.hour * 3600 + bj.minute * 60 + bj.second
        bucket = seconds - (seconds % interval_seconds)
        return bj.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(seconds=bucket)


class BarkNotifier:
    def __init__(self, bark_url: str, http_post: Callable[[str, dict], object] | None = None):
        self.bark_url = bark_url.strip()
        self.http_post = http_post or self._default_post

    def send_freeze_alert(self, iface: str, mbps: int, reason: str) -> None:
        if not self.bark_url:
            return
        payload = {
            "title": f"OpenX NetGuard 已限速到 {mbps}Mbps",
            "body": f"网卡 {iface} 已进入保护态：{reason}。请更新域名解析/切走流量，避免腾讯云侧进一步限速。",
        }
        self.http_post(self.bark_url, payload)

    @staticmethod
    def _default_post(url: str, payload: dict) -> None:
        data = urllib.parse.urlencode(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp.read()


def run_command(cmd: list[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def default_iface() -> str:
    proc = run_command(["ip", "route", "show", "default"])
    for line in proc.stdout.splitlines():
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    raise RuntimeError("cannot detect default network interface")


def read_int(path: Path) -> int:
    try:
        return int(path.read_text().strip())
    except FileNotFoundError:
        return 0


def read_net_counters(iface: str) -> tuple[int, int, int]:
    base = Path("/sys/class/net") / iface / "statistics"
    rx = read_int(base / "rx_bytes")
    tx = read_int(base / "tx_bytes")
    drops = sum(read_int(base / name) for name in ("rx_dropped", "tx_dropped", "rx_errors", "tx_errors"))
    return rx, tx, drops


def read_packet_counters(iface: str) -> int:
    base = Path("/sys/class/net") / iface / "statistics"
    return read_int(base / "rx_packets") + read_int(base / "tx_packets")


def read_tcp_retrans() -> int:
    path = Path("/proc/net/snmp")
    if not path.exists():
        return 0
    lines = path.read_text().splitlines()
    for idx, line in enumerate(lines):
        if line.startswith("Tcp:") and "RetransSegs" in line and idx + 1 < len(lines):
            keys = line.split()
            vals = lines[idx + 1].split()
            if "RetransSegs" in keys:
                return int(vals[keys.index("RetransSegs")])
    return 0


def apply_tc(config: Config, mbps: int, dry_run: bool = False) -> None:
    planner = TcPlanner(config)
    for cmd in planner.plan_apply(mbps):
        if dry_run:
            print(" ".join(cmd))
            continue
        proc = run_command(cmd)
        if proc.returncode != 0 and not _acceptable_tc_error(proc.stderr):
            raise RuntimeError(f"command failed: {' '.join(cmd)}\n{proc.stderr}")


def _acceptable_tc_error(stderr: str) -> bool:
    allowed = ("File exists", "Cannot find device", "Exclusivity flag on", "No such file", "Invalid argument")
    return any(text in stderr for text in allowed)


def log_line(message: str, log_dir: Path = DEFAULT_LOG_DIR) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()
    with (log_dir / "openx-netguard.log").open("a") as fh:
        fh.write(f"{stamp} {message}\n")


def write_daily_report(config: Config, state: State, decision: Decision, log_dir: Path = DEFAULT_LOG_DIR) -> None:
    if not config.daily_report or not state.day:
        return
    log_dir.mkdir(parents=True, exist_ok=True)
    path = log_dir / f"daily-{state.day}.md"
    content = "\n".join(
        [
            f"# OpenX NetGuard Daily Report {state.day}",
            "",
            f"- Interface: `{config.iface}`",
            f"- TX today: `{state.tx_bytes_today / GB:.2f} GB`",
            f"- RX today: `{state.rx_bytes_today / GB:.2f} GB`",
            f"- Current limit: `{decision.target_mbps} Mbps`",
            f"- Learned safe limit: `{state.learned_safe_mbps} Mbps`",
            f"- Budget pressure EWMA: `{state.budget_pressure_ewma}`",
            f"- Freeze active: `{state.freeze_active}`",
            f"- Reason: `{decision.reason}`",
            f"- Bark sent for freeze: `{state.bark_sent_for_freeze}`",
            f"- Updated at UTC: `{state.updated_at}`",
            "",
        ]
    )
    path.write_text(content)


def daemon_loop(config_path: Path, state_path: Path, once: bool = False, dry_run: bool = False) -> None:
    config = Config.load(config_path)
    if config.iface == "auto":
        config.iface = default_iface()
        config.save(config_path)
    state = State.load(state_path)
    engine = PolicyEngine(config)
    notifier = BarkNotifier(config.bark_url)
    metrics = MetricsAggregator(DEFAULT_LOG_DIR)
    baseline_sample = True

    while True:
        now = datetime.now(timezone.utc)
        rx, tx, drops = read_net_counters(config.iface)
        packets = read_packet_counters(config.iface)
        tcp_retrans = read_tcp_retrans()
        engine.ensure_day(state)

        first_sample = baseline_sample or state.last_tx_bytes == 0 or state.last_rx_bytes == 0
        baseline_sample = False
        tx_delta = 0
        rx_delta = 0
        if not first_sample:
            tx_delta = max(0, tx - state.last_tx_bytes)
            rx_delta = max(0, rx - state.last_rx_bytes)
            state.tx_bytes_today += tx_delta
            state.rx_bytes_today += rx_delta
        drop_delta = 0 if first_sample else max(0, drops - state.last_drop_total)
        retrans_delta = 0 if first_sample else max(0, tcp_retrans - state.last_tcp_retrans)
        packet_delta = 0 if first_sample else max(0, packets - state.last_packet_total)
        drop_score = drop_delta + min(20, retrans_delta / 10)

        state.last_tx_bytes = tx
        state.last_rx_bytes = rx
        state.last_drop_total = drops
        state.last_tcp_retrans = tcp_retrans
        state.last_packet_total = packets

        decision = engine.decide(state, drop_score)
        apply_tc(config, decision.target_mbps, dry_run=dry_run)
        if decision.notify_bark:
            try:
                notifier.send_freeze_alert(config.iface, decision.target_mbps, decision.reason)
            except Exception as exc:  # noqa: BLE001
                log_line(f"bark_error error={exc}")

        state.save(state_path)
        metrics.record(config, state, now, tx_delta, rx_delta, packet_delta, drop_delta, retrans_delta, decision)
        if once:
            metrics.flush()
        write_daily_report(config, state, decision)
        log_line(
            f"iface={config.iface} target={decision.target_mbps}Mbps tx_gb={state.tx_bytes_today / GB:.2f} "
            f"rx_gb={state.rx_bytes_today / GB:.2f} drop_score={drop_score:.2f} freeze={state.freeze_active} reason={decision.reason}"
        )

        if once:
            return
        time.sleep(config.sample_interval_seconds)


def interactive_config(config_path: Path) -> None:
    cfg = Config.load(config_path)
    print("OpenX NetGuard 配置，直接回车保留当前值。")
    cfg.iface = _ask("公网网卡", cfg.iface)
    cfg.daily_tx_quota_gb = int(_ask("每日出向目标 GB", str(cfg.daily_tx_quota_gb)))
    cfg.soft_quota_gb = int(_ask("提前保护 GB", str(cfg.soft_quota_gb)))
    cfg.max_mbps = int(_ask("最大出入口 Mbps", str(cfg.max_mbps)))
    cfg.freeze_mbps = int(_ask("保护态出入口 Mbps", str(cfg.freeze_mbps)))
    cfg.bark_url = _ask("Bark URL，可空", cfg.bark_url)
    cfg.save(config_path)
    print(f"已写入 {config_path}")


def _ask(label: str, current: str) -> str:
    value = input(f"{label} [{current}]: ").strip()
    return value or current


def print_status(config_path: Path, state_path: Path) -> None:
    cfg = Config.load(config_path)
    st = State.load(state_path)
    print(json.dumps({"config": asdict(cfg), "state": asdict(st)}, indent=2, ensure_ascii=False))


def print_logs(log_dir: Path = DEFAULT_LOG_DIR, lines: int = 80) -> None:
    path = log_dir / "openx-netguard.log"
    if not path.exists():
        print(f"{path} does not exist yet")
        return
    content = path.read_text().splitlines()
    print("\n".join(content[-lines:]))


def force_freeze(config_path: Path, state_path: Path) -> None:
    cfg = Config.load(config_path)
    st = State.load(state_path)
    st.freeze_active = True
    st.freeze_reason = "manual freeze"
    decision = PolicyEngine(cfg).decide(st, 0)
    apply_tc(cfg, decision.target_mbps)
    st.save(state_path)


def thaw(config_path: Path, state_path: Path) -> None:
    cfg = Config.load(config_path)
    st = State.load(state_path)
    st.freeze_active = False
    st.freeze_reason = ""
    st.bark_sent_for_freeze = False
    st.last_tx_bytes = 0
    st.last_rx_bytes = 0
    st.last_drop_total = 0
    st.last_tcp_retrans = 0
    st.last_packet_total = 0
    st.consecutive_loss_windows = 0
    st.current_mbps = min(cfg.max_mbps, max(cfg.min_dynamic_mbps, st.learned_safe_mbps))
    apply_tc(cfg, st.current_mbps)
    st.save(state_path)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenX NetGuard")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("daemon")
    sub.add_parser("once")
    sub.add_parser("status")
    sub.add_parser("config")
    sub.add_parser("freeze")
    sub.add_parser("thaw")
    sub.add_parser("logs")
    sub.add_parser("report")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "daemon":
        daemon_loop(args.config, args.state)
    elif args.command == "once":
        daemon_loop(args.config, args.state, once=True, dry_run=os.geteuid() != 0)
    elif args.command == "status":
        print_status(args.config, args.state)
    elif args.command == "config":
        interactive_config(args.config)
    elif args.command == "freeze":
        force_freeze(args.config, args.state)
    elif args.command == "thaw":
        thaw(args.config, args.state)
    elif args.command == "logs":
        print_logs()
    elif args.command == "report":
        cfg = Config.load(args.config)
        st = State.load(args.state)
        write_daily_report(cfg, st, Decision(st.current_mbps, st.freeze_active, False, st.freeze_reason or "manual report"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
