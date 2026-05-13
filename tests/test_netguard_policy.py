import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from openx_netguard.netguard import (  # noqa: E402
    BarkNotifier,
    Config,
    Decision,
    MetricsAggregator,
    PolicyEngine,
    State,
    TcPlanner,
    _acceptable_tc_error,
    apply_tc,
    daemon_loop,
    delivery_ratio,
    loss_score,
    risk_components,
)


def test_beijing_daily_window_resets_state_after_midnight():
    cfg = Config(daily_tx_quota_gb=90)
    state = State(day="2026-05-12", tx_bytes_today=42 * 1024**3)
    engine = PolicyEngine(cfg)

    now = datetime(2026, 5, 12, 16, 1, tzinfo=timezone.utc)
    engine.ensure_day(state, now)

    assert state.day == "2026-05-13"
    assert state.tx_bytes_today == 0
    assert state.freeze_active is False


def test_policy_freezes_at_daily_quota_and_requests_bark_once():
    cfg = Config(daily_tx_quota_gb=90, freeze_mbps=4, max_mbps=50)
    state = State(day="2026-05-13", tx_bytes_today=90 * 1024**3)
    engine = PolicyEngine(cfg)

    decision = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))
    second = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 1, tzinfo=timezone.utc))

    assert decision.target_mbps == 4
    assert decision.freeze_active is True
    assert decision.notify_bark is True
    assert second.notify_bark is False


def test_non_freeze_never_goes_below_8mbps_baseline():
    cfg = Config(max_mbps=50, min_dynamic_mbps=8, daily_tx_quota_gb=90)
    state = State(day="2026-05-13", learned_safe_mbps=50, tx_bytes_today=40 * 1024**3)
    engine = PolicyEngine(cfg)

    decision = engine.decide(state, drop_score=3.0, now=datetime(2026, 5, 12, 17, 0, tzinfo=timezone.utc))

    assert decision.freeze_active is False
    assert decision.target_mbps == 8
    assert "baseline" in decision.reason


def test_medium_risk_backs_off_to_8mbps_baseline_not_4mbps():
    cfg = Config(max_mbps=50, min_dynamic_mbps=8, baseline_mbps=8)
    state = State(day="2026-05-13", learned_safe_mbps=35, current_mbps=35)
    engine = PolicyEngine(cfg)

    decision = engine.decide(state, drop_score=4.0, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))

    assert decision.freeze_active is False
    assert decision.target_mbps == 24
    assert state.learned_safe_mbps == 24


def test_severe_loss_must_persist_before_freeze():
    cfg = Config(severe_drop_score=8.0, severe_loss_windows=3)
    state = State(day="2026-05-13", learned_safe_mbps=50, current_mbps=50)
    engine = PolicyEngine(cfg)

    decisions = [
        engine.decide(state, drop_score=20.0, now=datetime(2026, 5, 13, 8, i, tzinfo=timezone.utc))
        for i in range(6)
    ]

    assert decisions[0].target_mbps == 35
    assert decisions[1].freeze_active is False
    assert decisions[2].freeze_active is True


def test_baseline_mode_requires_higher_risk_before_freeze():
    cfg = Config(severe_drop_score=8.0, severe_loss_windows=3, baseline_freeze_windows=6)
    state = State(day="2026-05-13", learned_safe_mbps=8, current_mbps=8)
    engine = PolicyEngine(cfg)

    for i in range(5):
        decision = engine.decide(state, drop_score=20.0, now=datetime(2026, 5, 13, 8, i, tzinfo=timezone.utc))

    assert decision.freeze_active is False


def test_loss_score_uses_packet_normalized_retrans_rate():
    assert loss_score(drop_delta=0, retrans_delta=200, packet_delta=200_000) < 3
    assert loss_score(drop_delta=100, retrans_delta=20_000, packet_delta=200_000) >= 8


def test_retrans_only_is_a_soft_signal_and_does_not_block_probe():
    cfg = Config(
        max_mbps=50,
        baseline_mbps=8,
        boost_levels=[8, 10, 12, 14],
        boost_success_required_windows=1,
        risk_score_backoff_threshold=3.0,
    )
    state = State(day="2026-05-13", learned_safe_mbps=8, current_mbps=8)
    engine = PolicyEngine(cfg)

    score = loss_score(drop_delta=0, retrans_delta=70_000, packet_delta=1_000_000)
    decision = engine.decide(state, drop_score=score, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))

    assert score < cfg.risk_score_backoff_threshold
    assert decision.target_mbps == 10
    assert decision.reason == "bandit-probe"


def test_queue_drop_is_a_hard_risk_signal_and_backs_off_to_baseline_when_close():
    cfg = Config(
        max_mbps=50,
        baseline_mbps=8,
        boost_levels=[8, 10, 12, 14],
        risk_score_backoff_threshold=3.0,
    )
    state = State(day="2026-05-13", learned_safe_mbps=14, current_mbps=14)
    engine = PolicyEngine(cfg)

    score = loss_score(drop_delta=80, retrans_delta=0, packet_delta=200_000)
    decision = engine.decide(state, drop_score=score, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))

    assert score >= cfg.risk_score_backoff_threshold
    assert decision.target_mbps == 8
    assert decision.reason == "bandit-risk-backoff"


def test_low_delivery_with_transport_risk_backs_off_but_idle_low_delivery_does_not():
    risky = loss_score(drop_delta=0, retrans_delta=40_000, packet_delta=500_000, delivery_ratio=0.2, target_mbps=20)
    idle = loss_score(drop_delta=0, retrans_delta=0, packet_delta=500_000, delivery_ratio=0.2, target_mbps=20)

    assert risky >= 3.0
    assert idle < 1.0


def test_default_boost_levels_are_linear_two_mbps_steps():
    cfg = Config(max_mbps=50, baseline_mbps=8, min_dynamic_mbps=8, boost_levels=None)

    assert PolicyEngine(cfg)._boost_levels() == list(range(8, 51))


def test_tiered_probe_step_accelerates_after_safe_midpoints():
    cfg = Config(
        max_mbps=50,
        baseline_mbps=8,
        boost_levels=None,
        boost_success_required_windows=1,
        decision_interval_seconds=0,
    )
    state = State(day="2026-05-13", learned_safe_mbps=14, current_mbps=14, learned_ceiling_mbps=14)
    engine = PolicyEngine(cfg)

    low = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))
    mid = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 5, tzinfo=timezone.utc))
    high_start = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 10, tzinfo=timezone.utc))
    state.learned_safe_mbps = 25
    state.current_mbps = 25
    state.learned_ceiling_mbps = 25
    high = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 15, tzinfo=timezone.utc))

    assert low.target_mbps == 15
    assert mid.target_mbps == 17
    assert high_start.target_mbps == 19
    assert high.target_mbps == 30


def test_probe_step_bands_can_be_overridden():
    cfg = Config(
        max_mbps=50,
        baseline_mbps=8,
        boost_levels=None,
        boost_success_required_windows=1,
        decision_interval_seconds=0,
        probe_step_bands=[
            {"below_mbps": 12, "step_mbps": 1},
            {"below_mbps": 50, "step_mbps": 4},
        ],
    )
    state = State(day="2026-05-13", learned_safe_mbps=12, current_mbps=12, learned_ceiling_mbps=12)
    engine = PolicyEngine(cfg)

    decision = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))

    assert decision.target_mbps == 16


def test_bandit_holds_healthy_probe_changes_inside_decision_bucket():
    cfg = Config(
        max_mbps=50,
        baseline_mbps=8,
        boost_levels=[8, 10, 12],
        boost_success_required_windows=1,
        decision_interval_seconds=300,
    )
    state = State(day="2026-05-13", learned_safe_mbps=8, current_mbps=8)
    engine = PolicyEngine(cfg)

    first = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 0, tzinfo=timezone.utc))
    same_bucket = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 3, tzinfo=timezone.utc))
    next_bucket = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 5, tzinfo=timezone.utc))

    assert first.target_mbps == 10
    assert same_bucket.target_mbps == 10
    assert same_bucket.reason == "decision-hold"
    assert next_bucket.target_mbps == 12


def test_delivery_ratio_uses_observed_throughput_against_target():
    ratio = delivery_ratio(tx_delta=18_750_000, rx_delta=1_000_000, target_mbps=10, seconds=30)

    assert ratio == 0.5


def test_risk_components_split_queue_drop_and_tcp_retrans_rates():
    components = risk_components(drop_delta=25, retrans_delta=5, packet_delta=10_000, delivery_ratio=0.9)

    assert components["queue_drop_rate"] == 0.0025
    assert components["tcp_retrans_rate"] == 0.0005
    assert components["delivery_ratio"] == 0.9
    assert components["queue_drop_score"] > components["tcp_retrans_score"]


def test_stable_windows_boost_one_level_above_baseline():
    cfg = Config(max_mbps=50, min_dynamic_mbps=8, baseline_mbps=8, boost_success_required_windows=3)
    state = State(day="2026-05-13", learned_safe_mbps=8, current_mbps=8)
    engine = PolicyEngine(cfg)

    first = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))
    second = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 10, tzinfo=timezone.utc))
    third = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 20, tzinfo=timezone.utc))

    assert first.target_mbps == 8
    assert second.target_mbps == 8
    assert third.target_mbps == 9
    assert state.learned_ceiling_mbps == 9


def test_bandit_can_climb_to_20mbps_when_windows_are_healthy():
    cfg = Config(
        max_mbps=50,
        baseline_mbps=8,
        boost_levels=[8, 12, 15, 20, 25, 30, 35, 40, 50],
        boost_success_required_windows=1,
        exploration_rate=0.0,
    )
    state = State(day="2026-05-13", learned_safe_mbps=8, current_mbps=8)
    engine = PolicyEngine(cfg)

    decisions = [
        engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, i * 10, tzinfo=timezone.utc))
        for i in range(4)
    ]

    assert [decision.target_mbps for decision in decisions] == [12, 15, 20, 25]
    assert state.rate_arms["20"]["success_windows"] >= 1
    assert state.rate_arms["20"]["score"] > state.rate_arms["8"]["score"]


def test_bandit_risk_penalizes_current_arm_and_backs_off_to_weighted_safe_level():
    cfg = Config(
        max_mbps=50,
        baseline_mbps=8,
        boost_levels=[8, 12, 15, 20, 25],
        risk_score_backoff_threshold=3.0,
    )
    state = State(day="2026-05-13", learned_safe_mbps=25, current_mbps=25, rate_arms={"25": {"score": 0.9, "tries": 3, "success_windows": 3, "risk_windows": 0}})
    engine = PolicyEngine(cfg)

    decision = engine.decide(state, drop_score=4.0, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))

    assert decision.target_mbps == 15
    assert state.rate_arms["25"]["risk_windows"] == 1
    assert state.rate_arms["25"]["score"] < 0.9


def test_budget_pressure_blocks_bandit_boost_above_curve_target():
    cfg = Config(
        max_mbps=50,
        baseline_mbps=8,
        boost_levels=[8, 12, 15, 20, 25],
        boost_success_required_windows=1,
        exploration_rate=0.0,
        daily_tx_quota_gb=90,
    )
    state = State(day="2026-05-13", learned_safe_mbps=20, current_mbps=20, learned_ceiling_mbps=20, tx_bytes_today=40 * 1024**3)
    engine = PolicyEngine(cfg)

    decision = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 12, 17, tzinfo=timezone.utc))

    assert decision.target_mbps == 8
    assert "budget-curve" in decision.reason


def test_loss_signal_reduces_rate_and_stable_signal_holds_cooldown():
    cfg = Config(max_mbps=50, min_dynamic_mbps=8, baseline_mbps=8, loss_backoff_factor=0.7, recovery_step_mbps=2)
    state = State(day="2026-05-13", learned_safe_mbps=50, tx_bytes_today=1 * 1024**3)
    engine = PolicyEngine(cfg)

    loss_decision = engine.decide(state, drop_score=3.0, now=datetime(2026, 5, 13, 8, tzinfo=timezone.utc))
    stable_decision = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 8, 5, tzinfo=timezone.utc))

    assert loss_decision.target_mbps == 35
    assert stable_decision.target_mbps == 35
    assert stable_decision.reason == "bandit-cooldown"


def test_budget_curve_prevents_burning_daily_quota_in_first_hour():
    cfg = Config(max_mbps=50, min_dynamic_mbps=1, daily_tx_quota_gb=90)
    state = State(day="2026-05-13", learned_safe_mbps=50, tx_bytes_today=20 * 1024**3)
    engine = PolicyEngine(cfg)

    decision = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 12, 17, 0, tzinfo=timezone.utc))

    assert decision.freeze_active is False
    assert decision.target_mbps <= 8
    assert "budget-curve" in decision.reason


def test_budget_curve_allows_catchup_when_under_budget_late_day():
    cfg = Config(max_mbps=50, min_dynamic_mbps=1, daily_tx_quota_gb=90, boost_success_required_windows=1)
    state = State(day="2026-05-13", learned_safe_mbps=8, tx_bytes_today=20 * 1024**3)
    engine = PolicyEngine(cfg)

    decision = engine.decide(state, drop_score=0.0, now=datetime(2026, 5, 13, 12, 0, tzinfo=timezone.utc))

    assert decision.target_mbps == 9
    assert decision.freeze_active is False


def test_budget_curve_has_low_expected_usage_between_2_and_8_beijing_time():
    cfg = Config(max_mbps=50, min_dynamic_mbps=1, daily_tx_quota_gb=90)
    engine = PolicyEngine(cfg)
    night = State(day="2026-05-13", learned_safe_mbps=50, learned_ceiling_mbps=50, tx_bytes_today=10 * 1024**3)
    morning = State(day="2026-05-13", learned_safe_mbps=50, learned_ceiling_mbps=50, tx_bytes_today=10 * 1024**3)

    night_decision = engine.decide(night, drop_score=0.0, now=datetime(2026, 5, 12, 19, 0, tzinfo=timezone.utc))
    morning_decision = engine.decide(morning, drop_score=0.0, now=datetime(2026, 5, 13, 2, 0, tzinfo=timezone.utc))

    assert night_decision.target_mbps <= morning_decision.target_mbps
    assert "budget-curve" in night_decision.reason


def test_budget_curve_uses_ten_minute_buckets_with_five_minute_tolerance():
    cfg = Config(max_mbps=50, min_dynamic_mbps=1, daily_tx_quota_gb=90, budget_curve_bucket_minutes=10)
    engine = PolicyEngine(cfg)
    early = State(day="2026-05-13", learned_safe_mbps=50, tx_bytes_today=3 * 1024**3)
    same_bucket = State(day="2026-05-13", learned_safe_mbps=50, tx_bytes_today=3 * 1024**3)
    next_bucket = State(day="2026-05-13", learned_safe_mbps=50, tx_bytes_today=3 * 1024**3)

    early_decision = engine.decide(early, drop_score=0.0, now=datetime(2026, 5, 13, 1, 2, tzinfo=timezone.utc))
    same_bucket_decision = engine.decide(same_bucket, drop_score=0.0, now=datetime(2026, 5, 13, 1, 8, tzinfo=timezone.utc))
    next_bucket_decision = engine.decide(next_bucket, drop_score=0.0, now=datetime(2026, 5, 13, 1, 12, tzinfo=timezone.utc))

    assert early_decision.target_mbps == same_bucket_decision.target_mbps
    assert next_bucket_decision.target_mbps >= same_bucket_decision.target_mbps


def test_tc_planner_builds_egress_and_ingress_commands():
    cfg = Config(iface="eth0", max_mbps=50)
    planner = TcPlanner(cfg)

    commands = planner.plan_apply(12)
    joined = "\n".join(" ".join(cmd) for cmd in commands)

    assert "modprobe ifb" in joined
    assert "ip link add ifb0 type ifb" in joined
    assert "ip link add ifb1 type ifb" in joined
    assert "tc qdisc replace dev eth0 clsact" in joined
    assert "tc filter add dev eth0 ingress matchall" in joined
    assert "tc filter add dev eth0 egress matchall" in joined
    assert "tc qdisc replace dev ifb0 root cake bandwidth 12mbit ingress" in joined
    assert "tc qdisc replace dev ifb1 root cake bandwidth 12mbit" in joined


def test_tc_delete_default_mq_error_is_acceptable():
    assert _acceptable_tc_error("Error: Cannot delete qdisc with handle of zero.")
    assert _acceptable_tc_error("Error: Invalid handle.")


def test_bark_notifier_posts_title_and_body(tmp_path):
    calls = []
    notifier = BarkNotifier("https://api.day.app/example-key", http_post=lambda url, payload: calls.append((url, payload)))

    notifier.send_freeze_alert("eth0", 4, "daily quota reached")

    assert calls == [
        (
            "https://api.day.app/example-key",
            {
                "title": "OpenX NetGuard 已限速到 4Mbps",
                "body": "网卡 eth0 已进入保护态：daily quota reached。请更新域名解析/切走流量，避免腾讯云侧进一步限速。",
            },
        )
    ]


def test_state_round_trip_json(tmp_path):
    path = tmp_path / "state.json"
    state = State(day="2026-05-13", tx_bytes_today=123, freeze_active=True, learned_safe_mbps=31)

    state.save(path)
    loaded = State.load(path)

    assert json.loads(path.read_text())["learned_safe_mbps"] == 31
    assert loaded == state


def test_apply_tc_dry_run_does_not_execute_commands(monkeypatch, capsys):
    cfg = Config(iface="eth0")

    def fail_if_called(cmd):
        raise AssertionError(f"should not execute {cmd}")

    monkeypatch.setattr("openx_netguard.netguard.run_command", fail_if_called)

    apply_tc(cfg, 9, dry_run=True)

    assert "tc qdisc replace dev eth0 clsact" in capsys.readouterr().out


def test_daemon_loop_applies_tc_only_when_limit_changes(monkeypatch, tmp_path):
    cfg_path = tmp_path / "config.json"
    state_path = tmp_path / "state.json"
    Config(iface="eth0", sample_interval_seconds=0).save(cfg_path)
    State(day="2026-05-13", learned_safe_mbps=8, last_applied_mbps=8).save(state_path)
    applied = []

    monkeypatch.setattr("openx_netguard.netguard.read_net_counters", lambda iface: (100, 100, 0))
    monkeypatch.setattr("openx_netguard.netguard.read_packet_counters", lambda iface: 10)
    monkeypatch.setattr("openx_netguard.netguard.read_tcp_retrans", lambda: 0)
    monkeypatch.setattr("openx_netguard.netguard.apply_tc", lambda cfg, mbps, dry_run=False: applied.append(mbps))

    daemon_loop(cfg_path, state_path, once=True, log_dir=tmp_path)

    assert applied == []


def test_metrics_aggregator_writes_five_minute_jsonl(tmp_path):
    cfg = Config(iface="eth0", metric_interval_seconds=300)
    state = State(day="2026-05-13")
    aggregator = MetricsAggregator(tmp_path)
    decision = Decision(target_mbps=35, freeze_active=False, notify_bark=False, reason="dynamic")

    aggregator.record(
        cfg,
        state,
        now=datetime(2026, 5, 13, 8, 4, tzinfo=timezone.utc),
        tx_delta=30_000_000,
        rx_delta=15_000_000,
        packet_delta=10_000,
        drop_delta=25,
        retrans_delta=5,
        decision=decision,
    )
    aggregator.record(
        cfg,
        state,
        now=datetime(2026, 5, 13, 8, 5, tzinfo=timezone.utc),
        tx_delta=1_000_000,
        rx_delta=2_000_000,
        packet_delta=100,
        drop_delta=0,
        retrans_delta=0,
        decision=decision,
    )

    path = tmp_path / "metrics-2026-05-13.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]

    assert rows[0]["window_start_bj"] == "2026-05-13T16:00:00+08:00"
    assert rows[0]["window_seconds"] == 300
    assert rows[0]["tx_bytes"] == 30_000_000
    assert rows[0]["rx_bytes"] == 15_000_000
    assert rows[0]["avg_tx_mbps"] == 0.8
    assert rows[0]["avg_rx_mbps"] == 0.4
    assert rows[0]["packet_loss_rate"] == 0.003
    assert rows[0]["target_mbps_avg"] == 35.0
    assert rows[0]["behavior"] == "dynamic"
    assert rows[0]["learned_ceiling_mbps"] == 8
    assert rows[0]["risk_score_ewma"] == 0.0
    assert rows[0]["baseline_health_ewma"] == 1.0
    assert rows[0]["rate_arms"] == {}
