# OpenX NetGuard

面向腾讯云轻量/锐驰型服务器的主动限速守护脚本。它用 `tc clsact + ifb + CAKE` 控制出入口速率，用北京时间日窗口管理出向流量预算，并在触发保护态后发送 Bark 提醒。

## 安装

公开 GitHub 一键安装：

```bash
curl -fsSL https://raw.githubusercontent.com/helloandworlder/openx-netguard/main/install.sh | sudo bash
```

指定分支或 fork：

```bash
curl -fsSL https://raw.githubusercontent.com/helloandworlder/openx-netguard/main/install.sh | sudo OPENX_NETGUARD_REF=main bash
```

本地源码安装：

```bash
sudo bash install-openx-netguard.sh
```

## 常用命令

```bash
openx-netguard status
openx-netguard config
openx-netguard freeze
openx-netguard thaw
journalctl -u openx-netguard -f
```

## 默认策略

- 最大出入口带宽：`50Mbps`
- 常态基准带宽：`8Mbps`
- 弹性升档：默认线性 `8 -> 9 -> 10 -> ... -> 50Mbps`，也可在配置里用 `boost_levels` 自定义
- 探测步长：默认 `8-15Mbps` 每次 `+1Mbps`，`15-25Mbps` 每次 `+2Mbps`，`25Mbps+` 每次 `+5Mbps`
- 决策粒度：默认每 `5 分钟` 决策一次，采样仍是 `30 秒`；无风险时同一决策桶内保持当前档位，风险信号可立即回退
- 每日北京时间出向目标：`90GB`
- 提前保护线：`88GB`
- 保护态出入口带宽：`4Mbps`
- 智能预算曲线：按北京时间小时权重分配全天流量，并以 10 分钟 bucket 评估，`02:00-08:00` 权重最低，白天和晚间权重更高
- 风险学习：CAKE/网卡 drop 是强风险信号；TCP 重传是轻权重辅助信号；实际吞吐明显低于目标且伴随传输风险时才判定疑似平台侧压速
- 每日报告：`/var/log/openx-netguard/daily-YYYY-MM-DD.md`
- 5 分钟聚合指标：`/var/log/openx-netguard/metrics-YYYY-MM-DD.jsonl`

## 5 分钟聚合指标

每条 JSONL 记录包含：

- 北京时间窗口：`window_start_bj`
- 出入流量：`tx_bytes`、`rx_bytes`
- 平均速度：`avg_tx_mbps`、`avg_rx_mbps`
- 丢包/重传：`drop_delta`、`tcp_retrans_delta`、`queue_drop_rate`、`tcp_retrans_rate`、`delivery_ratio`、`risk_components`
- 当前行为：`behavior`、`freeze_active`、`target_mbps_avg`
- 学习参数：`learned_safe_mbps`、`learned_ceiling_mbps`、`budget_pressure_ewma`、`risk_score_ewma`、`baseline_health_ewma`、`rate_arms`

这套策略只能尽量平滑流量和降低触发平台侧惩罚的概率，不能保证规避腾讯云未公开的限速规则。
