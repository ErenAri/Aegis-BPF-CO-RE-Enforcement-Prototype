# Metrics Operations Guide

This guide maps key metrics to operator actions. Use it with alert rules in
`config/prometheus/alerts.yml` and runbooks in `docs/runbooks/`.

## Cardinality policy

- Keep production scraping to low-cardinality metrics (`aegisbpf metrics`).
- Use `--detailed` metrics only for short-lived debugging sessions.
- Never persist unbounded labels (`path`, `pid`, `inode`, `ip`) in Prometheus.

## Metric interpretation and action

| Metric | Warning | Critical | Action |
|---|---|---|---|
| `aegisbpf_ringbuf_drops_total` rate | `> 0` for 1m | sustained growth 5m+ | Follow `ALERT_ringbuf_drops.md`; increase ring buffer, reduce event volume |
| `aegisbpf_blocks_total` rate | sudden step-up vs baseline | sustained high rate with service impact | Follow `ALERT_high_block_rate.md`; validate policy, inspect false positives |
| `aegisbpf_policy_apply_errors_total` | any non-zero after rollout | repeated failures blocking deploy | Follow `ALERT_policy_apply_failed.md`; verify syntax/signature/version |
| `up{job=\"aegisbpf\"}` | single scrape miss | `0` for 1m+ | Follow `INCIDENT_agent_crash.md`; restart and collect incident bundle |
| Event-loss SLO proxy (`ringbuf_drops/blocks`) | >0.1% rolling | >1% rolling | Treat as degraded detection quality; throttle debug collection |

## SLO signals

Initial production targets:
- Availability: 99.9% (`agent running` AND `BPF attached`)
- Event delivery: 99.5% (`1 - drops/total_events`)
- Policy apply latency: p99 < 5s for 1000 rules
- Block decision latency: p99 < 1ms kernel decision path

If SLO burns, create incident and attach:
- `aegisbpf health --json`
- `aegisbpf metrics`
- `aegisbpf policy show`
- recent service logs and deploy context

## Operator response flow

1. Confirm mode/capability: enforce vs audit-only (`aegisbpf health`).
2. Check if impact is detection-only (drops) or prevention (blocking anomalies).
3. Route to runbook:
   - Drops -> `ALERT_ringbuf_drops.md`
   - Block spike -> `ALERT_high_block_rate.md`
   - Policy rollout failure -> `ALERT_policy_apply_failed.md`
   - Agent unavailable -> `INCIDENT_agent_crash.md`
4. Record incident evidence bundle for postmortem and control tuning.

## Deployment guardrails

- Gate production rollout on canary + soak success.
- Keep dashboard thresholds under version control.
- Review alert thresholds quarterly with security + SRE owners.
