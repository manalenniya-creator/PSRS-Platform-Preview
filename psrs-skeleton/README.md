# PSRS — Network Supervision & Security Platform
### Engineering Case Study

---

## 1. Problem Statement

Small and medium-sized network infrastructures rarely have access to a
dedicated SOC (Security Operations Center). Intrusion detection is usually
scattered across isolated tools — a firewall here, an IDS there — with no
correlation and no unified interface for the operator.

**PSRS** (*Plateforme de Supervision Réseau & Sécurité*) explores a
lightweight, fully self-hosted alternative: it combines live packet capture,
threshold-based heuristic detection, IDS/IPS enforcement (Suricata, via
OPNsense), and a local conversational AI assistant to support the operator's
decisions — with no dependency on any third-party cloud service.

## 2. System Architecture

```
LAN network traffic
   │
   ├─► sniffer.py  (Scapy capture, LAN-only BPF filter)
   │        │
   └─► OPNsense ─► Suricata (IDS/IPS, eve.json)
            │
            ▼
   Backend — Node.js / Express
   ├─ Detection engine (threshold + heuristic classification)
   ├─ REST API (logs, alerts, users, firewall control)
   ├─ MongoDB (persistence)
   └─ SSH → OPNsense (reads Suricata logs, automatic ban / unban)
            │
   ┌────────┼──────────────┐
   ▼        ▼               ▼
Frontend   AI Assistant   Notifications
(React)    (local Ollama) (Email / Telegram)
```

**Data flow, end to end:**
1. `sniffer.py` captures LAN-to-LAN packets with a BPF filter and forwards
   parsed traffic events to the backend via `POST /api/logs/add`.
2. In parallel, Suricata (running on OPNsense) inspects the same traffic and
   writes its alerts to `eve.json`; the backend reads this file over SSH.
3. The **Detection Engine** evaluates sliding-window counters against a set
   of rules and raises alerts when a rule fires.
4. Alerts are persisted in MongoDB, pushed to the React dashboard in near
   real time, sent to the operator by Email/Telegram, and — for critical
   severities — trigger an automatic IP ban on OPNsense via SSH.
5. The operator can query the local AI assistant for a plain-language
   explanation of an alert and a short, concrete recommendation.

## 3. Detection Engine — Methodology

The core logic lives in a pure, side-effect-free module
(`evaluateThreat()`), deliberately separated from the code that fetches
counters from MongoDB or triggers actions (alert creation, OPNsense ban).
This separation makes the detection logic unit-testable in isolation.

| Rule | Condition | Severity | Action |
|---|---|---|---|
| Abnormal traffic | ≥ 10 packets / 30 s from the same IP | High | Alert |
| ICMP flood | ≥ 8 ICMP packets / 30 s | Medium | Alert |
| TCP flood / port scan | ≥ 20 TCP packets / 60 s | Critical | Alert + automatic OPNsense ban |
| Repeated suspicious traffic | ≥ 5 occurrences classified "suspicious" / 60 s | Medium | Alert |

**Threshold justification.** The values are empirical, tuned by observing
real Nmap scans (SYN scan, aggressive `--min-rate`) against normal
single-user traffic. They are a starting point rather than a validated
model — a rigorous evaluation would require a labeled dataset (see §6).

A **cooldown window** (60 s per IP / alert-type pair) prevents the same
ongoing attack from generating duplicate alerts.

## 4. False-Positive Reduction

Two complementary filtering layers keep noise down:

1. **BPF filter at capture time** (`sniffer.py`): only traffic whose source
   *and* destination both belong to the local subnet is captured. This
   removes, by construction, the host machine's own Internet traffic
   (browsing, updates, etc.), which always has one local endpoint and would
   otherwise generate false positives.
2. **Backend allow-list** (`WHITELIST_IPS` in `.env`): a defense-in-depth
   layer that excludes trusted IPs (gateway, internal DNS) independently of
   the sniffer, in case of misconfiguration upstream.

## 5. Traffic Classification

A separate, rule-based `TrafficClassifier` maps each flow to a
human-readable category (Web, DNS, Mail, Remote Access, Database, File
Transfer, VoIP, P2P, Diagnostic, Suspicious, Other) using protocol and
source/destination ports, based on an IANA well-known-ports table extended
with the services most relevant to network supervision.

This is intentionally an **expert rule system, not a trained ML model** —
which makes it fast, deterministic, and fully auditable, a property that
matters for SOC-style tooling. It exposes a stable interface
(`classifyTraffic`), so it can later be swapped for a real ML classifier
(e.g., scikit-learn / TensorFlow served via an API) without changing the
rest of the pipeline.

## 6. AI Assistant

An in-app assistant, backed by a **quantized Qwen3 model served locally
through Ollama** (no API key, no per-token cost, no data leaving the
machine), helps the operator interpret an alert: type of attack, likely
cause, and a short, concrete recommendation (ban the IP, monitor, check a
specific service). The system prompt constrains the assistant to stay
factual and concise, and to ask for clarification rather than guess when
information is missing.

## 7. Notifications & Automated Response

- **Email (SMTP) and Telegram** notifications, each independently
  toggleable and gated by a configurable minimum severity
  (`NOTIFY_MIN_SEVERITY`).
- **Automatic IP ban** on OPNsense over SSH for Critical-severity alerts,
  with a matching manual ban/unban action exposed in the dashboard.

## 8. Frontend

A React (Vite) dashboard provides a real-time view of the network state:
live alert feed, traffic/log visualization (Recharts), incident management,
and firewall controls — talking to the backend exclusively through the REST
API, with the detection/business logic staying server-side.

## 9. Known Limitations & Future Work

- **Fixed-threshold detection** is context-sensitive: a threshold tuned on
  a test LAN won't necessarily hold in production. A natural next step is
  to complement these rules with unsupervised anomaly detection (e.g., an
  Isolation Forest over flow-level features — packet rate, destination-port
  entropy, etc.).
- **No labeled dataset** currently exists to measure the detection engine's
  precision/recall. Building one (normal traffic + replayed Nmap/hping3
  attacks) is the natural next step toward a quantitative evaluation.
- **Single-host sniffer**: traffic capture is limited to what's visible
  from the host machine's interface. A multi-segment deployment would need
  port mirroring (SPAN) or multiple distributed sensors.
- **No automated test suite** yet beyond the detection-engine unit tests.

## 10. Technology Stack

| Layer | Technology |
|---|---|
| Backend | Node.js, Express, MongoDB (Mongoose), JWT auth, SSH2 (OPNsense integration) |
| Frontend | React 18, Vite, Recharts |
| Packet capture | Python, Scapy, BPF filtering |
| IDS/IPS | Suricata, integrated with OPNsense |
| AI Assistant | Ollama, Qwen3 (local inference) |
| Notifications | Nodemailer (SMTP), Telegram Bot API |

## 11. Engineering Takeaways

- Separating **pure detection logic** from I/O and side effects (MongoDB
  fetches, OPNsense actions) keeps the core rules testable and easy to
  reason about — a small design decision with an outsized payoff for a
  security tool where correctness matters.
- Filtering *before* detection (the BPF layer) is cheaper and more
  reliable than filtering *after* — it eliminates a whole class of false
  positives structurally rather than patching around them downstream.
- Keeping the AI assistant **local and advisory** (not autonomous) avoids
  both a cloud dependency and any risk of an LLM taking unsupervised action
  on the network — it explains and recommends; the operator decides.