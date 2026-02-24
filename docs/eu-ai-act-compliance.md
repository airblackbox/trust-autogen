# AIR Blackbox — EU AI Act Compliance Mapping

## The Problem

The EU AI Act enters enforcement for **high-risk AI systems on August 2, 2026**. Companies deploying AI agents — tool-calling LLMs that take actions autonomously — face mandatory requirements around logging, transparency, human oversight, and data governance.

Most compliance platforms target CISOs with top-down dashboards. **Nobody is giving developers the building blocks to make their agents compliant by default.**

> **Note**: The European Commission's Digital Omnibus proposal (late 2025) could postpone Annex III high-risk obligations to December 2027, but formal adoption is pending. Prudent compliance planning treats August 2, 2026 as the binding deadline. Penalties: up to €35M or 7% of worldwide turnover for prohibited practices, up to €15M or 3% for other infringements.

AIR Blackbox is the compliance infrastructure layer for AI agents. Drop-in SDKs that make your agent stack EU AI Act compliant — the same way Stripe made payments PCI compliant.

---

## Compliance Matrix

### Article 9 — Risk Management System

| Requirement | AIR Blackbox Feature | Component |
|---|---|---|
| Identify and analyze known/foreseeable risks | **ConsentGate** — classifies every tool call by risk level | ConsentGate |
| Estimate and evaluate risks from intended use | **Tool risk registry** — configurable risk levels per tool | AirTrustConfig |
| Adopt suitable risk management measures | **Blocking policies** — configurable consent modes | ConsentGate |
| Residual risk below acceptable level | **Audit trail** proves risk decisions were enforced at runtime | AuditLedger |

### Article 10 — Data and Data Governance

| Requirement | AIR Blackbox Feature | Component |
|---|---|---|
| Data governance and management practices | **DataVault** — tokenizes PII before it enters the LLM pipeline | DataVault |
| Examination for possible biases | **Audit logs capture every prompt and response** | AuditLedger |
| Appropriate data minimization measures | **PII stripping** — SSNs, credit cards, emails, API keys auto-redacted | DataVault |

### Article 11 — Technical Documentation

| Requirement | AIR Blackbox Feature | Component |
|---|---|---|
| General description of the AI system | **Structured audit log** with timestamps | AuditLedger |
| Detailed description of system elements | **Full call graph capture** | Trust callback/hook handler |
| Monitoring, functioning, control | **HMAC-SHA256 tamper-evident chain** | AuditLedger.verify_chain() |

### Article 12 — Record-Keeping

| Requirement | AIR Blackbox Feature | Component |
|---|---|---|
| Automatic recording of events | **Timestamped entries** for every operation (ISO 8601) | AuditLedger |
| Reference database against which input data is checked | **Consent decisions logged** with tool name, risk level, allow/deny | AuditLedger |
| Input data for which the search has led to a match | **Injection detection results logged** | InjectionDetector |

**Key differentiator**: HMAC-SHA256 chaining. Each log entry's hash includes the previous entry's hash. Break the chain = detectable.

### Article 14 — Human Oversight

| Requirement | AIR Blackbox Feature | Component |
|---|---|---|
| Fully understand the AI system | **Complete audit trail** | AuditLedger |
| Correctly interpret the output | **Tokenized logging** — sensitive data masked, decision flow visible | DataVault + AuditLedger |
| Ability to override the AI system | **Consent gate** — humans define tool policies | ConsentGate |
| Ability to intervene or interrupt | **Exception-based blocking** halts execution immediately | ConsentDeniedError |

### Article 15 — Accuracy, Robustness, Cybersecurity

| Requirement | AIR Blackbox Feature | Component |
|---|---|---|
| Resilient against unauthorized alteration | **InjectionDetector** scans all prompts | InjectionDetector |
| Technically redundant solutions | **Multi-layer defense** — all components independent | Full trust stack |
| Cybersecurity measures proportionate to risks | **Configurable per deployment** | AirTrustConfig |

---

## Framework Coverage

| Framework | Package | Install |
|---|---|---|
| **LangChain / LangGraph** | `air-langchain-trust` | `pip install air-langchain-trust` |
| **CrewAI** | `air-crewai-trust` | `pip install air-crewai-trust` |
| **OpenAI Agents SDK** | `air-openai-agents-trust` | `pip install air-openai-agents-trust` |
| **AutoGen / AG2** | `air-autogen-trust` | `pip install air-autogen-trust` |
| **TypeScript / Node.js** | `openclaw-air-trust` | `npm install openclaw-air-trust` |
| **Any HTTP agent** | Gateway | `docker pull ghcr.io/airblackbox/gateway:main` |
| **Compliance Scanner** | `air-compliance` | `pip install air-compliance` |

See [full compliance mapping](https://github.com/airblackbox/air-langchain-trust/blob/main/docs/eu-ai-act-compliance.md) for detailed article-by-article breakdown.
