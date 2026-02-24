# air-autogen-trust

[![CI](https://github.com/airblackbox/trust-autogen/actions/workflows/ci.yml/badge.svg)](https://github.com/airblackbox/trust-autogen/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://github.com/airblackbox/trust-autogen/blob/main/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB.svg?logo=python&logoColor=white)](https://python.org)


**EU AI Act compliance infrastructure for Microsoft AutoGen / AG2.** Drop-in trust layer that adds tamper-evident audit logging, PII tokenization, consent-based tool gating, and prompt injection detection — making your AutoGen agent stack compliant with Articles 9, 10, 11, 12, 14, and 15 of the EU AI Act.

Part of the [AIR Blackbox](https://github.com/airblackbox) ecosystem — the compliance layer for autonomous AI agents.

> The EU AI Act enforcement date for high-risk AI systems is **August 2, 2026**. See the [full compliance mapping](./docs/eu-ai-act-compliance.md) for article-by-article coverage.

## Quick Start

pip install air-autogen-trust

```python
from autogen import AssistantAgent, UserProxyAgent
from air_autogen_trust import AirTrustPlugin

# Create the trust plugin
plugin = AirTrustPlugin()

# Create your agents
assistant = AssistantAgent(name="assistant", llm_config=llm_config)
user_proxy = UserProxyAgent(name="user_proxy")

# Install trust hooks on all agents
plugin.install(assistant)
plugin.install(user_proxy)

# Run your multi-agent conversation — all calls are now audited
user_proxy.initiate_chat(assistant, message="Write a Python script")

# Check what happened
print(plugin.get_audit_stats())
print(plugin.verify_chain())
```

## What It Does

### Tamper-Proof Audit Trail
Every tool call, LLM invocation, and inter-agent message is logged to an HMAC-SHA256 signed chain. Each entry references the previous entry's hash — modify any record and the chain breaks.

### Sensitive Data Tokenization
API keys, credentials, PII (emails, SSNs, phone numbers, credit cards) are automatically detected in tool inputs, LLM prompts, and agent messages. **14 built-in patterns** covering API keys, credentials, and PII.

### Consent Gate
Destructive tools are blocked until the user explicitly approves them. The plugin raises `ConsentDeniedError` to halt execution:

```python
from air_autogen_trust import ConsentDeniedError, InjectionBlockedError

try:
    user_proxy.initiate_chat(assistant, message="Deploy to production")
except ConsentDeniedError as e:
    print(f"Tool '{e.tool_name}' blocked (risk: {e.risk_level})")
except InjectionBlockedError as e:
    print(f"Injection detected (score: {e.score})")
```

### Prompt Injection Detection
15+ weighted patterns detect prompt injection attempts including role overrides, jailbreaks, delimiter injection, privilege escalation, and data exfiltration.

## AutoGen Hook Mapping

| AutoGen Hook | Trust Components |
|-------------|-----------------|
| `safeguard_tool_inputs` | ConsentGate → DataVault → AuditLedger |
| `safeguard_tool_outputs` | DataVault → AuditLedger |
| `safeguard_llm_inputs` | InjectionDetector → DataVault → AuditLedger |
| `safeguard_llm_outputs` | DataVault → AuditLedger |
| `process_message_before_send` | DataVault → AuditLedger |

## Configuration

```python
from air_autogen_trust import AirTrustPlugin, AirTrustConfig

config = AirTrustConfig(
    consent_gate={"enabled": True, "risk_threshold": "high"},
    vault={"enabled": True, "categories": ["api_key", "credential", "pii"]},
    injection_detection={"enabled": True, "sensitivity": "medium", "block_threshold": 0.8},
    audit_ledger={"enabled": True, "max_entries": 10000},
    gateway_url="https://your-gateway.example.com",
    gateway_key="your-api-key",
)

plugin = AirTrustPlugin(config=config)
```

## Works with GroupChat

```python
from autogen import GroupChat, GroupChatManager

plugin = AirTrustPlugin()

# Install on all agents in the group
for agent in [agent1, agent2, agent3]:
    plugin.install(agent)

groupchat = GroupChat(agents=[agent1, agent2, agent3])
manager = GroupChatManager(groupchat=groupchat)
plugin.install(manager)
```

## API Reference

```python
plugin.get_audit_stats()      # Chain statistics
plugin.verify_chain()          # Verify chain integrity
plugin.export_audit()          # Export all entries
plugin.get_vault_stats()       # Vault statistics
plugin.get_installed_agents()  # List of installed agent names
```

## EU AI Act Compliance

| EU AI Act Article | Requirement | AIR Feature |
|---|---|---|
| Art. 9 | Risk management | ConsentGate risk classification |
| Art. 10 | Data governance | DataVault PII tokenization |
| Art. 11 | Technical documentation | Full call graph audit logging |
| Art. 12 | Record-keeping | HMAC-SHA256 tamper-evident chain |
| Art. 14 | Human oversight | Consent-based tool blocking |
| Art. 15 | Robustness & security | InjectionDetector + multi-layer defense |

See [docs/eu-ai-act-compliance.md](./docs/eu-ai-act-compliance.md) for the full article-by-article mapping.

## AIR Blackbox Ecosystem

| Package | Framework | Install |
|---|---|---|
| `air-langchain-trust` | LangChain / LangGraph | `pip install air-langchain-trust` |
| `air-crewai-trust` | CrewAI | `pip install air-crewai-trust` |
| `air-openai-agents-trust` | OpenAI Agents SDK | `pip install air-openai-agents-trust` |
| `air-autogen-trust` | Microsoft AutoGen | `pip install air-autogen-trust` |
| `openclaw-air-trust` | TypeScript / Node.js | `npm install openclaw-air-trust` |
| `air-compliance` | Compliance checker CLI | `pip install air-compliance` |
| Gateway | Any HTTP agent | `docker pull ghcr.io/airblackbox/gateway:main` |

## Development

```bash
git clone https://github.com/airblackbox/trust-autogen.git
cd trust-autogen
pip install -e ".[dev]"
pytest tests/ -v
```

## License

Apache-2.0
