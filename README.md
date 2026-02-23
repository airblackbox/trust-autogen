# air-autogen-trust

**AIR Trust Layer for Microsoft AutoGen / AG2** — Drop-in security, audit, and compliance for multi-agent systems.

Part of the [AIR Blackbox](https://airblackbox.com) ecosystem. Adds tamper-proof audit trails, sensitive data tokenization, consent gates for destructive tools, and prompt injection detection to any AutoGen project.

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

## AIR Blackbox Ecosystem

| Repository | Purpose |
|-----------|---------|
| [gateway](https://github.com/airblackbox/gateway) | Go proxy gateway |
| [trust-crewai](https://github.com/airblackbox/trust-crewai) | Trust layer for CrewAI |
| [trust-langchain](https://github.com/airblackbox/trust-langchain) | Trust layer for LangChain |
| **trust-autogen** | **Trust layer for AutoGen** (this repo) |

## Development

```bash
git clone https://github.com/airblackbox/trust-autogen.git
cd trust-autogen
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
