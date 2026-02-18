"""
air-autogen-trust — AutoGen Plugin

Integrates the AIR Trust Layer with Microsoft AutoGen / AG2.

AutoGen's ConversableAgent has 9 hook points including:
  - safeguard_tool_inputs / safeguard_tool_outputs
  - safeguard_llm_inputs / safeguard_llm_outputs
  - process_message_before_send
  - process_all_messages_before_reply

The plugin registers hooks via agent.register_hook() and raises
exceptions (ConsentDeniedError, InjectionBlockedError) to block
operations when trust checks fail.

Usage:
    from autogen import AssistantAgent
    from air_autogen_trust import AirTrustPlugin

    plugin = AirTrustPlugin()
    agent = AssistantAgent(name="assistant", llm_config=llm_config)
    plugin.install(agent)

    # All tool calls, LLM calls, and messages are now audited
"""

from __future__ import annotations

import json
from typing import Any

from .audit_ledger import AuditLedger
from .config import AirTrustConfig
from .consent_gate import ConsentGate
from .data_vault import DataVault
from .errors import ConsentDeniedError, InjectionBlockedError
from .injection_detector import InjectionDetector


class AirTrustPlugin:
    """
    AIR Trust Layer plugin for Microsoft AutoGen / AG2.

    Registers hooks on ConversableAgent instances to provide:
    - Tamper-evident HMAC-SHA256 audit trails
    - Sensitive data tokenization (API keys, PII, credentials)
    - Consent gates for destructive tool calls
    - Prompt injection detection and blocking
    """

    def __init__(
        self,
        config: AirTrustConfig | None = None,
        consent_prompt_fn: Any | None = None,
    ) -> None:
        self.config = config or AirTrustConfig()
        self._consent_prompt_fn = consent_prompt_fn
        self._installed_agents: list[str] = []

        if not self.config.enabled:
            self.ledger = None
            self.vault = None
            self.consent_gate = None
            self.detector = None
            return

        # Initialize components
        self.ledger = AuditLedger(
            self.config.audit_ledger,
            gateway_url=self.config.gateway_url,
            gateway_key=self.config.gateway_key,
        )
        self.vault = DataVault(
            self.config.vault,
            gateway_url=self.config.gateway_url,
            gateway_key=self.config.gateway_key,
        )
        self.consent_gate = ConsentGate(self.config.consent_gate, self.ledger)
        self.detector = InjectionDetector(self.config.injection_detection)

    def install(self, agent: Any) -> None:
        """
        Install trust hooks on an AutoGen ConversableAgent.

        Registers hooks for:
        - safeguard_tool_inputs: consent gate + data vault
        - safeguard_tool_outputs: audit logging
        - safeguard_llm_inputs: injection detection + data vault
        - safeguard_llm_outputs: audit logging
        - process_message_before_send: message audit trail

        Args:
            agent: An AutoGen ConversableAgent (or subclass).
        """
        if not self.config.enabled:
            return

        agent_name = getattr(agent, "name", str(id(agent)))
        self._installed_agents.append(agent_name)

        agent.register_hook("safeguard_tool_inputs", self._safeguard_tool_inputs)
        agent.register_hook("safeguard_tool_outputs", self._safeguard_tool_outputs)
        agent.register_hook("safeguard_llm_inputs", self._safeguard_llm_inputs)
        agent.register_hook("safeguard_llm_outputs", self._safeguard_llm_outputs)
        agent.register_hook(
            "process_message_before_send", self._process_message_before_send
        )

    def uninstall(self, agent: Any) -> None:
        """Remove this plugin's record of an agent (hooks remain registered)."""
        agent_name = getattr(agent, "name", str(id(agent)))
        if agent_name in self._installed_agents:
            self._installed_agents.remove(agent_name)

    # ------------------------------------------------------------------
    # Hook implementations
    # ------------------------------------------------------------------

    def _safeguard_tool_inputs(self, tool_input: Any) -> Any:
        """
        Hook: safeguard_tool_inputs

        Runs BEFORE a tool/function executes. Applies:
        1. Consent gate — blocks destructive tools pending approval
        2. Data vault — tokenizes sensitive data in arguments
        3. Audit ledger — logs the tool call
        """
        if not self.config.enabled:
            return tool_input

        # Extract tool name and args from the input
        tool_name, tool_args = self._parse_tool_input(tool_input)

        # 1. Consent gate
        if self.config.consent_gate.enabled and self.consent_gate:
            result = self.consent_gate.intercept(
                tool_name, tool_args, prompt_fn=self._consent_prompt_fn
            )
            if result.get("blocked"):
                risk = self.consent_gate.classify_risk(tool_name)
                raise ConsentDeniedError(tool_name, risk.value)

        # 2. Data vault — tokenize sensitive data in the input
        tokenized = False
        if self.config.vault.enabled and self.vault:
            input_str = json.dumps(tool_args) if isinstance(tool_args, dict) else str(tool_input)
            vault_result = self.vault.tokenize(input_str)
            tokenized = vault_result["tokenized"]

        # 3. Audit ledger
        if self.config.audit_ledger.enabled and self.ledger:
            risk_level = "none"
            if self.consent_gate:
                risk_level = self.consent_gate.classify_risk(tool_name).value
            self.ledger.append(
                action="tool_call_start",
                tool_name=tool_name,
                risk_level=risk_level,
                data_tokenized=tokenized,
                metadata={"agent": "autogen"},
            )

        return tool_input


    def _safeguard_tool_outputs(self, tool_output: Any) -> Any:
        """
        Hook: safeguard_tool_outputs

        Runs AFTER a tool/function executes. Logs the result.
        """
        if not self.config.enabled:
            return tool_output

        # Tokenize output for audit
        tokenized = False
        if self.config.vault.enabled and self.vault:
            output_str = str(tool_output)
            vault_result = self.vault.tokenize(output_str)
            tokenized = vault_result["tokenized"]

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="tool_call_end",
                data_tokenized=tokenized,
                metadata={"agent": "autogen"},
            )

        return tool_output

    def _safeguard_llm_inputs(self, llm_input: Any) -> Any:
        """
        Hook: safeguard_llm_inputs

        Runs BEFORE an LLM call. Applies:
        1. Injection detection — scans for prompt injection patterns
        2. Data vault — tokenizes sensitive data in prompts
        3. Audit ledger — logs the LLM call
        """
        if not self.config.enabled:
            return llm_input

        # Extract text content for scanning
        content = self._extract_llm_content(llm_input)

        # 1. Injection detection
        injection_detected = False
        if self.config.injection_detection.enabled and self.detector and content:
            scan_result = self.detector.scan(content)
            injection_detected = scan_result.detected  # noqa: F841

            if scan_result.blocked:
                # Log before blocking
                if self.config.audit_ledger.enabled and self.ledger:
                    self.ledger.append(
                        action="injection_blocked",
                        injection_detected=True,
                        metadata={
                            "score": scan_result.score,
                            "patterns": scan_result.patterns,
                            "agent": "autogen",
                        },
                    )
                raise InjectionBlockedError(scan_result.score, scan_result.patterns)

        # 2. Data vault
        tokenized = False
        if self.config.vault.enabled and self.vault and content:
            vault_result = self.vault.tokenize(content)
            tokenized = vault_result["tokenized"]

        # 3. Audit ledger
        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="llm_call_start",
                data_tokenized=tokenized,
                injection_detected=injection_detected,
                metadata={"agent": "autogen"},
            )

        return llm_input

    def _safeguard_llm_outputs(self, llm_output: Any) -> Any:
        """
        Hook: safeguard_llm_outputs

        Runs AFTER an LLM call returns. Logs the result.
        """
        if not self.config.enabled:
            return llm_output

        tokenized = False
        if self.config.vault.enabled and self.vault:
            output_str = self._extract_llm_content(llm_output) or str(llm_output)
            vault_result = self.vault.tokenize(output_str)
            tokenized = vault_result["tokenized"]

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="llm_call_end",
                data_tokenized=tokenized,
                metadata={"agent": "autogen"},
            )

        return llm_output

    def _process_message_before_send(
        self,
        sender: Any,
        message: Any,
        recipient: Any,
        silent: bool,
    ) -> Any:
        """
        Hook: process_message_before_send

        Runs BEFORE a message is sent between agents. Logs the
        inter-agent message for audit trail.
        """
        if not self.config.enabled:
            return message

        sender_name = getattr(sender, "name", "unknown") if sender else "unknown"
        recipient_name = (
            getattr(recipient, "name", "unknown") if recipient else "unknown"
        )

        # Tokenize message content
        tokenized = False
        if self.config.vault.enabled and self.vault:
            msg_str = (
                json.dumps(message)
                if isinstance(message, dict)
                else str(message)
            )
            vault_result = self.vault.tokenize(msg_str)
            tokenized = vault_result["tokenized"]

        if self.config.audit_ledger.enabled and self.ledger:
            self.ledger.append(
                action="message_send",
                data_tokenized=tokenized,
                metadata={
                    "sender": sender_name,
                    "recipient": recipient_name,
                    "agent": "autogen",
                },
            )

        return message

    # ------------------------------------------------------------------
    # Public inspection API
    # ------------------------------------------------------------------

    def get_audit_stats(self) -> dict:
        """Get audit chain statistics."""
        if not self.ledger:
            return {"enabled": False}
        return self.ledger.stats()

    def verify_chain(self) -> dict:
        """Verify the integrity of the audit chain."""
        if not self.ledger:
            return {"enabled": False}
        return self.ledger.verify().to_dict()

    def export_audit(self) -> list[dict]:
        """Export all audit entries."""
        if not self.ledger:
            return []
        return self.ledger.export()

    def get_vault_stats(self) -> dict:
        """Get data vault statistics."""
        if not self.vault:
            return {"enabled": False}
        return self.vault.stats()

    def get_installed_agents(self) -> list[str]:
        """Get list of agent names this plugin is installed on."""
        return list(self._installed_agents)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_tool_input(tool_input: Any) -> tuple[str, dict]:
        """Extract tool name and arguments from AutoGen tool input."""
        if isinstance(tool_input, dict):
            # AutoGen passes function calls as dicts with "name" and "arguments"
            name = tool_input.get("name", tool_input.get("tool_name", "unknown"))
            args = tool_input.get("arguments", tool_input.get("args", {}))
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except (json.JSONDecodeError, TypeError):
                    args = {"raw": args}
            return name, args
        elif isinstance(tool_input, str):
            try:
                parsed = json.loads(tool_input)
                if isinstance(parsed, dict):
                    return parsed.get("name", "unknown"), parsed.get("arguments", {})
            except (json.JSONDecodeError, TypeError):
                pass
            return "unknown", {"raw": tool_input}
        return "unknown", {}

    @staticmethod
    def _extract_llm_content(llm_data: Any) -> str | None:
        """Extract text content from LLM input/output for scanning."""
        if isinstance(llm_data, str):
            return llm_data
        if isinstance(llm_data, list):
            # List of messages
            parts = []
            for item in llm_data:
                if isinstance(item, dict):
                    content = item.get("content", "")
                    if content:
                        parts.append(str(content))
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts) if parts else None
        if isinstance(llm_data, dict):
            content = llm_data.get("content", "")
            if content:
                return str(content)
            # Try choices format
            choices = llm_data.get("choices", [])
            if choices:
                parts = []
                for choice in choices:
                    msg = choice.get("message", {})
                    c = msg.get("content", "")
                    if c:
                        parts.append(str(c))
                return "\n".join(parts) if parts else None
        return None
