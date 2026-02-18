"""
air-autogen-trust — AIR Trust Layer for Microsoft AutoGen / AG2

Drop-in security, audit, and compliance for AutoGen multi-agent systems.
"""

from .config import (
    RISK_ORDER,
    AirTrustConfig,
    AuditLedgerConfig,
    ConsentGateConfig,
    InjectionDetectionConfig,
    RiskLevel,
    VaultConfig,
)
from .errors import AirTrustError, ConsentDeniedError, InjectionBlockedError
from .plugin import AirTrustPlugin

__all__ = [
    "AirTrustPlugin",
    "AirTrustConfig",
    "AirTrustError",
    "AuditLedgerConfig",
    "ConsentDeniedError",
    "ConsentGateConfig",
    "InjectionBlockedError",
    "InjectionDetectionConfig",
    "RISK_ORDER",
    "RiskLevel",
    "VaultConfig",
]
