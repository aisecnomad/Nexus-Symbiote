"""Enumerations for Nexus SymBiote AgentBOM component classification."""

from enum import Enum


class ComponentType(str, Enum):
    AGENT = "agent"
    MCP_SERVER = "mcp-server"
    MCP_CLIENT = "mcp-client"
    TOOL = "tool"
    MODEL = "model"
    PROMPT_TEMPLATE = "prompt-template"
    GUARDRAIL_POLICY = "guardrail-policy"
    MEMORY_STORE = "memory-store"
    RAG_SOURCE = "rag-source"
    DATA_SOURCE = "data-source"
    REGISTRY_ENTRY = "registry-entry"
    SKILL_PACKAGE = "skill-package"
    A2A_CLIENT = "a2a-client"
    A2A_SERVER = "a2a-server"
    IDE_AGENT = "ide-agent"
    VERIFIED_EXTENSION = "verified-extension"
    CREDENTIAL = "credential"


class AssuranceLevel(str, Enum):
    DECLARED = "declared"
    OBSERVED = "observed"
    VERIFIED = "verified"


class TrustTier(str, Enum):
    INTERNAL_VERIFIED = "internal-verified"
    INTERNAL_UNVERIFIED = "internal-unverified"
    THIRD_PARTY_SIGNED = "third-party-signed"
    THIRD_PARTY_UNSIGNED = "third-party-unsigned"
    UNTRUSTED_PUBLIC = "untrusted-public"
    UNKNOWN = "unknown"


class CapabilityClass(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    PAYMENT = "payment"
    CREDENTIALS = "credentials"
    DESTRUCTIVE = "destructive"


class SerializationSafety(str, Enum):
    SAFE = "safe"
    UNSAFE_CODE_EXECUTION = "unsafe-code-execution"
    UNSAFE_TEMPLATE_INJECTION = "unsafe-template-injection"
    UNKNOWN = "unknown"


class RiskSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AutonomyLevel(str, Enum):
    L0_CHATBOT = "L0-chatbot"
    L1_COPILOT = "L1-copilot"
    L2_AGENT = "L2-agent"
    L3_AUTONOMOUS = "L3-autonomous"
    L4_FULLY_AUTONOMOUS = "L4-fully-autonomous"


class SideEffectProfile(str, Enum):
    READ_ONLY = "read-only"
    STATE_MODIFYING = "state-modifying"
    DESTRUCTIVE = "destructive"
    FINANCIAL_TRANSACTION = "financial-transaction"
    UNKNOWN = "unknown"


class ExecutionIsolation(str, Enum):
    NONE = "none"
    PROCESS = "process"
    CONTAINER = "container"
    WASM = "wasm"
    MICROVM = "microvm"
    GVISOR = "gvisor"


class HumanInTheLoop(str, Enum):
    REQUIRED = "required"
    CONDITIONAL = "conditional"
    NONE = "none"
