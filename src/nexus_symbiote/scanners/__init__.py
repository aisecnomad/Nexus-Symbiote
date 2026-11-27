"""Scanners discover agent supply chain components from project files.

Nexus-ShadowScan is the preferred primary discovery engine for multi-surface
agent inventory. The ShadowScanImporter consumes its reports. Local scanners
remain available for fine-grained, project-local verification, and the source
scanner reads what the project's own code and configuration declare.
"""

from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.scanners.prompt import PromptScanner
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.scanners.registry import RegistryScanner
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from nexus_symbiote.scanners.source import SourceScanner

ALL_SCANNERS: list[type[Scanner]] = [
    ShadowScanImporter,  # primary discovery
    MCPScanner,
    ModelScanner,
    PromptScanner,
    RAGScanner,
    RegistryScanner,
    A2AScanner,
    IDEAgentScanner,
    SourceScanner,
]

__all__ = [
    "ALL_SCANNERS",
    "A2AScanner",
    "IDEAgentScanner",
    "MCPScanner",
    "ModelScanner",
    "PromptScanner",
    "RAGScanner",
    "RegistryScanner",
    "Scanner",
    "ScanResult",
    "ShadowScanImporter",
    "SourceScanner",
]
