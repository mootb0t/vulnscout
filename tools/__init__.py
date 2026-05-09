"""Tools subpackage — subprocess orchestration, output parsing, PATH checks.

Re-exports the most commonly used names so callers can write
`from vulnscout.tools import stream, parse_nmap_xml, is_available`.
"""

from .runner import (
    INSECURE_TLS_ENV,
    PhaseEvent,
    ScanContext,
    ScanState,
    adapt_nmap_args,
    running_as_root,
    stream,
)
from .parser import (
    NmapPort,
    NmapResult,
    derive_severity,
    detect_target_type,
    extract_domain,
    format_nmap_summary,
    looks_like_xml,
    parse_nmap_xml,
    parse_nuclei_jsonl,
    parse_searchsploit_table,
    validate_target,
)
from .toolcheck import ToolStatus, check_tools, is_available

__all__ = [
    "INSECURE_TLS_ENV",
    "NmapPort",
    "NmapResult",
    "PhaseEvent",
    "ScanContext",
    "ScanState",
    "ToolStatus",
    "adapt_nmap_args",
    "check_tools",
    "derive_severity",
    "detect_target_type",
    "extract_domain",
    "format_nmap_summary",
    "is_available",
    "looks_like_xml",
    "parse_nmap_xml",
    "parse_nuclei_jsonl",
    "parse_searchsploit_table",
    "running_as_root",
    "stream",
    "validate_target",
]
