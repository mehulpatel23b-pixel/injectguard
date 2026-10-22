"""injectguard — zero-dependency prompt-injection scanner.

Scan text for LLM prompt-injection and jailbreak patterns before it
reaches your model or agent. Library and CLI, Python stdlib only.
"""

from .scanner import Finding, Report, scan_text, scan_report
from .rules import RULES, RULE_VERSION

__version__ = "1.0.0"
__all__ = [
    "Finding",
    "Report",
    "scan_text",
    "scan_report",
    "RULES",
    "RULE_VERSION",
]
