"""Detection rules for injectguard.

Each rule is a compiled regex with metadata: a stable id, category,
human description, and a severity weight (1-10) used by the scorer.
Rules are intentionally conservative and documented: injectguard is a
deterministic heuristic layer, not a proof of safety.
"""

import re

RULE_VERSION = "2026.10.22"

# Verdict thresholds on the summed severity score.
WARN_THRESHOLD = 8
BLOCK_THRESHOLD = 10

_RULE_DEFS = [
    # id, category, severity, regex, flags, description
    (
        "INJ001", "instruction_override", 10,
        r"ignore\s+(all|any|the|your|all\s+of\s+the\s+)?\s*"
        r"(previous|prior|above|earlier|preceding|prior\s+given)\s+"
        r"(instructions?|prompts?|rules|directives|context|guardrails?)",
        re.IGNORECASE,
        "Attempts to make the model ignore previous instructions.",
    ),
    (
        "INJ002", "instruction_override", 10,
        r"disregard\s+(all|any|the)?\s*"
        r"(previous|prior|above|earlier|preceding)\s+"
        r"(instructions?|prompts?|rules|directives|guidelines)",
        re.IGNORECASE,
        "Variant of the classic instruction-override attack.",
    ),
    (
        "INJ003", "instruction_override", 7,
        r"new\s+(instructions?|rules|directives|policy)\s*"
        r"(are|follow|apply|:|\bnow\b)",
        re.IGNORECASE,
        "Declares replacement instructions inside the content.",
    ),
    (
        "INJ004", "role_hijack", 9,
        r"\b(do\s+anything\s+now|DAN\s+mode|jailbreak\s+mode)\b",
        re.IGNORECASE,
        "DAN-style jailbreak persona activation.",
    ),
    (
        "INJ005", "role_hijack", 8,
        r"you\s+are\s+now\s+(dan|an?\s+"
        r"(unrestricted|unfiltered|uncensored|unethical|liberated)\s+\w+)",
        re.IGNORECASE,
        "Attempts to overwrite the assistant persona.",
    ),
    (
        "INJ006", "role_hijack", 8,
        r"\b(developer\s+mode(\s+enabled)?|godmode|grandma\s+exploit)\b",
        re.IGNORECASE,
        "Fictional 'mode switch' used to bypass guardrails.",
    ),
    (
        "INJ007", "system_prompt_extraction", 8,
        r"(reveal|show|print|output|repeat|recite|leak|expose|display)\w*\s+"
        r"(your|the|this\s+system'?s?)\s+"
        r"(system\s+)?(prompt|instructions|initial\s+message|rules)",
        re.IGNORECASE,
        "Tries to extract the hidden system prompt.",
    ),
    (
        "INJ008", "credential_phishing", 9,
        r"(send|share|post|upload|exfiltrate|transmit|paste|email)\w*\s+"
        r"(me\s+|us\s+|to\s+\S+|the\s+)?[\w\W]{0,40}?"
        r"(api[_\s-]?key|secret|password|credentials?|access\s+token|"
        r"\.env\b|environment\s+variables?)",
        re.IGNORECASE,
        "Requests secrets or environment variables be exfiltrated.",
    ),
    (
        "INJ009", "tool_abuse", 10,
        r"rm\s+-rf\s+/|curl\s+[^\n|]{0,120}\|\s*(ba)?sh\b|"
        r"wget\s+[^\n|]{0,120}\|\s*(ba)?sh\b|"
        r"eval\s*\(.*base64|base64\s+-d\s*[^\n|]{0,120}\|\s*(ba)?sh",
        re.IGNORECASE,
        "Embedded shell abuse pattern (pipe-to-shell, rm -rf, eval).",
    ),
    (
        "INJ010", "fake_control_token", 10,
        r"<\|(im_start|im_end|endoftext|system|assistant|user)\|>|"
        r"<\|?(tool_call|function_call|tool_response)\|?>",
        0,
        "Forged model control or tool-call tokens inside content.",
    ),
    (
        "INJ011", "hidden_payload", 9,
        "[\u200b\u200c\u200d\u2060\ufeff\U000E0000-\U000E007F]",
        0,
        "Invisible characters (zero-width / unicode tags) hiding text.",
    ),
    (
        "INJ012", "encoding_evasion", 6,
        r"(?:[A-Za-z0-9+/]{40,}={0,2}\s*){3,}",
        0,
        "Suspiciously long base64 block — possible encoded payload.",
    ),
    (
        "INJ013", "data_exfiltration", 7,
        r"<!--[\s\S]{0,300}?(ignore|instruction|prompt|system|assistant|"
        r"secret|token)\s",
        re.IGNORECASE,
        "Instructions hidden inside an HTML comment.",
    ),
    (
        "INJ014", "data_exfiltration", 6,
        r"!\[[^\]]{0,80}\]\(\s*https?://[^\s)]{4,200}\)",
        0,
        "Remote markdown image — a classic silent exfiltration beacon.",
    ),
    (
        "INJ015", "instruction_override", 7,
        r"(stop|cease|abort|pause)\s+(following|acting\s+on|executing)\s+"
        r"(your|the|all|any)\s+(instructions?|rules|guidelines)",
        re.IGNORECASE,
        "Tells the model to stop obeying its instructions.",
    ),
]


class Rule:
    __slots__ = ("id", "category", "severity", "pattern", "description")

    def __init__(self, id, category, severity, regex, flags, description):
        self.id = id
        self.category = category
        self.severity = severity
        self.pattern = re.compile(regex, flags)
        self.description = description

    def __repr__(self):
        return f"<Rule {self.id} severity={self.severity}>"


RULES = [
    Rule(*spec) for spec in _RULE_DEFS
]

RULES_BY_ID = {r.id: r for r in RULES}
