"""Core scanning engine: pattern matching, scoring, verdicts."""

from dataclasses import dataclass, field, asdict
from typing import List, Optional

from .rules import RULES, WARN_THRESHOLD, BLOCK_THRESHOLD, RULE_VERSION


@dataclass
class Finding:
    """One detected injection indicator."""
    rule_id: str
    category: str
    severity: int
    line: int
    column: int
    excerpt: str          # short, sanitized context around the match
    description: str

    def to_dict(self):
        return asdict(self)


@dataclass
class Report:
    """Result of scanning one text blob."""
    verdict: str                 # PASS | LOW | WARN | BLOCK
    score: int
    findings: List[Finding] = field(default_factory=list)
    bytes_scanned: int = 0
    rule_version: str = RULE_VERSION

    @property
    def passed(self) -> bool:
        return self.verdict in ("PASS", "LOW")

    def to_dict(self):
        return {
            "verdict": self.verdict,
            "score": self.score,
            "passed": self.passed,
            "bytes_scanned": self.bytes_scanned,
            "rule_version": self.rule_version,
            "findings": [f.to_dict() for f in self.findings],
        }


def _line_col(text, pos):
    line = text.count("\n", 0, pos) + 1
    last_nl = text.rfind("\n", 0, pos)
    return line, pos - last_nl


def _excerpt(text, start, end, width=60):
    s = max(0, start - width)
    e = min(len(text), end + width)
    frag = text[s:e].replace("\n", " ")
    return ("…" if s > 0 else "") + frag + ("…" if e < len(text) else "")


def scan_text(text: str) -> List[Finding]:
    """Scan raw text and return all findings (unsorted order = rule order)."""
    findings = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            line, col = _line_col(text, m.start())
            excerpt = _excerpt(text, m.start(), m.end())
            # Never echo back raw control characters in the excerpt.
            excerpt = "".join(ch if ch.isprintable() else "·" for ch in excerpt)
            findings.append(Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=rule.severity,
                line=line,
                column=col,
                excerpt=excerpt.strip(),
                description=rule.description,
            ))
    return findings


def _verdict_for(score: int) -> str:
    if score >= BLOCK_THRESHOLD:
        return "BLOCK"
    if score >= WARN_THRESHOLD:
        return "WARN"
    if score > 0:
        return "LOW"
    return "PASS"


def scan_report(text: str, warn: int = WARN_THRESHOLD,
                block: int = BLOCK_THRESHOLD) -> Report:
    """Scan text and return a scored :class:`Report`."""
    findings = scan_text(text)
    score = sum(f.severity for f in findings)
    verdict = "BLOCK"
    if score >= block:
        verdict = "BLOCK"
    elif score >= warn:
        verdict = "WARN"
    elif score > 0:
        verdict = "LOW"
    else:
        verdict = "PASS"
    return Report(verdict=verdict, score=score, findings=findings,
                  bytes_scanned=len(text.encode("utf-8")))
