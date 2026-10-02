"""Best-effort secret redaction for excerpts stored in the database or sent to the judge."""
from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
]
_KEY_VALUE = re.compile(
    r"(?i)\b((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization)"
    r"[\"']?\s*[:=]\s*[\"']?)([^\s\"',;]{4,})"
)
_URL_CREDS = re.compile(r"(://[^/\s:@]+:)([^@\s/]+)(@)")


def redact(text: str | None) -> str:
    if not text:
        return ""
    for pattern in _PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = _KEY_VALUE.sub(lambda m: m.group(1) + "[REDACTED]", text)
    text = _URL_CREDS.sub(lambda m: m.group(1) + "[REDACTED]" + m.group(3), text)
    return text


def excerpt(text: str | None, limit: int) -> str:
    text = redact(text or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + " ...[truncated]"
