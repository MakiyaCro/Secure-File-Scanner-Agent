"""
Guardrails — detect and block prompt injection attempts in uploaded files.
"""

import re
import logging

log = logging.getLogger("vulnscan.guardrails")

# ─── Prompt injection patterns ────────────────────────────────────────────────
# These target common techniques used to hijack LLM behavior via code files.
_INJECTION_PATTERNS = [
    # Direct instruction override
    r"ignore\s+previous\s+instructions",
    r"ignore\s+all\s+prior\s+instructions",
    r"disregard\s+(your\s+)?(previous|prior|above|all)\s+instructions",
    r"forget\s+(everything|all|your\s+instructions)",
    r"new\s+instructions?\s*:",
    r"system\s+prompt\s*:",

    # Role hijacking
    r"you\s+are\s+now\s+(a\s+)?(?!vulnerable|insecure|the\s+file)",  # allow legit code strings
    r"act\s+as\s+(a\s+)?(?:jailbroken|unrestricted|DAN)",
    r"pretend\s+(you\s+are|to\s+be)\s+(?:an?\s+)?(?:evil|malicious|unrestricted)",
    r"DAN\s+mode",

    # Data exfil attempts
    r"send\s+(your\s+)?(system\s+)?prompt\s+to",
    r"reveal\s+(your\s+)?(system\s+)?prompt",
    r"print\s+(your\s+)?(system\s+)?prompt",
    r"output\s+(your\s+)?(system\s+)?instructions",

    # Delimiter attacks
    r"<\|im_start\|>system",
    r"\[INST\]\s*<<SYS>>",
    r"#{3,}\s*SYSTEM",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in _INJECTION_PATTERNS]

# Maximum density of injection-like tokens per KB
_KEYWORD_FLOOD_THRESHOLD = 50


class Guardrails:
    @staticmethod
    def is_prompt_injection(content: str) -> bool:
        """Return True if content contains suspected prompt injection."""
        for pattern in _COMPILED:
            if pattern.search(content):
                log.warning(f"Injection pattern matched: {pattern.pattern[:40]}")
                return True

        # Heuristic: excessive repetition of override keywords
        keywords = ["ignore", "forget", "instructions", "system", "prompt", "jailbreak"]
        total = sum(content.lower().count(k) for k in keywords)
        kb = max(len(content) / 1024, 1)
        if total / kb > _KEYWORD_FLOOD_THRESHOLD:
            log.warning(f"Keyword flood detected: {total} hits in {kb:.1f} KB")
            return True

        return False

    @staticmethod
    def sanitize_filename(name: str) -> str:
        """Remove path components and dangerous characters from filenames."""
        # Strip directory traversal
        name = name.replace("..", "").replace("/", "").replace("\\", "")
        # Keep only safe chars
        name = re.sub(r"[^\w.\-]", "_", name)
        return name[:128]  # cap length