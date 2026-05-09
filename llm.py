"""Ollama integration. The LLM is a translator only — it never decides
severity, never picks attack angles on its own, never reads raw XML.

Two public methods on `LLMClient`:

  translate(tool, output) → (severity, summary)
      Phase 2 helper. Severity is derived deterministically from the raw
      output (tools/parser.derive_severity), not from the LLM. The LLM
      produces ONE sentence describing what was found. Falls back to a
      manual extraction if ollama is down or the model misbehaves —
      Phase 2 never shows the user a "LLM unavailable" error.

  synthesize(intel_summary, findings) → text | None
      Phase 3 helper. Single call with the fixed-format prompt from the
      spec. Returns the full analysis text, or None if ollama is down
      (Phase 3 then falls back to a deterministic summary in
      phases/analysis.py).

XML guard: both methods refuse inputs that look like raw XML. Callers
must format nmap output through tools.parser.format_nmap_summary before
sending it through the LLM.
"""

import asyncio
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .tools.parser import looks_like_xml


# Used to sort findings in the UI and report. Lower = higher priority.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


@dataclass
class Finding:
    severity: str
    summary: str
    detail: str = ""
    tool: str = ""
    raw: str = ""
    phase: int = 0  # 1, 2, or 3 — drives which collapsible section it lands in
    # Optional sub-section header within a phase. Currently used by the
    # Exposure Check sub-phase ("EXPOSURE") so the findings panel groups
    # binary-result probes under their own header.
    category: str = ""

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity.upper(), 4)


# ----------------------------------------------------------------------
# Prompts
# ----------------------------------------------------------------------


_TRANSLATE_PROMPT = (
    "Summarize what this tool found in one plain english sentence. "
    "Do not include any severity rating — that is handled separately.\n\n"
    "Tool: {tool}\n"
    "Output: {output}"
)


_SYNTHESIZE_PROMPT = """You are a penetration testing analyst. Based only on the findings and loot below, provide exactly three sections:

1. TOP ATTACK ANGLES — up to 3, ranked by likelihood of success, based strictly on what was found. one paragraph each. When relevant, reference specific loot items (e.g. "use the confirmed bob/SSH credential to ...", "the leaked .env from <source> hands you ...").
2. CONFIRMING CONDITIONS — for each angle, what additional information would confirm it is viable
3. NEXT STEPS — concrete manual actions the tester should take. Prefer commands that chain the loot (verified creds, hashes, internal hosts, leaked secrets) into the next pivot.

Be specific to these findings only. Do not invent findings not present. Label each section clearly.

INTEL SUMMARY:
{intel_summary}

FINDINGS:
{findings}
{loot_section}"""


_LOOT_SECTION_TEMPLATE = """
LOOT ALREADY COLLECTED (use these in your reasoning when relevant):
{loot}
"""


# ----------------------------------------------------------------------
# Client
# ----------------------------------------------------------------------


class LLMClient:
    """Thin wrapper around the ollama python SDK.

    Availability is probed lazily on first use — we don't want to block
    the UI startup if the daemon is slow to respond.
    """

    def __init__(self, model: str = "gemma4uncensored:latest"):
        self.model = model
        self._available: Optional[bool] = None
        self._client = None
        self.last_error: Optional[str] = None

    def _ensure(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            import ollama  # type: ignore
            self._client = ollama
            self._client.list()
            self._available = True
            self.last_error = None
        except Exception as e:
            self._available = False
            self.last_error = f"ollama unreachable: {e}"
        return self._available

    @property
    def available(self) -> bool:
        return self._ensure()

    def reset_probe(self) -> None:
        """Forget cached availability so the next call re-probes the daemon."""
        self._available = None
        self.last_error = None

    # ------------------------------------------------------------------
    # Phase 2: one-sentence translator
    # ------------------------------------------------------------------

    async def translate(self, tool: str, output: str) -> str:
        """Convert raw tool output to one plain-english sentence.

        Always returns a sentence — never raises, never returns empty.
        Falls back to a manual extraction (first non-empty line) if the
        LLM is unreachable or returns nonsense. The caller pairs this
        with `tools.parser.derive_severity(tool, output)` to label the
        Finding with a severity.
        """
        if not output.strip():
            return f"{tool}: no output captured"

        # XML guard — refuse rather than burn tokens. If a caller passes
        # raw nmap XML (a bug), they get the manual fallback.
        if looks_like_xml(output):
            return _manual_summary(tool, output)

        if not self._ensure():
            return _manual_summary(tool, output)

        truncated = output if len(output) < 4000 else output[:4000] + "\n... [truncated]"
        prompt = _TRANSLATE_PROMPT.format(tool=tool, output=truncated)

        try:
            resp = await asyncio.to_thread(
                self._client.generate,
                model=self.model,
                prompt=prompt,
                options={"temperature": 0.1},
            )
            text = (resp or {}).get("response", "").strip()
            sentence = _first_sentence(text)
            if sentence:
                return sentence
        except Exception as e:
            self.last_error = _format_model_error(self.model, e)

        return _manual_summary(tool, output)

    # ------------------------------------------------------------------
    # Phase 3: fixed-prompt synthesis
    # ------------------------------------------------------------------

    async def synthesize(
        self, intel_summary: str, findings_block: str,
        loot_block: str = "",
    ) -> Optional[str]:
        """Single call with the spec's three-section prompt.

        `loot_block` is an optional plain-text inventory of already-
        collected pivot data (verified creds, hashes, secrets,
        usernames, internal hosts, version strings). When non-empty,
        the LLM is instructed to chain it into the attack angles and
        next-step commands. Caller (phases/analysis.py) is responsible
        for redacting sensitive values before passing them through —
        we do no further sanitization here.

        Returns the full analysis text or None on hard failure (model
        not pulled, daemon down). The caller — phases/analysis.py — has
        a deterministic fallback that lists raw findings sorted by
        severity when this returns None.
        """
        if (looks_like_xml(intel_summary) or looks_like_xml(findings_block)
                or (loot_block and looks_like_xml(loot_block))):
            self.last_error = "synthesize() refused: input contained raw XML"
            return None
        if not self._ensure():
            return None

        loot_section = (
            _LOOT_SECTION_TEMPLATE.format(loot=loot_block[:6000])
            if loot_block.strip() else ""
        )
        prompt = _SYNTHESIZE_PROMPT.format(
            intel_summary=intel_summary[:8000],
            findings=findings_block[:12000],
            loot_section=loot_section,
        )
        try:
            resp = await asyncio.to_thread(
                self._client.generate,
                model=self.model,
                prompt=prompt,
                options={
                    "temperature": 0.3,
                    # Give the model a large context window so the prompt
                    # (up to ~5 000 tokens) doesn't crowd out the response.
                    "num_ctx": 16384,
                    # -1 = generate until the model's own EOS token — no
                    # artificial cutoff. The previous 2048-token cap was
                    # causing every complex analysis to stop mid-sentence.
                    "num_predict": -1,
                },
            )
            text = (resp or {}).get("response", "").strip()
            return text if text else None
        except Exception as e:
            self.last_error = _format_model_error(self.model, e)
            return None


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _first_sentence(text: str) -> str:
    """Trim model output to a single sentence, stripping markdown fences
    and common preambles like 'Sure! Here is...'.
    """
    t = text.strip()
    # Strip markdown fences a misbehaving model added.
    t = re.sub(r"^```(?:\w+)?\s*", "", t)
    t = re.sub(r"\s*```$", "", t)
    # Collapse whitespace.
    t = " ".join(t.split())
    if not t:
        return ""

    # Cut at the first sentence terminator. Keep the punctuation.
    for sep in (". ", "! ", "? "):
        if sep in t:
            head, _, _ = t.partition(sep)
            return (head + sep[0]).strip()
    # No sentence terminator — return up to a reasonable length.
    return t[:240].strip()


def _manual_summary(tool: str, output: str) -> str:
    """Best-effort fallback when the LLM is unavailable or unhelpful.

    Picks the first informative line of output. Never returns empty.
    """
    lines = [l.strip() for l in output.splitlines() if l.strip()]
    # Skip banner / separator-style lines.
    informative = [
        l for l in lines
        if not l.startswith(("=", "-", "*", "+"))
        and len(l) > 4
    ]
    pick = informative[0] if informative else (lines[0] if lines else "")
    if not pick:
        return f"{tool}: completed with no parseable output"
    return f"{tool}: {pick[:240]}"


def _format_model_error(model: str, exc: Exception) -> str:
    """Make ollama's 'model not found' error actionable."""
    msg = str(exc)
    lower = msg.lower()
    if any(s in lower for s in ("not found", "no such model",
                                  "try pulling", "pull it first")):
        return f"model {model!r} is not pulled locally — run: ollama pull {model}"
    return f"model {model!r}: {msg}"
