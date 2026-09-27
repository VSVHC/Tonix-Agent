"""
llm.py
──────
Ollama integration for finding enrichment.

Improvements over v1:
  - Concurrent enrichment via asyncio.gather (semaphore-bounded)
  - Robust JSON extraction with fallback regex strip
  - Typed return values
  - Structured logging
"""

import json
import asyncio
import re
import httpx
from typing import Any

from backend.config import settings
from backend.models import Finding
from backend.logger import get_logger

log = get_logger(__name__)

# Max concurrent LLM calls — avoids overwhelming local Ollama
_LLM_SEMAPHORE = asyncio.Semaphore(4)


# ─────────────────────────────────────────────────────────
#  Prompt templates
# ─────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are a senior penetration tester writing a professional security assessment report.
Given a raw security finding from an automated scan, your job is to:
1. Write a clear 2-3 sentence technical description of what was found and why it is a risk
2. Write a concrete, actionable remediation recommendation (2-3 sentences)

Do NOT change the severity — it is determined by the scanner, not by you.

Respond ONLY with a JSON object — no preamble, no markdown, no backticks.
Format:
{
  "description": "...",
  "remediation": "..."
}"""

USER_PROMPT_TEMPLATE = """Finding details:
Module: {module}
Title: {title}
Severity: {severity}
Evidence: {evidence}
Request: {request_data}
Response (truncated to 500 chars): {response_preview}

Enrich this finding (description + remediation only)."""


# ─────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────

async def enrich_finding(finding: Finding) -> dict[str, Any]:
    """
    Send a finding to Ollama for description/remediation enrichment.
    Returns a dict with keys: description, remediation.
    Severity is NOT enriched — it stays exactly as the scanner set it.
    Falls back to original values if Ollama is unavailable.
    """
    async with _LLM_SEMAPHORE:
        prompt = USER_PROMPT_TEMPLATE.format(
            module=finding.module,
            title=finding.title,
            severity=finding.severity,
            evidence=(finding.evidence or "")[:800],
            request_data=(finding.request_data or "")[:400],
            response_preview=(finding.response_data or "")[:500],
        )
        try:
            result = await _call_ollama(prompt)
            if all(k in result for k in ("description", "remediation")):
                log.debug("LLM enriched finding: %s", finding.title)
                return {"description": result["description"], "remediation": result["remediation"]}
        except Exception as exc:
            log.warning("LLM enrichment failed for '%s': %s", finding.title, exc)

    # Fallback — return original values unchanged
    return {
        "description": finding.description or f"{finding.title} was detected on the target.",
        "remediation": finding.remediation or "Review and address the identified security issue.",
    }


async def enrich_findings_concurrent(findings: list[Finding]) -> list[dict[str, Any]]:
    """
    Enrich all findings concurrently (bounded by _LLM_SEMAPHORE).
    Returns results in the same order as the input list.
    """
    if not findings:
        return []
    log.info("Enriching %d findings concurrently (max 4 parallel LLM calls)", len(findings))
    tasks = [enrich_finding(f) for f in findings]
    return await asyncio.gather(*tasks)


SCAN_SUMMARY_SYSTEM = """You are a senior penetration tester writing the summary of a security assessment.
You are given the full list of confirmed findings from one automated blackbox scan.

Produce two things:
1. "summary" — a 3-5 sentence executive summary of the target's overall security posture:
   the biggest risks, the general theme, and what to fix first. Written for a technical manager.
2. "chains" — a list of attack chains: cases where two or more findings COMBINE into a bigger
   risk than any one alone (e.g. exposed .git + verbose errors = source-code disclosure).
   Each item is ONE sentence naming the findings involved and the combined risk. If no findings
   meaningfully combine, return an empty list.

Only reason about the findings given — do NOT invent vulnerabilities that are not listed.
Respond ONLY with a JSON object — no preamble, no markdown, no backticks.
Format:
{
  "summary": "...",
  "chains": ["...", "..."]
}"""


async def summarize_scan(findings: list[Finding], target_url: str) -> dict[str, Any]:
    """
    One LLM pass over ALL findings → executive summary + correlated attack chains.
    Returns {"summary": str, "correlations": list[str]}.
    Falls back to empty values if Ollama is unavailable or no findings.
    """
    if not findings:
        return {"summary": "", "correlations": []}

    # Compact list — keep token budget bounded even on large scans.
    lines = [
        f"- [{f.severity}] {f.title} ({f.module}) — {(f.evidence or '')[:160]}"
        for f in findings[:40]
    ]
    user_prompt = (
        f"Target: {target_url}\n"
        f"Confirmed findings ({len(findings)}):\n" + "\n".join(lines) +
        "\n\nWrite the executive summary and attack chains."
    )

    async with _LLM_SEMAPHORE:
        try:
            result = await _call_ollama(user_prompt, system=SCAN_SUMMARY_SYSTEM, num_predict=700)
            chains = result.get("chains") or []
            if isinstance(chains, str):
                chains = [chains]
            return {
                "summary": str(result.get("summary") or ""),
                "correlations": [str(c) for c in chains if str(c).strip()],
            }
        except Exception as exc:
            log.warning("LLM scan summary failed: %s", exc)
            return {"summary": "", "correlations": []}


async def check_ollama_health() -> bool:
    """Returns True if the local Ollama server is reachable."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{settings.OLLAMA_BASE_URL}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


# ─────────────────────────────────────────────────────────
#  Internal
# ─────────────────────────────────────────────────────────

async def _call_ollama(user_prompt: str, system: str = SYSTEM_PROMPT,
                       num_predict: int = 400) -> dict[str, Any]:
    """
    Call the local Ollama /api/chat endpoint.
    Returns parsed JSON dict from the model response.
    """
    payload = {
        "model": settings.OLLAMA_MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_prompt},
        ],
        "options": {
            "temperature": 0.1,
            "num_predict": num_predict,
        },
    }

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(settings.ollama_url(), json=payload)
        response.raise_for_status()

    data = response.json()
    content: str = data["message"]["content"].strip()

    # Strip markdown fences if the model added them
    content = re.sub(r"^```(?:json)?\s*", "", content, flags=re.MULTILINE)
    content = re.sub(r"\s*```$", "", content, flags=re.MULTILINE)
    content = content.strip()

    return json.loads(content)
