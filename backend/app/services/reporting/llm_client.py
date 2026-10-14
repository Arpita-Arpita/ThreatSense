"""Pluggable LLM client for incident reports (task 3.2, Section 2.6).

Same shape as app/services/alerting/sender.py in Phase 2: the generator talks
to this interface, never to OpenAI directly. That keeps report generation —
prompt building, sanitisation, section validation, immutable storage, rate
limiting, audit rows — fully testable before an OpenAI account exists
(task 3.1), and makes failure injection in tests trivial.

Selection is driven by settings.report_llm_client:
    auto    OpenAI when an API key is present, otherwise mock (default)
    mock    always the mock client
    openai  always OpenAI; raises if the key is missing

Transport failures are raised as exceptions rather than returned, because the
caller must distinguish "the LLM never gave us a usable answer" (retryable,
NOT counted against the rate limit, audited as REPORT_GENERATION_FAILED)
from an ordinary bad-content result.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from ...config import settings

logger = logging.getLogger("threatsense.reporting.llm")

# Section titles are fixed by Section 2.6 / Algorithm 5. The mock renders them
# and the validator requires them, so they live here as the single source.
REPORT_SECTIONS = (
    "Executive Summary",
    "Threat Details",
    "Risk Assessment",
    "Recommended Actions",
)


@dataclass
class LLMResult:
    """A raw completion, before sanitisation/validation."""

    text: str
    model: str
    token_count: int | None = None


class LLMError(Exception):
    """Base for transport-level failures. kind feeds the audit row detail."""

    kind = "api_error"
    retryable = True


class LLMTimeout(LLMError):
    """The provider did not answer within settings.openai_timeout_seconds."""

    kind = "timeout"


class LLMAPIError(LLMError):
    """Any non-timeout provider failure (auth, quota, 5xx, network …)."""

    kind = "api_error"


class LLMClient(Protocol):
    """Anything that can turn a report prompt into completion text."""

    name: str

    def complete(self, system: str, user: str) -> LLMResult: ...


_MOCK_TEMPLATE = """## Executive Summary
An anomalous network event was flagged by the ThreatSense detection engine and
classified as requiring administrator attention. This report summarises the
event in non-technical terms for review and action.

## Threat Details
The detection engine identified activity consistent with the classified threat
category. The characteristics of the traffic, as summarised in the detection
metadata, deviated significantly from the learned baseline of normal behaviour
for this environment.

## Risk Assessment
Based on the assigned severity and the normalised anomaly score, this event
represents a level of risk that warrants review. If the activity is genuine
and not a false positive, the affected host or service could be exposed to
disruption or unauthorised access.

## Recommended Actions
Verify whether the flagged activity corresponds to known, legitimate
behaviour. If it cannot be explained, isolate or restrict the source address,
review recent authentication and firewall logs for the involved hosts, and
acknowledge the alert in the ThreatSense dashboard once triaged.
"""


@dataclass
class MockLLMClient:
    """Deterministic offline stand-in, used until task 3.1 is done.

    Mirrors MockSender's failure-injection style:
        fail_times      next N calls raise LLMAPIError
        timeout_times   next N calls raise LLMTimeout
        malformed_times next N calls return text missing required sections,
                        which exercises the validation + failure-audit path
    Successful calls echo the prompt into the fixed four-section template so
    tests can assert the prompt actually reached the client.
    """

    name: str = "mock"
    calls: list[dict] = field(default_factory=list)
    fail_times: int = 0
    timeout_times: int = 0
    malformed_times: int = 0

    def complete(self, system: str, user: str) -> LLMResult:
        self.calls.append({"system": system, "user": user})
        if self.fail_times > 0:
            self.fail_times -= 1
            logger.info("[mock-llm] simulated API error")
            raise LLMAPIError("simulated API error")
        if self.timeout_times > 0:
            self.timeout_times -= 1
            logger.info("[mock-llm] simulated timeout")
            raise LLMTimeout("simulated timeout after %ss" % settings.openai_timeout_seconds)
        if self.malformed_times > 0:
            self.malformed_times -= 1
            logger.info("[mock-llm] simulated malformed completion")
            return LLMResult("Sorry, I cannot help with that.", "mock-llm", 12)
        logger.info("[mock-llm] deterministic report completion")
        return LLMResult(_MOCK_TEMPLATE, "mock-llm", len(_MOCK_TEMPLATE) // 4)

    def reset(self) -> None:
        self.calls.clear()
        self.fail_times = self.timeout_times = self.malformed_times = 0


class OpenAIClient:
    """Chat Completions adapter implementing the LLMClient interface.

    max_retries=0 on the SDK: retry is a user-facing choice here (the API
    returns a retry option and failed attempts don't consume the rate limit),
    so silent SDK retries would only blur the 15s NFR budget.
    """

    name = "openai"

    def __init__(self) -> None:
        if not settings.openai_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Complete task 3.1 (account, billing "
                "cap, key) or set REPORT_LLM_CLIENT=mock for offline testing."
            )
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise RuntimeError("the 'openai' package is not installed — pip install openai") from exc
        self._client = OpenAI(
            api_key=settings.openai_api_key,
            timeout=settings.openai_timeout_seconds,
            max_retries=0,
        )

    def complete(self, system: str, user: str) -> LLMResult:
        from openai import APITimeoutError

        try:
            resp = self._client.chat.completions.create(
                model=settings.openai_model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                temperature=0.2,
                max_tokens=settings.report_max_completion_tokens,
            )
        except APITimeoutError as exc:
            logger.warning("OpenAI timed out after %ss", settings.openai_timeout_seconds)
            raise LLMTimeout(str(exc)) from exc
        except Exception as exc:
            logger.warning("OpenAI call raised: %s", exc)
            raise LLMAPIError(f"{type(exc).__name__}: {exc}"[:500]) from exc

        text = (resp.choices[0].message.content or "") if resp.choices else ""
        usage = getattr(resp, "usage", None)
        tokens = getattr(usage, "total_tokens", None) if usage else None
        # incident_reports.model_used is VARCHAR(30)
        model = (getattr(resp, "model", None) or settings.openai_model)[:30]
        return LLMResult(text, model, tokens)


def get_llm_client() -> LLMClient:
    """Resolve the configured client. Import is lazy so openai stays optional."""
    mode = (settings.report_llm_client or "auto").strip().lower()
    if mode == "mock":
        return MockLLMClient()
    if mode == "openai" or (mode == "auto" and settings.openai_api_key):
        return OpenAIClient()
    logger.warning(
        "no OPENAI_API_KEY set — using the mock LLM client. Reports will be "
        "generated from a fixed template and stored/audited normally, but no "
        "OpenAI call is made."
    )
    return MockLLMClient()
