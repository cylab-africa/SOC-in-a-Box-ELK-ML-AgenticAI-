#!/usr/bin/env python3
"""LLM-powered reflection layer for the feedback refinement loop.

When an operator provides feedback on an alert (helpful / not helpful / incorrect,
or a free-text thread reply), this module:
1. Reads the current SYSTEM_MEMORY.md
2. Builds a judge prompt with the original alert context + feedback
3. Calls the LLM to produce a structured verdict
4. Applies the verdict to SYSTEM_MEMORY.md (add hypothesis, confirm, reject)
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from llm_common import get_llm_model, is_llm_enabled, llm_chat_complete
from system_memory import (
    MemoryRule,
    SystemMemory,
    add_pending_hypothesis,
    get_active_rules_text,
    get_rejected_patterns_text,
    increment_hypothesis_confirmation,
    read_system_memory,
    reject_hypothesis,
)

LOG = logging.getLogger("feedback_judge")

JUDGE_SYSTEM_PROMPT = (
    "You are a SIEM operations meta-analyst. Your job is to review feedback on alerts "
    "produced by an Elasticsearch health monitoring system and determine whether the "
    "system's behavior should be adjusted.\n\n"
    "You will receive:\n"
    "1. The original alert context (issues detected, recommendations given)\n"
    "2. The operator's feedback (helpful/not_helpful/incorrect + optional text)\n"
    "3. The system's current memory (active rules, pending hypotheses, rejected patterns)\n\n"
    "Based on this, produce a JSON verdict:\n"
    "{\n"
    '  "action": "add_hypothesis" | "confirm_existing" | "reject_existing" | "no_action",\n'
    '  "rule_id": "<existing rule_id if confirming or rejecting, null otherwise>",\n'
    '  "rule_text": "<new rule text if adding a hypothesis, null otherwise>",\n'
    '  "reasoning": "<2-3 sentence explanation>",\n'
    '  "confidence": <0.0-1.0>\n'
    "}\n\n"
    "Guidelines:\n"
    "- Only add a hypothesis if the feedback suggests a PATTERN, not a one-off event\n"
    "- If the feedback matches an existing pending hypothesis, confirm it (use its rule_id)\n"
    "- If the feedback contradicts an active rule, reject it (use its rule_id)\n"
    "- If confidence < 0.5, choose 'no_action'\n"
    "- Rules should be specific and actionable (e.g., 'When X condition, do Y instead of Z')\n"
    "- Respond ONLY with valid JSON"
)


@dataclass
class JudgeVerdict:
    """Structured verdict from the judge LLM."""

    action: str
    rule_id: Optional[str]
    rule_text: Optional[str]
    reasoning: str
    confidence: float


def build_judge_prompt(
    alert_context: Dict[str, Any],
    feedback_type: str,
    feedback_text: Optional[str],
    current_memory: SystemMemory,
) -> tuple[str, str]:
    """Build the (system_msg, user_msg) pair for the judge LLM.

    Args:
        alert_context: Original alert payload and metadata.
        feedback_type: One of 'helpful', 'not_helpful', 'incorrect'.
        feedback_text: Optional free-text feedback from the operator.
        current_memory: Current state of SYSTEM_MEMORY.md.

    Returns:
        Tuple of (system_msg, user_msg).
    """
    active_text = "\n".join(
        f"  - [rule_id={r.rule_id}] {r.text}" for r in current_memory.active_rules
    ) or "  (none)"
    pending_text = "\n".join(
        f"  - [hypothesis_id={r.rule_id}] {r.text} (feedback_count: {r.feedback_count})"
        for r in current_memory.pending_hypotheses
    ) or "  (none)"
    rejected_text = "\n".join(
        f"  - {r.text}" for r in current_memory.rejected_patterns
    ) or "  (none)"

    issues_summary = json.dumps(alert_context.get("issues", []), indent=2, default=str)
    llm_analysis = json.dumps(alert_context.get("llm_analysis") or {}, indent=2, default=str)

    user_msg = (
        f"ORIGINAL ALERT:\n"
        f"  Title: {alert_context.get('card_title', 'unknown')}\n"
        f"  Scenario: {alert_context.get('scenario', 'unknown')}\n"
        f"  Issues:\n{issues_summary}\n"
        f"  LLM Analysis:\n{llm_analysis}\n\n"
        f"OPERATOR FEEDBACK:\n"
        f"  Type: {feedback_type}\n"
        f"  Text: {feedback_text or '(no additional text)'}\n\n"
        f"CURRENT SYSTEM MEMORY:\n"
        f"  Active Rules:\n{active_text}\n"
        f"  Pending Hypotheses:\n{pending_text}\n"
        f"  Rejected Patterns:\n{rejected_text}\n\n"
        f"Produce your JSON verdict."
    )

    return JUDGE_SYSTEM_PROMPT, user_msg


def _parse_verdict(raw: str) -> JudgeVerdict:
    """Parse a raw LLM response into a JudgeVerdict.

    Args:
        raw: Raw LLM response text (expected JSON).

    Returns:
        Parsed JudgeVerdict, or a no_action verdict on parse failure.
    """
    try:
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0].strip()
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0].strip()

        data = json.loads(raw)
        action = data.get("action", "no_action")
        if action not in ("add_hypothesis", "confirm_existing", "reject_existing", "no_action"):
            action = "no_action"

        confidence = float(data.get("confidence", 0.0))
        if confidence < 0.5:
            action = "no_action"

        return JudgeVerdict(
            action=action,
            rule_id=data.get("rule_id"),
            rule_text=data.get("rule_text"),
            reasoning=data.get("reasoning", ""),
            confidence=confidence,
        )
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        LOG.warning("Failed to parse judge verdict: %s", e)
        return JudgeVerdict(
            action="no_action",
            rule_id=None,
            rule_text=None,
            reasoning=f"Parse failure: {e}",
            confidence=0.0,
        )


def invoke_judge(
    alert_context: Dict[str, Any],
    feedback_type: str,
    feedback_text: Optional[str] = None,
) -> JudgeVerdict:
    """Run the full judge pipeline: read memory, build prompt, call LLM, parse verdict.

    Args:
        alert_context: Original alert payload and metadata.
        feedback_type: One of 'helpful', 'not_helpful', 'incorrect'.
        feedback_text: Optional free-text feedback from the operator.

    Returns:
        A JudgeVerdict with the recommended action.
    """
    if not is_llm_enabled():
        LOG.info("LLM disabled; skipping judge evaluation")
        return JudgeVerdict("no_action", None, None, "LLM disabled", 0.0)

    current_memory = read_system_memory()
    system_msg, user_msg = build_judge_prompt(alert_context, feedback_type, feedback_text, current_memory)

    model = get_llm_model()
    LOG.info("Invoking judge LLM (%s) for feedback_type=%s", model, feedback_type)

    raw = llm_chat_complete(model, system_msg, user_msg)
    if not raw:
        LOG.warning("Judge LLM returned no response")
        return JudgeVerdict("no_action", None, None, "LLM returned no response", 0.0)

    verdict = _parse_verdict(raw)
    LOG.info("Judge verdict: action=%s confidence=%.2f rule_id=%s",
             verdict.action, verdict.confidence, verdict.rule_id)
    return verdict


def apply_verdict(verdict: JudgeVerdict, alert_id: str) -> str:
    """Apply a judge verdict to SYSTEM_MEMORY.md.

    Args:
        verdict: The JudgeVerdict to apply.
        alert_id: The alert that triggered this feedback.

    Returns:
        Human-readable summary of what was done.
    """
    if verdict.action == "no_action":
        return f"No action taken (confidence={verdict.confidence:.2f}): {verdict.reasoning}"

    if verdict.action == "add_hypothesis":
        if not verdict.rule_text:
            return "No action: add_hypothesis verdict missing rule_text"
        rule = MemoryRule(
            rule_id=uuid.uuid4().hex[:8],
            text=verdict.rule_text,
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            feedback_count=1,
            source_alert_ids=[alert_id],
        )
        add_pending_hypothesis(rule)
        return f"Added pending hypothesis (rule_id={rule.rule_id}): {rule.text}"

    if verdict.action == "confirm_existing":
        if not verdict.rule_id:
            return "No action: confirm_existing verdict missing rule_id"
        new_count = increment_hypothesis_confirmation(verdict.rule_id, alert_id)
        if new_count == 0:
            return f"No action: hypothesis {verdict.rule_id} not found"
        return f"Confirmed hypothesis {verdict.rule_id} (new count={new_count})"

    if verdict.action == "reject_existing":
        if not verdict.rule_id:
            return "No action: reject_existing verdict missing rule_id"
        success = reject_hypothesis(verdict.rule_id, verdict.reasoning)
        if not success:
            return f"No action: rule {verdict.rule_id} not found for rejection"
        return f"Rejected rule {verdict.rule_id}: {verdict.reasoning}"

    return f"Unknown action: {verdict.action}"


def process_feedback(
    alert_context: Dict[str, Any],
    feedback_type: str,
    feedback_text: Optional[str] = None,
    alert_id: str = "",
) -> str:
    """Top-level function called by the feedback server.

    Orchestrates: invoke_judge -> apply_verdict -> return summary.

    Args:
        alert_context: Original alert payload and metadata.
        feedback_type: One of 'helpful', 'not_helpful', 'incorrect'.
        feedback_text: Optional free-text feedback from the operator.
        alert_id: The alert that triggered this feedback.

    Returns:
        Human-readable summary of what was done.
    """
    LOG.info("Processing feedback: type=%s alert_id=%s", feedback_type, alert_id)

    if feedback_type == "helpful":
        memory = read_system_memory()
        for h in memory.pending_hypotheses:
            if alert_id in h.source_alert_ids:
                new_count = increment_hypothesis_confirmation(h.rule_id, alert_id)
                if new_count > 0:
                    return f"Positive feedback reinforced hypothesis {h.rule_id} (count={new_count})"
        return "Positive feedback recorded (no matching hypothesis to reinforce)"

    verdict = invoke_judge(alert_context, feedback_type, feedback_text)
    summary = apply_verdict(verdict, alert_id)
    LOG.info("Feedback processing complete: %s", summary)
    return summary
