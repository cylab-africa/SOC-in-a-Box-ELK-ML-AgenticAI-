#!/usr/bin/env python3
"""Shared LLM routing for all modules.

Routes LLM calls to OpenAI, Anthropic, or Ollama based on model name prefix.
Extracted from es_health_monitor._llm_chat_complete to eliminate duplication.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

import requests

LOG = logging.getLogger("llm_common")


def llm_chat_complete(model: str, system_msg: str, user_msg: str) -> Optional[str]:
    """Route an LLM chat completion: gpt-* -> OpenAI, claude-* -> Anthropic, else Ollama.

    Args:
        model: Model identifier (e.g. 'gpt-4o-mini', 'claude-3-sonnet', 'llama3.2:1b').
        system_msg: System prompt content.
        user_msg: User prompt content.

    Returns:
        The LLM response text, or None on failure.
    """
    if model.startswith("gpt-"):
        return _openai_complete(model, system_msg, user_msg)
    if model.startswith("claude-"):
        return _anthropic_complete(model, system_msg, user_msg)
    return _ollama_complete(model, system_msg, user_msg)


def get_llm_model() -> str:
    """Return the configured LLM model name from environment variables."""
    return os.getenv("ES_HEALTH_LLM_MODEL") or os.getenv("LLM_MODEL", "gpt-4o-mini")


def is_llm_enabled() -> bool:
    """Check whether LLM analysis is enabled via environment variables."""
    return os.getenv("LLM_ENABLED", "true").lower() in ("true", "1", "yes", "on")


def _openai_uses_new_params(model: str) -> bool:
    """Return True for models that require max_completion_tokens and disallow temperature."""
    return model.startswith("o1") or model.startswith("o3") or model.startswith("o4") or model.startswith("gpt-5")


def _openai_complete(model: str, system_msg: str, user_msg: str, max_tokens: int = 4000) -> Optional[str]:
    """Send a chat completion request to OpenAI."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        LOG.debug("OPENAI_API_KEY not set; cannot use OpenAI model %s", model)
        return None
    try:
        new_style = _openai_uses_new_params(model)
        payload: dict = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
        }
        if new_style:
            payload["max_completion_tokens"] = max_tokens
        else:
            payload["max_tokens"] = max_tokens
            payload["temperature"] = 0.3
        openai_timeout = int(os.getenv("OPENAI_TIMEOUT_SECONDS", "300"))
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=openai_timeout,
        )
        if r.status_code != 200:
            LOG.warning("OpenAI HTTP %s: %s", r.status_code, r.text[:300])
            return None
        data = r.json()
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        text = text.strip()
        if not text:
            finish = (data.get("choices") or [{}])[0].get("finish_reason", "unknown")
            LOG.warning("OpenAI returned empty content for %s (finish_reason=%s); raise max_completion_tokens or OPENAI_TIMEOUT_SECONDS", model, finish)
            return None
        return text
    except Exception as e:
        LOG.warning("OpenAI request failed: %s", e)
        return None


def _anthropic_complete(model: str, system_msg: str, user_msg: str) -> Optional[str]:
    """Send a chat completion request to Anthropic."""
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        LOG.debug("ANTHROPIC_API_KEY not set; cannot use Anthropic model %s", model)
        return None
    try:
        r = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 1500,
                "system": system_msg,
                "messages": [
                    {"role": "user", "content": user_msg},
                ],
                "temperature": 0.3,
            },
            timeout=120,
        )
        if r.status_code != 200:
            LOG.warning("Anthropic HTTP %s: %s", r.status_code, r.text[:300])
            return None
        data = r.json()
        content_blocks = data.get("content") or []
        text_parts = [b.get("text", "") for b in content_blocks if b.get("type") == "text"]
        return "".join(text_parts).strip()
    except Exception as e:
        LOG.warning("Anthropic request failed: %s", e)
        return None


def _ollama_complete(model: str, system_msg: str, user_msg: str) -> Optional[str]:
    """Send a generation request to Ollama."""
    base = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    try:
        r = requests.post(
            f"{base}/api/generate",
            json={
                "model": model,
                "prompt": f"{system_msg}\n\n{user_msg}",
                "stream": False,
                "options": {"temperature": 0.3, "num_predict": 2048},
            },
            timeout=180,
        )
        if r.status_code != 200:
            LOG.warning("Ollama HTTP %s: %s", r.status_code, r.text[:300])
            return None
        return (r.json() or {}).get("response", "").strip()
    except Exception as e:
        LOG.warning("Ollama request failed: %s", e)
        return None
