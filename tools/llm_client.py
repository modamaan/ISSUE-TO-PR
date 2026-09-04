"""LLM client — thin wrapper around the OpenAI SDK.

All agents call this module rather than the SDK directly, so swapping
models or providers only requires changing this one file.
"""

from __future__ import annotations

import structlog
from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from shared.config import settings

log = structlog.get_logger(__name__)

_client: OpenAI | None = None


def _get_client() -> OpenAI:
    global _client  # noqa: PLW0603
    if _client is None:
        _client = OpenAI(api_key=settings.openai_api_key.get_secret_value())
    return _client


@retry(
    wait=wait_exponential(multiplier=1, min=2, max=60),
    stop=stop_after_attempt(4),
    reraise=True,
)
def chat_completion(
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.2,
    max_tokens: int = 4096,
    model: str | None = None,
) -> str:
    """Call the OpenAI chat completion API.

    Args:
        system_prompt: System message setting agent context.
        user_prompt: User message containing the task.
        temperature: Sampling temperature (lower = more deterministic).
        max_tokens: Maximum response length.
        model: Override the default model from settings.

    Returns:
        The assistant's response text.
    """
    _model = model or settings.openai_model
    log.debug("llm_call", model=_model, max_tokens=max_tokens)

    response = _get_client().chat.completions.create(
        model=_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )

    content = response.choices[0].message.content or ""
    
    # Strip markdown fences if the model still outputs them despite the prompt
    content = content.strip()
    if content.startswith("```"):
        # Split by newlines, remove first line and last line if it's also ```
        lines = content.splitlines()
        if len(lines) >= 2 and lines[-1].strip() == "```":
            content = "\n".join(lines[1:-1])

    log.debug(
        "llm_response",
        tokens_used=response.usage.total_tokens if response.usage else "?",
        response_len=len(content),
    )
    return content


@retry(
    wait=wait_exponential(multiplier=1, min=2, max=60),
    stop=stop_after_attempt(4),
    reraise=True,
)
def chat_completion_json(
    system_prompt: str,
    user_prompt: str,
    temperature: float = 0.1,
    max_tokens: int = 4096,
    model: str | None = None,
) -> str:
    """Call chat completion with JSON mode enforced.

    Returns:
        Raw JSON string from the model (caller must parse).
    """
    _model = model or settings.openai_model
    log.debug("llm_json_call", model=_model)

    response = _get_client().chat.completions.create(
        model=_model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
    )

    return response.choices[0].message.content or "{}"
