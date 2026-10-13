"""Tests for the Gemini provider.

No key, no network, no quota. Every request goes through an `httpx` mock
transport, which means the responses that matter most — a safety block, a
truncated answer, a rate limit — can be produced on demand instead of being
waited for in production.

The safety-block case is not hypothetical. This pipeline sends a hosted model
real malware commands, so a filter declining to engage is a recurring outcome,
and how it is handled decides whether that shows up in the comparison as a
number or as a mystery.
"""

from __future__ import annotations

import json
from typing import Any
from unittest import mock

import httpx
import pytest

from honeypot_ai.classify.llm.gemini import (
    _BACKOFF,
    DEFAULT_MODEL,
    MAX_ATTEMPTS,
    GeminiProvider,
    response_schema,
)
from honeypot_ai.classify.llm.provider import (
    PermanentProviderError,
    Provider,
    ProviderError,
)
from honeypot_ai.classify.taxonomy import Behaviour, Intent, Operator

ANSWER = {
    "intent": "fingerprinting",
    "behaviours": ["host_enumeration"],
    "operator": "automated",
    "confidence": 0.95,
    "rationale": "ran uname and disconnected",
}


def generate_content(text: str, finish_reason: str = "STOP") -> dict[str, Any]:
    return {
        "candidates": [
            {
                "content": {"parts": [{"text": text}], "role": "model"},
                "finishReason": finish_reason,
            }
        ]
    }


def provider_returning(*responses: httpx.Response) -> GeminiProvider:
    queue = list(responses)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return queue.pop(0) if queue else httpx.Response(200, json=generate_content("{}"))

    provider = GeminiProvider(
        api_key="test-key",
        model="test-model",
        min_interval=0.0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    provider.requests = seen  # type: ignore[attr-defined]
    return provider


# --- The contract ----------------------------------------------------------


def test_the_provider_satisfies_the_protocol() -> None:
    """Swappability is the whole point; a drifted signature must fail here."""
    assert isinstance(provider_returning(), Provider)


def test_the_name_identifies_the_model_not_just_the_vendor() -> None:
    """Stored results have to distinguish two Gemini models from each other."""
    assert provider_returning().name == "gemini:test-model"


def test_a_missing_key_fails_before_any_request() -> None:
    with pytest.raises(ProviderError, match="GEMINI_API_KEY"):
        GeminiProvider(api_key="")


def test_the_key_travels_in_a_header_not_the_url() -> None:
    """URLs reach logs, proxies and error messages; headers mostly do not."""
    provider = provider_returning(httpx.Response(200, json=generate_content(json.dumps(ANSWER))))
    provider.complete("system", "user")

    request = provider.requests[0]  # type: ignore[attr-defined]
    assert request.headers["x-goog-api-key"] == "test-key"
    assert "test-key" not in str(request.url)


# --- The schema is generated, not restated ---------------------------------


def test_the_response_schema_offers_every_taxonomy_value() -> None:
    """A schema listing last week's vocabulary silently forbids a real label."""
    schema = response_schema()
    assert set(schema["properties"]["intent"]["enum"]) == {i.value for i in Intent}
    assert set(schema["properties"]["behaviours"]["items"]["enum"]) == {b.value for b in Behaviour}
    assert set(schema["properties"]["operator"]["enum"]) == {o.value for o in Operator}


def test_the_request_asks_for_json_constrained_to_that_schema() -> None:
    provider = provider_returning(httpx.Response(200, json=generate_content(json.dumps(ANSWER))))
    provider.complete("system prompt", "user prompt")

    body = json.loads(provider.requests[0].content)  # type: ignore[attr-defined]
    config = body["generationConfig"]
    assert config["responseMimeType"] == "application/json"
    assert config["responseSchema"] == response_schema()


def test_the_temperature_is_zero_so_a_rerun_reproduces() -> None:
    """The comparison must measure the model, not the sampler."""
    provider = provider_returning(httpx.Response(200, json=generate_content(json.dumps(ANSWER))))
    provider.complete("system", "user")

    body = json.loads(provider.requests[0].content)  # type: ignore[attr-defined]
    assert body["generationConfig"]["temperature"] == 0


def test_the_system_prompt_is_sent_as_a_system_instruction() -> None:
    """Not folded into the user turn: that is where the untrusted data lives."""
    provider = provider_returning(httpx.Response(200, json=generate_content(json.dumps(ANSWER))))
    provider.complete("SYSTEM RULES", "session data")

    body = json.loads(provider.requests[0].content)  # type: ignore[attr-defined]
    assert body["systemInstruction"]["parts"][0]["text"] == "SYSTEM RULES"
    assert body["contents"][0]["parts"][0]["text"] == "session data"


# --- Replies ---------------------------------------------------------------


def test_a_normal_reply_returns_its_text() -> None:
    provider = provider_returning(httpx.Response(200, json=generate_content(json.dumps(ANSWER))))
    assert json.loads(provider.complete("s", "u"))["intent"] == "fingerprinting"


def test_text_split_across_parts_is_joined() -> None:
    payload = {
        "candidates": [
            {
                "content": {"parts": [{"text": '{"intent": '}, {"text": '"staging"}'}]},
                "finishReason": "STOP",
            }
        ]
    }
    provider = provider_returning(httpx.Response(200, json=payload))
    assert json.loads(provider.complete("s", "u"))["intent"] == "staging"


# --- The failures that actually happen -------------------------------------


def test_a_blocked_prompt_is_a_provider_error_not_an_empty_answer() -> None:
    """A hosted model refusing to read malware is a finding, not a blank."""
    payload = {"promptFeedback": {"blockReason": "SAFETY"}}
    provider = provider_returning(httpx.Response(200, json=payload))

    with pytest.raises(ProviderError, match="blocked the prompt: SAFETY"):
        provider.complete("s", "u")


@pytest.mark.parametrize("reason", ["SAFETY", "RECITATION", "PROHIBITED_CONTENT"])
def test_a_stopped_candidate_is_a_provider_error(reason: str) -> None:
    provider = provider_returning(
        httpx.Response(200, json=generate_content("partial", finish_reason=reason))
    )
    with pytest.raises(ProviderError, match=reason):
        provider.complete("s", "u")


def test_a_truncated_answer_with_no_parts_is_reported_with_its_reason() -> None:
    payload = {"candidates": [{"content": {}, "finishReason": "MAX_TOKENS"}]}
    provider = provider_returning(httpx.Response(200, json=payload))

    with pytest.raises(ProviderError, match="MAX_TOKENS"):
        provider.complete("s", "u")


def test_no_candidates_is_a_provider_error() -> None:
    provider = provider_returning(httpx.Response(200, json={"candidates": []}))
    with pytest.raises(ProviderError, match="no candidates"):
        provider.complete("s", "u")


@pytest.mark.parametrize("status", [401, 403])
def test_a_rejected_key_is_not_retried(status: int) -> None:
    provider = provider_returning(httpx.Response(status, json={"error": {}}))
    with pytest.raises(ProviderError, match="rejected the API key"):
        provider.complete("s", "u")
    assert len(provider.requests) == 1  # type: ignore[attr-defined]


def test_a_server_error_is_retried_and_then_succeeds() -> None:
    provider = provider_returning(
        httpx.Response(503, text="unavailable"),
        httpx.Response(200, json=generate_content(json.dumps(ANSWER))),
    )
    assert json.loads(provider.complete("s", "u"))["intent"] == "fingerprinting"
    assert len(provider.requests) == 2  # type: ignore[attr-defined]


def test_a_persistent_rate_limit_becomes_a_provider_error() -> None:
    limited = [httpx.Response(429, headers={"Retry-After": "0"}) for _ in range(MAX_ATTEMPTS)]
    provider = provider_returning(*limited)

    with pytest.raises(ProviderError, match="rate limit"):
        provider.complete("s", "u")


def test_an_unreachable_host_is_a_provider_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("name resolution failed")

    provider = GeminiProvider(
        api_key="k",
        min_interval=0.0,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(ProviderError, match="could not reach Gemini"):
        provider.complete("s", "u")


# --- Listing models --------------------------------------------------------


def test_available_models_are_reported_without_their_prefix() -> None:
    """The useful answer to "that model does not exist" is the list that does."""
    payload = {"models": [{"name": "models/gemini-a"}, {"name": "models/gemini-b"}]}
    provider = provider_returning(httpx.Response(200, json=payload))

    assert provider.list_models() == ["gemini-a", "gemini-b"]


# --- A retired model, which is what actually happened ----------------------


def test_a_retired_model_is_permanent_and_says_what_to_do() -> None:
    """The real 404: the name was valid when it was written and is not now."""
    body = {
        "error": {
            "code": 404,
            "message": (
                "This model models/gemini-2.0-flash is no longer available. "
                "Please update your code to use models/gemini-3.8-flash."
            ),
        }
    }
    provider = provider_returning(httpx.Response(404, json=body))

    with pytest.raises(PermanentProviderError) as caught:
        provider.complete("s", "u")

    message = str(caught.value)
    assert "gemini-3.8-flash" in message, "the replacement model must survive"
    assert "--models" in message, "and the way to find it for oneself"
    assert len(provider.requests) == 1, "retrying a retired model is pointless"  # type: ignore[attr-defined]


def test_a_rejected_key_is_permanent_too() -> None:
    provider = provider_returning(httpx.Response(401, json={"error": {"message": "bad key"}}))
    with pytest.raises(PermanentProviderError):
        provider.complete("s", "u")


def test_a_missing_key_is_permanent() -> None:
    with pytest.raises(PermanentProviderError):
        GeminiProvider(api_key="")


def test_a_malformed_request_is_not_retried() -> None:
    provider = provider_returning(httpx.Response(400, json={"error": {"message": "bad field"}}))
    with pytest.raises(PermanentProviderError, match="bad field"):
        provider.complete("s", "u")
    assert len(provider.requests) == 1  # type: ignore[attr-defined]


def test_a_rate_limit_stays_transient_and_is_retried() -> None:
    """Permanence is the exception; a 429 really does pass."""
    provider = provider_returning(
        httpx.Response(429, headers={"Retry-After": "0"}),
        httpx.Response(200, json=generate_content(json.dumps(ANSWER))),
    )
    assert json.loads(provider.complete("s", "u"))["intent"] == "fingerprinting"


def test_the_error_body_is_reduced_to_its_message() -> None:
    """Dumping the envelope buried the sentence naming the replacement model."""
    body = {"error": {"code": 400, "message": "a\n\n   b   c"}}
    provider = provider_returning(httpx.Response(400, json=body))

    with pytest.raises(PermanentProviderError) as caught:
        provider.complete("s", "u")
    assert "a b c" in str(caught.value)
    assert '"code"' not in str(caught.value)


def test_a_non_json_error_body_still_produces_something_readable() -> None:
    provider = provider_returning(httpx.Response(400, text="<html>  gateway\n error </html>"))
    with pytest.raises(PermanentProviderError, match="gateway error"):
        provider.complete("s", "u")


# --- Waiting for the right length of time ----------------------------------


def test_an_overloaded_model_is_waited_out_longer_than_a_dropped_connection() -> None:
    """Two seconds after a 503 is not a pause, it is another request."""
    provider = provider_returning()
    assert _BACKOFF["overloaded"][0] > _BACKOFF["network"][0]
    assert all(
        later >= earlier
        for schedule in _BACKOFF.values()
        for earlier, later in zip(schedule, schedule[1:], strict=False)
    ), "every schedule must grow"
    assert provider is not None


def test_a_rate_limit_obeys_the_wait_the_server_asked_for() -> None:
    """The server knows when its window resets; this code does not."""
    waited: list[float] = []
    provider = provider_returning(
        httpx.Response(429, headers={"Retry-After": "7"}),
        httpx.Response(200, json=generate_content(json.dumps(ANSWER))),
    )
    with mock.patch("honeypot_ai.classify.llm.gemini.time.sleep", waited.append):
        provider.complete("s", "u")

    assert 7.0 in waited


def test_a_nonsense_retry_after_falls_back_to_the_schedule() -> None:
    waited: list[float] = []
    provider = provider_returning(
        httpx.Response(429, headers={"Retry-After": "soon"}),
        httpx.Response(200, json=generate_content(json.dumps(ANSWER))),
    )
    with mock.patch("honeypot_ai.classify.llm.gemini.time.sleep", waited.append):
        provider.complete("s", "u")

    assert _BACKOFF["rate_limit"][0] in waited


def test_an_absurd_retry_after_is_capped() -> None:
    """A server asking for an hour must not stall the run for an hour."""
    provider = provider_returning(httpx.Response(429, headers={"Retry-After": "99999"}))
    assert provider._retry_after(httpx.Response(429, headers={"Retry-After": "99999"})) == 120.0


def test_the_default_model_is_pinned_not_an_alias() -> None:
    """An alias would move under the benchmark and invalidate the comparison."""
    assert "latest" not in DEFAULT_MODEL


def test_every_backoff_schedule_covers_every_attempt() -> None:
    """A schedule shorter than MAX_ATTEMPTS would reuse its last value in
    silence — fine by accident, wrong the moment either is tuned."""
    for kind, schedule in _BACKOFF.items():
        assert len(schedule) >= MAX_ATTEMPTS - 1, kind
