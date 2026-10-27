"""Tests for the local Ollama provider.

No Ollama, no model, no network. The point of a second provider is that it
meets the same contract as the first, and these check that rather than
re-testing the parsing and validation the shared classifier already covers.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from honeypot_ai.classify.llm.gemini import GeminiProvider
from honeypot_ai.classify.llm.ollama import (
    DEFAULT_MODEL,
    MAX_BEHAVIOURS,
    MAX_OUTPUT_TOKENS,
    MAX_RATIONALE_CHARS,
    SEED,
    OllamaProvider,
    response_schema,
)
from honeypot_ai.classify.llm.provider import PermanentProviderError, Provider, ProviderError
from honeypot_ai.classify.llm.schema import MAX_RATIONALE_CHARS as SCHEMA_MAX_RATIONALE
from honeypot_ai.classify.taxonomy import Behaviour, Intent, Operator

ANSWER = {
    "intent": "staging",
    "behaviours": ["writable_dir_hunt", "payload_download"],
    "operator": "automated",
    "confidence": 0.8,
    "rationale": "hunted for a writable directory and attempted a download",
}


def chat_response(text: str) -> dict[str, Any]:
    return {"model": "test", "message": {"role": "assistant", "content": text}, "done": True}


def provider_returning(*responses: httpx.Response) -> OllamaProvider:
    queue = list(responses)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return queue.pop(0) if queue else httpx.Response(200, json=chat_response("{}"))

    provider = OllamaProvider(
        host="http://testhost:11434",
        model="test-model",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    provider.requests = seen  # type: ignore[attr-defined]
    return provider


# --- The same contract as the hosted provider ------------------------------


def test_the_provider_satisfies_the_protocol() -> None:
    assert isinstance(provider_returning(), Provider)


def test_the_name_distinguishes_the_backend_as_well_as_the_model() -> None:
    """Stored results have to tell a local model from a hosted one."""
    assert provider_returning().name == "ollama:test-model"
    assert (
        provider_returning().name.split(":")[0]
        != GeminiProvider(api_key="k", model="m").name.split(":")[0]
    )


def test_a_normal_reply_returns_its_text() -> None:
    provider = provider_returning(httpx.Response(200, json=chat_response(json.dumps(ANSWER))))
    assert json.loads(provider.complete("s", "u"))["intent"] == "staging"


# --- The schema, which matters more here than it does for a large model ----


def test_the_schema_offers_every_taxonomy_value() -> None:
    schema = response_schema()
    assert set(schema["properties"]["intent"]["enum"]) == {i.value for i in Intent}
    assert set(schema["properties"]["behaviours"]["items"]["enum"]) == {b.value for b in Behaviour}
    assert set(schema["properties"]["operator"]["enum"]) == {o.value for o in Operator}


def test_the_schema_is_flat_so_the_grammar_builder_can_use_it() -> None:
    """A `$ref` is where a grammar-constrained decoder is most likely to trip."""
    assert "$ref" not in json.dumps(response_schema())
    assert "$defs" not in json.dumps(response_schema())


def test_the_request_constrains_generation_to_that_schema() -> None:
    provider = provider_returning(httpx.Response(200, json=chat_response(json.dumps(ANSWER))))
    provider.complete("system prompt", "user prompt")

    body = json.loads(provider.requests[0].content)  # type: ignore[attr-defined]
    assert body["format"] == response_schema()
    assert body["stream"] is False
    assert body["options"]["temperature"] == 0


def test_the_system_prompt_is_its_own_message() -> None:
    provider = provider_returning(httpx.Response(200, json=chat_response(json.dumps(ANSWER))))
    provider.complete("SYSTEM RULES", "session data")

    body = json.loads(provider.requests[0].content)  # type: ignore[attr-defined]
    assert body["messages"][0] == {"role": "system", "content": "SYSTEM RULES"}
    assert body["messages"][1] == {"role": "user", "content": "session data"}


# --- Failures particular to running it yourself ----------------------------


def test_nothing_listening_says_so_and_is_not_retried() -> None:
    """The fix is to start Ollama, which no number of retries will do."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    provider = OllamaProvider(client=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(PermanentProviderError, match="No Ollama at"):
        provider.complete("s", "u")


def test_a_model_that_was_never_pulled_says_how_to_pull_it() -> None:
    provider = provider_returning(httpx.Response(404, json={"error": "model not found"}))

    with pytest.raises(PermanentProviderError) as caught:
        provider.complete("s", "u")
    assert "ollama pull test-model" in str(caught.value)


def test_a_server_error_is_retried() -> None:
    provider = provider_returning(
        httpx.Response(500, text="out of memory"),
        httpx.Response(200, json=chat_response(json.dumps(ANSWER))),
    )
    assert json.loads(provider.complete("s", "u"))["intent"] == "staging"


def test_an_empty_answer_is_an_error_not_an_empty_label() -> None:
    provider = provider_returning(httpx.Response(200, json=chat_response("   ")))
    with pytest.raises(ProviderError, match="empty content"):
        provider.complete("s", "u")


def test_a_reply_with_no_message_is_an_error() -> None:
    provider = provider_returning(httpx.Response(200, json={"done": True}))
    with pytest.raises(ProviderError, match="no message"):
        provider.complete("s", "u")


# --- Configuration ---------------------------------------------------------


def test_the_host_can_be_set_and_trailing_slashes_do_not_double_up() -> None:
    provider = OllamaProvider(host="http://box:11434/", model="m")
    assert provider._host == "http://box:11434"


def test_the_default_model_is_small_enough_for_a_laptop() -> None:
    """Not a style preference: a larger model on this hardware swaps and stops."""
    assert any(size in DEFAULT_MODEL for size in ("0.5b", "1b", "1.5b", "2b", "3b"))


def test_installed_models_are_listed_by_their_tags() -> None:
    payload = {"models": [{"name": "qwen2.5:1.5b"}, {"name": "llama3.2:3b"}]}
    provider = provider_returning(httpx.Response(200, json=payload))
    assert provider.list_models() == ["qwen2.5:1.5b", "llama3.2:3b"]


# --- Truncation, which is what the first real run actually hit -------------
#
# Eight of ten sessions came back as "reply was not JSON: unterminated string
# at column 2043". The model was not producing bad JSON; it was producing good
# JSON that the token ceiling cut in half, because nothing limited how long a
# rationale it could write.


def test_the_rationale_is_length_capped_in_the_schema() -> None:
    """The cap is the fix. More tokens would only buy a longer ramble."""
    rationale = response_schema()["properties"]["rationale"]
    assert rationale["maxLength"] == MAX_RATIONALE_CHARS


def test_the_cap_matches_what_validation_would_keep() -> None:
    """Asking for more than the validator stores would waste the tokens."""
    assert MAX_RATIONALE_CHARS <= SCHEMA_MAX_RATIONALE


def test_hitting_the_token_ceiling_is_reported_as_itself() -> None:
    """Not as a JSON error three layers away, where it reads as the model's fault."""
    payload = {
        "message": {"role": "assistant", "content": '{"intent": "staging", "rational'},
        "done": True,
        "done_reason": "length",
    }
    provider = provider_returning(httpx.Response(200, json=payload))

    with pytest.raises(PermanentProviderError, match="cut off"):
        provider.complete("s", "u")


def test_the_truncation_error_shows_what_the_model_was_writing() -> None:
    """Otherwise the fix is guesswork: a loop and a ramble look identical."""
    looping = '{"behaviours": ["shell_escape", "shell_escape", "shell_escape"'
    payload = {
        "message": {"role": "assistant", "content": looping},
        "done_reason": "length",
    }
    provider = provider_returning(httpx.Response(200, json=payload))

    with pytest.raises(PermanentProviderError) as caught:
        provider.complete("s", "u")
    assert "shell_escape" in str(caught.value)


def test_truncation_is_permanent_so_it_is_not_retried() -> None:
    """At temperature zero the same request returns the same answer. Retrying
    a deterministic failure buys another minute and a half of nothing."""
    payload = {"message": {"content": "{"}, "done_reason": "length"}
    provider = provider_returning(httpx.Response(200, json=payload))

    with pytest.raises(PermanentProviderError):
        provider.complete("s", "u")
    assert len(provider.requests) == 1  # type: ignore[attr-defined]


def test_the_behaviour_list_is_bounded() -> None:
    """An unbounded array lets a constrained model repeat values forever."""
    behaviours = response_schema()["properties"]["behaviours"]
    assert behaviours["maxItems"] == MAX_BEHAVIOURS
    assert MAX_BEHAVIOURS < len(list(Behaviour))


def test_the_token_ceiling_is_tight_enough_to_fail_fast() -> None:
    """Generous ceilings do not prevent loops, they only pay for them."""
    assert MAX_OUTPUT_TOKENS <= 400


def test_a_normal_stop_is_not_mistaken_for_truncation() -> None:
    payload = {
        "message": {"role": "assistant", "content": json.dumps(ANSWER)},
        "done": True,
        "done_reason": "stop",
    }
    provider = provider_returning(httpx.Response(200, json=payload))
    assert json.loads(provider.complete("s", "u"))["intent"] == "staging"


# --- Reproducibility -------------------------------------------------------


def test_generation_is_seeded_so_two_runs_are_comparable() -> None:
    """Temperature zero is not by itself reproducible. Two runs of the
    injection suite gave different answers on two of twelve cases, which is
    enough to move a published number without anyone noticing."""
    provider = provider_returning(httpx.Response(200, json=chat_response(json.dumps(ANSWER))))
    provider.complete("s", "u")

    body = json.loads(provider.requests[0].content)  # type: ignore[attr-defined]
    assert body["options"]["seed"] == SEED
