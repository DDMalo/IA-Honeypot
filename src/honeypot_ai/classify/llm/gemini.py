"""Google Gemini, behind the project's provider contract.

Written against the REST API with `httpx` rather than the official SDK. The
SDK would be less code, but it would also bring a large dependency tree into a
project whose whole use of it is one POST, and it would hide the request body
— which here is the interesting part, because the response schema is generated
from the taxonomy and is what stops the model inventing labels at source.

Two layers of structure, deliberately:

* **At the API.** `responseMimeType` plus a `responseSchema` built from the
  taxonomy enums. The model is constrained to the allowed values rather than
  asked nicely for them.
* **At the parser.** The same reply still goes through the shared validation,
  because a constraint enforced by somebody else's service is a constraint
  that can change without telling you.

The second is not redundancy. It is the difference between trusting a vendor's
current behaviour and depending on it.
"""

from __future__ import annotations

import logging
import os
import time
from types import TracebackType
from typing import Any, Self

import httpx

from honeypot_ai.classify.llm.provider import PermanentProviderError, ProviderError
from honeypot_ai.classify.taxonomy import Behaviour, Intent, Operator

logger = logging.getLogger(__name__)

API_ROOT = "https://generativelanguage.googleapis.com/v1beta"

#: The smallest model that does the job, which is the right size for it: this
#: task is "put nine commands into one of seven categories", not something
#: that needs the largest model in the catalogue. The newest flagship was
#: tried first and spent its time returning 503 and 429; this one answered
#: every request on the first attempt.
#:
#: Pinned rather than an alias like `gemini-flash-latest`, because a benchmark
#: whose model silently changes underneath it is not a benchmark. The cost is
#: that this name will eventually be retired — it has happened to this project
#: once already — so `list_models()` reports what the key can reach and
#: `GEMINI_MODEL` overrides this without a code change.
DEFAULT_MODEL = "gemini-3.5-flash-lite"

#: Free-tier limits move, so this is a conservative floor rather than a claim
#: about the current quota: four seconds between requests is fifteen a minute.
#: Raise it if the API starts answering 429, and check the current limits in
#: Google's own documentation rather than trusting this comment.
DEFAULT_MIN_INTERVAL = 4.0

DEFAULT_TIMEOUT = 60.0
MAX_ATTEMPTS = 3

#: Seconds to wait before each retry, by what went wrong. A busy model needs
#: tens of seconds to recover; a dropped connection needs barely any.
_BACKOFF: dict[str, tuple[float, ...]] = {
    "network": (2.0, 5.0, 10.0),
    "overloaded": (5.0, 20.0, 45.0),
    "rate_limit": (20.0, 45.0, 90.0),
}
MAX_OUTPUT_TOKENS = 512


def response_schema() -> dict[str, Any]:
    """The answer's shape, generated from the taxonomy rather than restated.

    Generated so that adding a category to `taxonomy.py` cannot leave the API
    constraint describing last week's vocabulary — the class of bug that is
    invisible until a model is quietly unable to return a label that exists.
    """
    return {
        "type": "OBJECT",
        "properties": {
            "intent": {"type": "STRING", "enum": [intent.value for intent in Intent]},
            "behaviours": {
                "type": "ARRAY",
                "items": {
                    "type": "STRING",
                    "enum": [behaviour.value for behaviour in Behaviour],
                },
            },
            "operator": {
                "type": "STRING",
                "enum": [operator.value for operator in Operator],
            },
            "confidence": {"type": "NUMBER"},
            "rationale": {"type": "STRING"},
        },
        "required": ["intent", "behaviours", "operator", "confidence", "rationale"],
        "propertyOrdering": [
            "intent",
            "behaviours",
            "operator",
            "confidence",
            "rationale",
        ],
    }


class GeminiProvider:
    """Calls one Gemini model, paced and retrying."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        min_interval: float = DEFAULT_MIN_INTERVAL,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.Client | None = None,
    ) -> None:
        key = api_key if api_key is not None else os.getenv("GEMINI_API_KEY", "")
        if not key:
            raise PermanentProviderError("No Gemini API key. Set GEMINI_API_KEY in .env.")

        self._model = model or os.getenv("GEMINI_MODEL") or DEFAULT_MODEL
        self._min_interval = min_interval
        self._last_request = 0.0

        self._client = client or httpx.Client(timeout=timeout)
        # Applied to an injected client too. Setting them only on one we built
        # ourselves would mean a caller supplying a client — for a proxy, or
        # instrumentation — silently loses the key and 401s on every call.
        #
        # The key goes in a header, never the query string: URLs end up in
        # logs, proxies and error messages in a way headers mostly do not.
        self._client.headers.update({"x-goog-api-key": key, "Content-Type": "application/json"})

    @property
    def name(self) -> str:
        return f"gemini:{self._model}"

    def complete(self, system: str, user: str) -> str:
        """Ask the model, and return its raw text.

        Raises `ProviderError` for anything the classifier should count as the
        provider failing rather than the model being wrong — a rejected key, a
        safety block, an exhausted quota, an unreachable host.
        """
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                # Zero so the comparison in v0.5.0 measures the model rather
                # than the sampler, and so a rerun reproduces.
                "temperature": 0,
                "responseMimeType": "application/json",
                "responseSchema": response_schema(),
                "maxOutputTokens": MAX_OUTPUT_TOKENS,
            },
        }
        url = f"{API_ROOT}/models/{self._model}:generateContent"

        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._wait_turn()

            try:
                response = self._client.post(url, json=body)
            except httpx.HTTPError as exc:
                if attempt == MAX_ATTEMPTS:
                    raise ProviderError(f"could not reach Gemini: {exc}") from exc
                self._back_off(attempt)
                continue

            if response.status_code == httpx.codes.TOO_MANY_REQUESTS:
                if attempt == MAX_ATTEMPTS:
                    raise ProviderError("Gemini rate limit reached")
                asked = self._retry_after(response)
                if asked is not None:
                    time.sleep(asked)
                else:
                    self._back_off(attempt, "rate_limit")
                continue

            if response.status_code in (httpx.codes.UNAUTHORIZED, httpx.codes.FORBIDDEN):
                raise PermanentProviderError("Gemini rejected the API key")

            if response.status_code == httpx.codes.NOT_FOUND:
                raise PermanentProviderError(
                    f"Gemini has no model {self._model!r}: {_api_message(response)}. "
                    "Run `python -m honeypot_ai.classify.llm --models` to see what "
                    "this key can reach, then set GEMINI_MODEL in .env."
                )

            if response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR:
                if attempt == MAX_ATTEMPTS:
                    raise ProviderError(f"Gemini returned {response.status_code}")
                self._back_off(attempt, "overloaded")
                continue

            if response.status_code != httpx.codes.OK:
                # A 4xx not covered above is a malformed request: sending it
                # again changes nothing.
                raise PermanentProviderError(
                    f"Gemini returned {response.status_code}: {_api_message(response)}"
                )

            return _extract_text(response.json())

        raise ProviderError(f"gave up after {MAX_ATTEMPTS} attempts")

    def list_models(self) -> list[str]:
        """Model names this key can use.

        Worth having as code rather than a note in a README: the useful answer
        to "that model does not exist" is the list of the ones that do.
        """
        response = self._client.get(f"{API_ROOT}/models")
        if response.status_code != httpx.codes.OK:
            raise ProviderError(f"could not list models: {response.status_code}")
        payload = response.json()
        models = payload.get("models", [])
        return [
            str(model["name"]).removeprefix("models/")
            for model in models
            if isinstance(model, dict) and "name" in model
        ]

    def _wait_turn(self) -> None:
        elapsed = time.monotonic() - self._last_request
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)
        self._last_request = time.monotonic()

    def _back_off(self, attempt: int, kind: str = "network") -> None:
        """Wait before retrying, for a length that suits what went wrong.

        Treating every transient failure the same was wrong in a way that only
        showed up against a busy model: two seconds is a reasonable pause after
        a dropped connection and no pause at all for a service that has just
        said it is overloaded. A retry that arrives before the cause has
        cleared is an extra request on a service already struggling.
        """
        schedule = _BACKOFF.get(kind, _BACKOFF["network"])
        time.sleep(schedule[min(attempt, len(schedule)) - 1])

    @staticmethod
    def _retry_after(response: httpx.Response) -> float | None:
        """The wait the server asked for, when it asked for one.

        A 429 usually carries this, and obeying it beats guessing: the server
        knows when the window resets and this code does not.
        """
        header = response.headers.get("Retry-After")
        if header is None:
            return None
        try:
            return min(float(header), 120.0)
        except ValueError:
            return None

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _api_message(response: httpx.Response) -> str:
    """The one useful sentence out of an error body.

    Google returns a nested JSON error whose `message` says what is wrong; the
    rest is envelope. Dumping the raw body instead produced a wall of repeated
    JSON the first time a model name went stale here, with the sentence that
    named the replacement model cut off halfway.
    """
    try:
        payload = response.json()
    except ValueError:
        return " ".join(response.text.split())[:200]

    error = payload.get("error") if isinstance(payload, dict) else None
    message = error.get("message") if isinstance(error, dict) else None
    if isinstance(message, str) and message:
        return " ".join(message.split())[:300]
    return " ".join(response.text.split())[:200]


def _extract_text(payload: dict[str, Any]) -> str:
    """Pull the model's text out of a `generateContent` response.

    A refusal is a `ProviderError` rather than an empty answer, and that
    distinction matters here more than in most projects: this pipeline feeds a
    model real malware commands, so a safety filter declining to engage is a
    plausible, recurring outcome. Recorded as the provider failing, it shows up
    in the v0.5.0 comparison as a usable number — how much of a honeypot's
    traffic a hosted model will not look at — rather than as a mystery.
    """
    feedback = payload.get("promptFeedback")
    if isinstance(feedback, dict) and feedback.get("blockReason"):
        raise ProviderError(f"Gemini blocked the prompt: {feedback['blockReason']}")

    candidates = payload.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise ProviderError("Gemini returned no candidates")

    candidate = candidates[0]
    if not isinstance(candidate, dict):
        raise ProviderError("Gemini returned a malformed candidate")

    reason = candidate.get("finishReason")
    if reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT"}:
        raise ProviderError(f"Gemini stopped: {reason}")

    content = candidate.get("content")
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list) or not parts:
        # MAX_TOKENS arrives here: a truncated answer and nothing to show.
        raise ProviderError(f"Gemini returned no text (finishReason={reason})")

    text = "".join(str(part.get("text", "")) for part in parts if isinstance(part, dict))
    if not text.strip():
        raise ProviderError(f"Gemini returned empty text (finishReason={reason})")

    return text
