"""A model running on the homelab itself, behind the same provider contract.

The hosted model answered eight of ten requests in the first real run. The
other two were a service saying it was busy. That number is the reason this
exists: a model on your own hardware has no quota, no queue and no vendor, and
it cannot decline to look at malware because a safety filter fired. It will be
slower and probably less accurate, and those are exactly the trade-offs the
comparison in v0.5.0 is for.

Running it is also the only version of this pipeline that handles attacker
data without sending it anywhere, which for a project that argues carefully
about what leaves the homelab is worth being able to offer.

## The hardware is the constraint

The homelab is a laptop with 3.2 GB of RAM and no GPU, already running
PostgreSQL and Grafana, which leaves roughly 2.5 GB free. That rules out
anything beyond a couple of billion parameters and makes the choice of model a
measurement rather than a preference — which is why the deployment notes ask
for timings rather than recommending a model.
"""

from __future__ import annotations

import logging
import os
from types import TracebackType
from typing import Any, Self

import httpx

from honeypot_ai.classify.llm.provider import PermanentProviderError, ProviderError
from honeypot_ai.classify.taxonomy import Behaviour, Intent, Operator

logger = logging.getLogger(__name__)

DEFAULT_HOST = "http://127.0.0.1:11434"

#: Small on purpose. Quantised to four bits this is roughly 1.1 GB of weights,
#: which fits in the 2.5 GB this host has free with room for the context. A
#: larger model on a GPU-less machine with this much memory does not run
#: slowly, it swaps and effectively stops. Override with OLLAMA_MODEL and measure —
#: `--sample` reports per-session latency precisely so this can be chosen on
#: evidence rather than on which name sounds most capable.
DEFAULT_MODEL = "qwen2.5:1.5b"

#: Minutes, not seconds. A small model on CPU is slow, and a timeout that
#: fires before it finishes would record "unavailable" for something that was
#: merely thinking — the one failure mode that would make the comparison lie.
DEFAULT_TIMEOUT = 300.0

MAX_ATTEMPTS = 2
MAX_OUTPUT_TOKENS = 512


def response_schema() -> dict[str, Any]:
    """The answer's shape as standard JSON Schema, generated from the taxonomy.

    Ollama turns this into a grammar the model is constrained by while it
    generates, which matters far more for a small model than for a large one:
    the schema is most of what keeps a 1.5-billion-parameter model producing
    the right six keys instead of a paragraph of prose.

    Flat and self-contained — no `$ref` — because the grammar builder is
    happier that way and because it is one obvious thing to read.
    """
    return {
        "type": "object",
        "properties": {
            "intent": {"type": "string", "enum": [intent.value for intent in Intent]},
            "behaviours": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [behaviour.value for behaviour in Behaviour],
                },
            },
            "operator": {
                "type": "string",
                "enum": [operator.value for operator in Operator],
            },
            "confidence": {"type": "number"},
            "rationale": {"type": "string"},
        },
        "required": ["intent", "behaviours", "operator", "confidence", "rationale"],
    }


class OllamaProvider:
    """Calls a model served by a local Ollama instance."""

    def __init__(
        self,
        host: str | None = None,
        model: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        client: httpx.Client | None = None,
    ) -> None:
        self._host = (host or os.getenv("OLLAMA_HOST") or DEFAULT_HOST).rstrip("/")
        self._model = model or os.getenv("OLLAMA_MODEL") or DEFAULT_MODEL
        self._client = client or httpx.Client(timeout=timeout)

    @property
    def name(self) -> str:
        return f"ollama:{self._model}"

    def complete(self, system: str, user: str) -> str:
        """Ask the local model, and return its raw text."""
        body = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": response_schema(),
            "options": {
                # Zero, as with the hosted model: the comparison must measure
                # the model and not the sampler.
                "temperature": 0,
                "num_predict": MAX_OUTPUT_TOKENS,
            },
        }

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self._client.post(f"{self._host}/api/chat", json=body)
            except httpx.ConnectError as exc:
                raise PermanentProviderError(
                    f"No Ollama at {self._host}: {exc}. Start it, or set OLLAMA_HOST."
                ) from exc
            except httpx.HTTPError as exc:
                if attempt == MAX_ATTEMPTS:
                    raise ProviderError(f"could not reach Ollama: {exc}") from exc
                continue

            if response.status_code == httpx.codes.NOT_FOUND:
                raise PermanentProviderError(
                    f"Ollama has no model {self._model!r}. "
                    f"Pull it with `ollama pull {self._model}`, or set OLLAMA_MODEL "
                    "to one of the installed models."
                )

            if response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR:
                if attempt == MAX_ATTEMPTS:
                    raise ProviderError(f"Ollama returned {response.status_code}")
                continue

            if response.status_code != httpx.codes.OK:
                raise PermanentProviderError(
                    f"Ollama returned {response.status_code}: "
                    f"{' '.join(response.text.split())[:200]}"
                )

            return _extract_text(response.json())

        raise ProviderError(f"gave up after {MAX_ATTEMPTS} attempts")

    def list_models(self) -> list[str]:
        """The models pulled on this machine."""
        try:
            response = self._client.get(f"{self._host}/api/tags")
        except httpx.HTTPError as exc:
            raise PermanentProviderError(f"No Ollama at {self._host}: {exc}") from exc

        if response.status_code != httpx.codes.OK:
            raise ProviderError(f"could not list models: {response.status_code}")

        payload = response.json()
        models = payload.get("models", [])
        return [
            str(model["name"]) for model in models if isinstance(model, dict) and "name" in model
        ]

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


def _extract_text(payload: dict[str, Any]) -> str:
    """Pull the model's text out of an `/api/chat` response."""
    message = payload.get("message")
    if not isinstance(message, dict):
        raise ProviderError("Ollama returned no message")

    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ProviderError("Ollama returned empty content")

    return content
