"""Shared single-use nonce store (data-plane client).

`common.InMemoryNonceStore` enforces single-use only *within one proxy process*.
A horizontally-scaled proxy fleet needs a shared ledger, or an approved HITL token
consumed on instance A could be replayed against instance B (R-2). `HttpNonceStore`
consumes nonces via the control plane's atomic `POST /hitl/consume-nonce`, so
single-use holds fleet-wide.

It is used only on the HITL-token path (rare, human-gated), so the extra network
hop is off the common decision hot path. Fail closed: a transport error or non-2xx
propagates, and the pipeline turns any such failure into a deny rather than risk
allowing a possibly-replayed token. httpx is imported lazily so the package stays
importable without the proxy extra installed.
"""

from __future__ import annotations


class HttpNonceStore:
    """`NonceStore` backed by the control-plane ledger (atomic check-and-set)."""

    def __init__(self, base_url: str, agent_key: str, *, timeout: float = 2.0) -> None:
        self._url = base_url.rstrip("/") + "/hitl/consume-nonce"
        self._headers = {"X-Agent-Key": agent_key}
        self._timeout = timeout

    def consume(self, jti: str, expires_at: int) -> bool:
        import httpx

        response = httpx.post(
            self._url,
            json={"jti": jti, "expires_at": expires_at},
            headers=self._headers,
            timeout=self._timeout,
        )
        response.raise_for_status()
        return bool(response.json()["consumed"])
