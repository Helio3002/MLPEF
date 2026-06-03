"""A generic governed-tool decorator (reference SDK shim).

Wrap any tool function so the call is enforced before it runs: the decorator
normalizes the call into an Intent, submits it to the pipeline, and only invokes
the underlying function on ALLOW (otherwise it raises GovernanceDenied). Pass
`approval_token=...` in the call to satisfy a HITL gate.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from common import IngressSource

from ..base import GovernedHandler, build_intent


class GovernanceDenied(RuntimeError):
    """Raised when MLPEF denies (or requires approval for) a governed tool call."""


def governed(
    handler: GovernedHandler,
    *,
    agent_id: str,
    credential: str,
    tool: str,
    action: str | None = None,
    tenant: str = "default",
    resource_key: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            token = kwargs.get("approval_token")
            arguments = {key: value for key, value in kwargs.items() if key != "approval_token"}
            resource = str(kwargs.get(resource_key, "-")) if resource_key else "-"
            intent = build_intent(
                agent_id=agent_id,
                tenant=tenant,
                tool=tool,
                action=action or tool,
                resource=resource,
                arguments=arguments,
                ingress=IngressSource.SDK_SHIM,
                approval_token=token if isinstance(token, str) else None,
            )
            outcome = handler.handle(intent, credential=credential)
            if not outcome.result.allowed:
                raise GovernanceDenied(
                    f"MLPEF {outcome.result.final_verdict.value} for {tool}: {outcome.result.reason}"
                )
            return func(*args, **kwargs)

        return wrapper

    return decorator
