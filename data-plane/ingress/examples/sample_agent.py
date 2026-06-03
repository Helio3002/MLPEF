"""Sample governed agent — calls a tool through the MLPEF REST ingress.

Prereqs: run control-api (migrate + seed), run the ingress app (uvicorn), and export
the sample agent's id + API key (printed by `python -m app.seed`):

    export MLPEF_INGRESS_URL=http://localhost:8080
    export MLPEF_AGENT_ID=<sample-agent-id>
    export MLPEF_AGENT_KEY=<sample-agent-key>
    python data-plane/ingress/examples/sample_agent.py

A locked-down agent is DENIED until an operator grants the tool in the admin UI —
that denial is the system working as intended.
"""

from __future__ import annotations

import os

import httpx

MLPEF_URL = os.environ.get("MLPEF_INGRESS_URL", "http://localhost:8080")
AGENT_ID = os.environ.get("MLPEF_AGENT_ID", "")
AGENT_KEY = os.environ.get("MLPEF_AGENT_KEY", "")


def execute(tool: str, action: str, resource: str, **arguments: object) -> httpx.Response:
    response = httpx.post(
        f"{MLPEF_URL}/v1/execute",
        headers={"X-Agent-Id": AGENT_ID, "X-Agent-Key": AGENT_KEY},
        json={"tool": tool, "action": action, "resource": resource, "arguments": arguments},
        timeout=10.0,
    )
    print(f"{response.status_code}  {response.json()}")
    return response


if __name__ == "__main__":
    execute("shell.exec", "shell.exec", "-", argv=["echo", "hello from a governed agent"])
