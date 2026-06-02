"""MLPEF control-api — the control-plane service.

FastAPI app exposing agent registration, policy-profile and tool CRUD, the
config-bundle endpoint the proxy pulls, and admin auth + RBAC.

Run from this directory (`control-plane/control-api`) so the `app` package is
importable; `common` is installed via the repo-root `pip install -e .`.
"""
