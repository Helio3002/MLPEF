"""Thin SDK shims: a generic decorator + a LangChain-style tool wrapper."""

from __future__ import annotations

from .decorator import GovernanceDenied, governed
from .langchain import GovernedTool

__all__ = ["GovernanceDenied", "GovernedTool", "governed"]
