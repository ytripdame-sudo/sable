"""Packaging side of SABLE.

Nothing under ``core/`` imports ``agent/``: the agent is the thing being packaged,
not a dependency of the packager. The two halves meet at three documented contracts
— the archive layout, the seal format, and the footer — and each is pinned by a test
rather than by a shared import.
"""
