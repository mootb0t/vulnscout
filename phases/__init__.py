"""Engagement (interactive exploitation guidance).

The old phase pipeline (intel / exploits / exposure / discovery /
analysis) is gone — those tools are now individual Tasks under
plugins/. Engagement remains a phase because it's an interactive,
user-driven loop rather than a fact-driven graph; rewriting its
~3400 lines for the new API isn't worth the disruption.

Engagement consumes a materialized ScanState (built from the FactStore
by core.state_view.materialize) and writes loot back into the store
via core.state_view.echo_state_change.
"""

from .engagement import (
    EngagementAction, EngagementLogEntry, build_action_queue,
    cleanup_tmpfiles, execute_action,
)

__all__ = [
    "EngagementAction", "EngagementLogEntry",
    "build_action_queue", "execute_action", "cleanup_tmpfiles",
]
