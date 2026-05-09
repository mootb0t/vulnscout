"""Core orchestration primitives.

The redesign replaces the linear three-phase pipeline + mutable ScanState
with four cooperating pieces:

  - facts.py     — typed, append-only fact records with provenance
  - store.py     — thread-safe FactStore + indexed queries
  - tasks.py     — Task descriptors (requires/produces/condition/run)
  - scheduler.py — DAG scheduler that runs tasks as their requirements
                   become satisfied, in parallel, with cancellation
  - events.py    — EventBus the TUI subscribes to (no transport coupling)
  - policy.py    — replaces profiles.Profile; declares allowlist + intensity
                   knobs + parallelism + budget

Phase modules are gone. Each former phase tool is now a Task in plugins/.
"""
