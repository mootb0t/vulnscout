"""Tool plugins.

Each module in this package registers one or more Tasks at import time.
Importing this package via `from vulnscout import plugins` is enough to
populate the task registry — the scheduler does not need to know about
individual plugins.

Add a new tool: drop a file in here, declare a Task, call register().
No edits anywhere else.
"""

# The order of imports here doesn't matter — Tasks self-register and the
# scheduler resolves dependencies dynamically via the FactStore.

from . import (    # noqa: F401  (imported for side effects: task registration)
    passive_intel,
    network,
    web_recon,
    web_scan,
    web_fuzz,
    exposure,
    cve_xref,
    file_discovery,
    synthesis,
)
