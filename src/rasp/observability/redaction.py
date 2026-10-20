"""Log redaction policy (Milestone 3).

RASP logs identifiers, decisions, and reason codes only. The following are
NEVER logged, by design and by the structural absence of any API that would
let a caller pass them to a log call:

- prompt / chat message text;
- tool arguments and tool outputs;
- retrieved documents or private records;
- credentials, tokens, and connection strings.

`LOG_REDACTION_NOTE` is embedded in the module documentation and asserted by
the logging canary tests so the guarantee is explicit and testable.
"""

from __future__ import annotations

LOG_REDACTION_NOTE = (
    "RASP logs contain identifiers, decisions, and reason codes only — "
    "never prompts, tool arguments, outputs, records, or credentials."
)

__all__ = ["LOG_REDACTION_NOTE"]
