"""
Output exporters — bridge ``Finding``/``ToolExecution`` to external systems.

Each exporter consumes the in-memory ``PentestMemory`` and emits a
sink-specific representation. Reused across the report command
(``cli/commands/report.py``) and CI integrations.

Exporters are thin: they only translate the schema. They never invoke
LLMs, never re-validate findings (that's the analyst's job), never
mutate ``PentestMemory``. This keeps them safe to run on any saved
session JSON.
"""
