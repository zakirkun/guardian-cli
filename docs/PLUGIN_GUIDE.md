# Guardian Plugin Guide

Guardian discovers tools and AI providers via setuptools entry points.
Third-party packages can ship Guardian extensions without forking core.

Two extension surfaces:

  * `guardian.providers` — new AI provider implementations (Ollama, vLLM,
    Together, fine-tunes, etc.)
  * `guardian.tools` — new security tool wrappers (custom scanners,
    proprietary CLI bridges, internal tooling)

## Provider plugin

Implement `BaseProvider` from `ai/providers/base_provider.py`. Required
methods: `generate`, `generate_sync`, `generate_with_usage`,
`get_model_name`, `is_available`, `_initialize`.

Use the BaseProvider helpers — they're free:

  * `_with_retry(coro_factory, is_retriable)` — exponential backoff
  * `_enforce_token_budget(total_tokens)` — abort at budget exhaustion
  * `_apply_rate_limit()` — async, concurrency-safe
  * `_estimate_cost(prompt_tokens, completion_tokens)` — uses config pricing

```python
# my_pkg/my_provider.py
from ai.providers.base_provider import BaseProvider

class MyProvider(BaseProvider):
    def __init__(self, config, logger):
        super().__init__(config, logger)
        self._initialize()

    def _initialize(self):
        ...

    async def generate_with_usage(self, prompt, system_prompt, context=None):
        await self._apply_rate_limit()
        # ... call your backend ...
        self._enforce_token_budget(total_tokens)
        return {
            "response": text,
            "reasoning": "",
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "total_tokens": pt + ct,
            "cost_usd": self._estimate_cost(pt, ct),
            "model": self.get_model_name(),
            "provider": "my_provider",
        }
    # ... and the other abstract methods ...
```

Register in your package's `pyproject.toml`:

```toml
[project.entry-points."guardian.providers"]
my_provider = "my_pkg.my_provider:MyProvider"
```

Use it from `config/guardian.yaml`:

```yaml
ai:
  provider: my_provider
  my_provider:
    api_key: ...
```

## Tool plugin

Implement `BaseTool` from `tools/base_tool.py`. Override `get_command` and
`parse_output`. Inherit async exec, streaming, ANSI strip, timeout, and
skip-on-missing for free.

```python
# my_pkg/my_scanner.py
from typing import Any, Dict, List
from tools.base_tool import BaseTool

class MyScannerTool(BaseTool):
    def __init__(self, config):
        super().__init__(config)
        self.tool_name = "my-scanner"   # binary in PATH

    def get_command(self, target: str, **kwargs: Any) -> List[str]:
        return ["my-scanner", "--target", target, "--format", "json"]

    def parse_output(self, output: str) -> Dict[str, Any]:
        # Return a dict — typical keys: vulnerabilities, by_severity, count
        ...
```

Register:

```toml
[project.entry-points."guardian.tools"]
my-scanner = "my_pkg.my_scanner:MyScannerTool"
```

## Collision rules

In-tree always wins. A plugin trying to overwrite a name that exists in
`PROVIDERS` (or `TOOL_REGISTRY`) is logged at WARNING and ignored. Pick a
distinct name.

## Risk classification (tools only)

Plugin tools default to `active` risk class — they will prompt for user
confirmation. Override by extending `core/tool_agent.TOOL_RISK_CLASS` at
import time:

```python
# my_pkg/__init__.py
from core.tool_agent import TOOL_RISK_CLASS
TOOL_RISK_CLASS["my-scanner"] = "passive"
```

Or by setting `risk_class` on the class itself (future contract — TBD).

## Security caveats

A plugin can run any code in the Guardian process. Only install
plugins from trusted sources. The entry-point discovery surface is the
same trust boundary as `pip install` — apply the same scrutiny.

For research / sandboxed plugins, run Guardian inside a container.
