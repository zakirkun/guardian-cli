"""
AI Client for Guardian
Generic client that delegates to specific providers (Gemini, OpenAI, Claude, OpenRouter)
and exposes generate_with_usage() + get_token_report() for token cost tracking.
"""

from typing import Optional, Dict, Any, List
from ai.providers import get_provider
from utils.logger import get_logger


class AIClient:
    """
    Unified AI client that works with multiple providers.
    Delegates all operations to the configured provider.
    Adds generate_with_usage() for token cost tracking and
    get_token_report() for report generation.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger(config)

        # Load the appropriate provider based on config
        self.provider = get_provider(config)

        # Expose provider's model name
        self.model_name = self.provider.get_model_name()
        self.logger.info(
            f"AIClient initialized with {self.provider.__class__.__name__}: {self.model_name}"
        )

    # ── Text generation (basic) ───────────────────────────────────────────────

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        """Generate AI response asynchronously (text only)"""
        return await self.provider.generate(prompt, system_prompt, context)

    def generate_sync(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        context: Optional[list] = None,
    ) -> str:
        """Generate AI response synchronously (text only)"""
        return self.provider.generate_sync(prompt, system_prompt, context)

    # ── Text generation + token tracking ─────────────────────────────────────

    async def generate_with_usage(
        self,
        prompt: str,
        system_prompt: str,
        context: Optional[list] = None,
    ) -> Dict[str, Any]:
        """
        Generate a response AND return full token usage metadata.

        Returns:
          {
            "response":           str,
            "reasoning":          str,
            "prompt_tokens":      int,
            "completion_tokens":  int,
            "total_tokens":       int,
            "cost_usd":           float,
            "model":              str,
            "provider":           str,
          }
        """
        return await self.provider.generate_with_usage(prompt, system_prompt, context)

    async def generate_with_reasoning(
        self,
        prompt: str,
        system_prompt: str,
        task_context: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Backward-compatible wrapper around generate_with_usage().
        Always returns at least {"response", "reasoning"}.
        """
        return await self.provider.generate_with_reasoning(prompt, system_prompt, task_context)

    # ── Token reporting ───────────────────────────────────────────────────────

    @staticmethod
    def get_token_report(memory) -> str:
        """
        Generate a formatted text token-cost report from memory.token_ledger.
        Suitable for embedding in CLI output or the report appendix.

        Args:
            memory: PentestMemory instance

        Returns:
            Formatted multi-line string with token usage tables.
        """
        summary = memory.get_token_summary()

        lines: List[str] = [
            "",
            "╔══════════════════════════════════════════════════════════╗",
            "║              AI USAGE & COST SUMMARY                    ║",
            "╚══════════════════════════════════════════════════════════╝",
            "",
            "  By Agent:",
            f"  {'Agent':<20} {'Model':<30} {'Tokens':>10} {'Est. USD':>12}",
            "  " + "─" * 76,
        ]

        for entry in memory.token_ledger:
            lines.append(
                f"  {entry.agent:<20} {entry.model:<30} "
                f"{entry.total_tokens:>10,} {entry.cost_usd:>11.6f}"
            )

        lines += [
            "",
            "  By Provider:",
            f"  {'Provider':<20} {'Calls':>8} {'Tokens':>12} {'Est. USD':>14}",
            "  " + "─" * 58,
        ]
        for provider, data in summary.get("by_provider", {}).items():
            lines.append(
                f"  {provider:<20} {data['calls']:>8} "
                f"{data['tokens']:>12,} {data['cost_usd']:>13.6f}"
            )

        lines += [
            "",
            "  ─" * 40,
            f"  TOTAL PROMPT TOKENS     : {summary['total_prompt_tokens']:>12,}",
            f"  TOTAL COMPLETION TOKENS : {summary['total_completion_tokens']:>12,}",
            f"  TOTAL TOKENS            : {summary['total_tokens']:>12,}",
            f"  ESTIMATED TOTAL COST    : ${summary['total_cost_usd']:>11.4f} USD",
            f"  AI CALLS                : {len(memory.token_ledger):>12}",
            f"  THINKING STEPS          : {len(memory.thinking_chain):>12}",
            "",
            "  Note: Costs are estimates based on ai.pricing in config/guardian.yaml.",
            "        Actual billed amounts may differ.",
            "",
        ]

        return "\n".join(lines)

    # ── Introspection ─────────────────────────────────────────────────────────

    def get_model_name(self) -> str:
        """Get the current model name"""
        return self.model_name

    def is_available(self) -> bool:
        """Check if the provider is properly configured"""
        return self.provider.is_available()


# Backward compatibility alias
GeminiClient = AIClient
