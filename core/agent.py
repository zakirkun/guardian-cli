"""
Base agent class for all Guardian AI agents.
Provides think() and think_deeply() for chain-of-thought reasoning,
and records every AI call as a TokenUsage + ThinkingStep in memory.
"""

from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from datetime import datetime

from ai.gemini_client import GeminiClient
from core.memory import PentestMemory, TokenUsage, ThinkingStep
from utils.logger import get_logger


class BaseAgent(ABC):
    """Base class for all AI agents in Guardian"""

    def __init__(
        self,
        name: str,
        config: Dict[str, Any],
        gemini_client: GeminiClient,
        memory: PentestMemory,
    ):
        self.name = name
        self.config = config
        self.gemini = gemini_client
        self.memory = memory
        self.logger = get_logger(config)
        self._step_counter = 0   # thinking step counter for this agent instance

    @abstractmethod
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the agent's primary function"""
        pass

    # ── Core reasoning methods ────────────────────────────────────────────────

    async def think(self, prompt: str, system_prompt: str) -> Dict[str, Any]:
        """
        Single-round AI reasoning call.

        Returns a dict with:
          response, reasoning, prompt_tokens, completion_tokens,
          total_tokens, cost_usd, model, provider
        Also records a ThinkingStep and TokenUsage in PentestMemory.
        """
        try:
            result = await self.gemini.generate_with_usage(
                prompt=prompt,
                system_prompt=system_prompt,
            )

            self._record_usage_and_step(prompt, result, round_number=1)
            return result

        except Exception as e:
            self.logger.error(f"Agent {self.name} think() error: {e}")
            raise

    async def think_deeply(
        self,
        prompt: str,
        system_prompt: str,
        max_rounds: int = 3,
    ) -> Dict[str, Any]:
        """
        Multi-round iterative reasoning loop.

        Round 1: initial answer.
        Rounds 2…max_rounds: the model critiques and improves its own previous answer.

        Builds a richer, more accurate conclusion than a single call.
        
        Returns a dict with:
          response (final answer), reasoning (last reasoning),
          thinking_chain (list of all round responses),
          total_tokens (sum across all rounds), total_cost_usd
        """
        previous_answer = ""
        thinking_chain: List[str] = []
        accumulated_tokens = 0
        accumulated_cost = 0.0
        last_result: Dict[str, Any] = {}

        for round_num in range(1, max_rounds + 1):
            if round_num == 1:
                round_prompt = prompt
            else:
                # Ask the model to critique and improve its prior answer
                round_prompt = (
                    f"{prompt}\n\n"
                    f"--- YOUR PREVIOUS ANSWER (Round {round_num - 1}) ---\n"
                    f"{previous_answer}\n\n"
                    f"--- CRITIQUE & IMPROVEMENT TASK ---\n"
                    f"Critically review your previous answer. Identify:\n"
                    f"1. Logical gaps or missing considerations\n"
                    f"2. Facts that need strengthening with evidence\n"
                    f"3. Conclusions that could be more precise\n\n"
                    f"Then provide an improved, final answer that addresses these gaps. "
                    f"If the previous answer was already optimal, say so and repeat it."
                )

            try:
                result = await self.gemini.generate_with_usage(
                    prompt=round_prompt,
                    system_prompt=system_prompt,
                )
            except Exception as e:
                self.logger.error(f"think_deeply round {round_num} error: {e}")
                # Return what we have so far on error
                break

            self._record_usage_and_step(round_prompt, result, round_number=round_num)

            previous_answer = result["response"]
            thinking_chain.append(result["response"])
            accumulated_tokens += result.get("total_tokens", 0)
            accumulated_cost   += result.get("cost_usd", 0.0)
            last_result = result

            self.logger.debug(
                f"[{self.name}] think_deeply round {round_num}/{max_rounds} "
                f"| tokens: {result.get('total_tokens', 0)}"
            )

        return {
            "response":        last_result.get("response", ""),
            "reasoning":       last_result.get("reasoning", ""),
            "thinking_chain":  thinking_chain,
            "total_tokens":    accumulated_tokens,
            "total_cost_usd":  round(accumulated_cost, 8),
            "model":           last_result.get("model", ""),
            "provider":        last_result.get("provider", ""),
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _record_usage_and_step(
        self,
        prompt: str,
        result: Dict[str, Any],
        round_number: int = 1,
    ):
        """Store a TokenUsage + ThinkingStep in memory and emit log entries."""
        self._step_counter += 1
        ts = datetime.now().isoformat()

        # ── Token ledger ──────────────────────────────────────────────────────
        usage = TokenUsage(
            timestamp         = ts,
            agent             = self.name,
            model             = result.get("model", self.gemini.get_model_name()),
            provider          = result.get("provider", "unknown"),
            prompt_tokens     = result.get("prompt_tokens", 0),
            completion_tokens = result.get("completion_tokens", 0),
            total_tokens      = result.get("total_tokens", 0),
            cost_usd          = result.get("cost_usd", 0.0),
        )
        self.memory.add_token_usage(usage)

        # ── Thinking chain ────────────────────────────────────────────────────
        step = ThinkingStep(
            timestamp      = ts,
            agent          = self.name,
            step_number    = self._step_counter,
            prompt_summary = prompt[:300],
            reasoning      = result.get("reasoning", ""),
            conclusion     = result["response"][:300],
            tokens_used    = result.get("total_tokens", 0),
            round_number   = round_number,
        )
        self.memory.add_thinking_step(step)

        # ── AI decision log ───────────────────────────────────────────────────
        self.memory.add_ai_decision(
            agent     = self.name,
            decision  = result["response"],
            reasoning = result.get("reasoning", ""),
        )

        # ── Audit log ─────────────────────────────────────────────────────────
        self.logger.log_ai_decision(
            agent     = self.name,
            decision  = result["response"],
            reasoning = result.get("reasoning", ""),
            context   = {
                "prompt":    prompt[:200],
                "tokens":    result.get("total_tokens", 0),
                "cost_usd":  result.get("cost_usd", 0.0),
                "model":     result.get("model", ""),
                "round":     round_number,
            },
        )

    def log_action(self, action: str, details: str):
        """Log a named agent action"""
        self.logger.info(f"[{self.name}] {action}: {details}")
