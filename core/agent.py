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
        judge_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Multi-round iterative reasoning loop.

        Round 1: initial answer.
        Rounds 2…max_rounds: the model critiques and improves its own previous answer.

        If ``judge_model`` is provided, after the configured rounds a SEPARATE
        provider — typically a smaller/cheaper one — reads the full transcript
        and selects the best answer. This decouples the *thinker* (expensive,
        high-capability) from the *judge* (cheap, fast). Common pattern:
        gpt-4o for rounds + gpt-4o-mini as judge ⇒ ~10x cost reduction at
        equal or better quality.

        ``judge_model`` accepts either a model identifier (string) — the
        existing client switches model — or ``None`` to keep the legacy
        single-model self-critique behaviour.

        Returns a dict with:
          response (final answer), reasoning (last reasoning),
          thinking_chain (list of all round responses),
          total_tokens (sum across all rounds INCLUDING judge), total_cost_usd,
          judge_used (bool), judge_selected_round (int|None)
        """
        # Per-call resolution: explicit kwarg > config > none.
        judge_model = judge_model or self.config.get("ai", {}).get("judge_model")

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

        # ── Optional judge pass ───────────────────────────────────────────────
        judge_used = False
        judge_selected_round: Optional[int] = None
        if judge_model and len(thinking_chain) >= 2:
            judge_result = await self._invoke_judge(
                question=prompt,
                rounds=thinking_chain,
                judge_model=judge_model,
            )
            if judge_result is not None:
                judge_used = True
                judge_selected_round = judge_result["selected_round"]
                # Replace the surfaced answer with the judge's pick. The
                # losing rounds remain in ``thinking_chain`` for audit.
                if 0 <= judge_selected_round - 1 < len(thinking_chain):
                    last_result = dict(last_result)
                    last_result["response"] = thinking_chain[judge_selected_round - 1]
                accumulated_tokens += judge_result.get("total_tokens", 0)
                accumulated_cost += judge_result.get("cost_usd", 0.0)

        return {
            "response":             last_result.get("response", ""),
            "reasoning":            last_result.get("reasoning", ""),
            "thinking_chain":       thinking_chain,
            "total_tokens":         accumulated_tokens,
            "total_cost_usd":       round(accumulated_cost, 8),
            "model":                last_result.get("model", ""),
            "provider":             last_result.get("provider", ""),
            "judge_used":           judge_used,
            "judge_selected_round": judge_selected_round,
        }

    async def _invoke_judge(
        self,
        question: str,
        rounds: List[str],
        judge_model: str,
    ) -> Optional[Dict[str, Any]]:
        """Cheap-judge pass: pick the best answer from rounds.

        The judge runs on a different model. The simplest implementation
        — used here — temporarily swaps the underlying model on the same
        client, calls once, restores. A cleaner future contract would
        accept a separate provider instance; this preserves backwards
        compatibility while delivering the cost savings the upgrade exists
        to capture.

        Returns ``None`` on any failure so the caller falls back to the
        last-round answer (legacy behaviour). Never raises.
        """
        prompt_lines = [
            "You are an impartial judge. The following are candidate answers "
            "produced in successive critique rounds for the same question. "
            "Pick the single best round.",
            "",
            "## ORIGINAL QUESTION",
            question[:2000],
            "",
            "## CANDIDATE ANSWERS",
        ]
        for i, round_text in enumerate(rounds, start=1):
            prompt_lines.append(f"\n### Round {i}\n{round_text[:3000]}")
        prompt_lines.extend([
            "",
            "## INSTRUCTIONS",
            "Reply with a JSON object only:",
            '  {"selected_round": <integer 1..N>, "reason": "<one sentence>"}',
            "Pick the round that is most accurate, complete, and grounded in evidence.",
        ])
        judge_prompt = "\n".join(prompt_lines)

        # Swap model on the client for the judge call. Restore afterwards
        # even on exception so the rest of the workflow stays on the
        # configured model.
        original_model = getattr(self.gemini, "model_name", None)
        try:
            if hasattr(self.gemini, "model_name"):
                self.gemini.model_name = judge_model
                # Some backends cache the langchain client per model — invalidate.
                if hasattr(self.gemini, "_initialize"):
                    try:
                        self.gemini._initialize()
                    except Exception:
                        pass

            result = await self.gemini.generate_with_usage(
                prompt=judge_prompt,
                system_prompt="You are an impartial judge selecting the best of several candidate answers.",
            )
            self._record_usage_and_step(judge_prompt, result, round_number=99)

            # Parse {"selected_round": int} out of the response.
            import json
            import re
            text = result.get("response", "")
            m = re.search(r"\{[\s\S]*?\}", text)
            if not m:
                return None
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
            sel = obj.get("selected_round")
            if not isinstance(sel, int) or sel < 1 or sel > len(rounds):
                return None
            return {
                "selected_round": sel,
                "reason": obj.get("reason", ""),
                "total_tokens": result.get("total_tokens", 0),
                "cost_usd": result.get("cost_usd", 0.0),
            }
        except Exception as e:
            self.logger.warning(f"Judge pass failed ({e}); falling back to last round")
            return None
        finally:
            if original_model is not None and hasattr(self.gemini, "model_name"):
                self.gemini.model_name = original_model
                if hasattr(self.gemini, "_initialize"):
                    try:
                        self.gemini._initialize()
                    except Exception:
                        pass

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
