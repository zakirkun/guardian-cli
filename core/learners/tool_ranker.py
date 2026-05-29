"""
Tool ranker — A5 Phase 2.

Trains a small classifier on telemetry rows (``core/telemetry.py``) to
predict the best tool given (target_type, phase, prior_tool_count,
prior_findings_count). Used by ``ToolAgent`` as a fast pre-filter before
falling back to the LLM-based selector.

Design choices:
  * Pure-Python featuriser + a sklearn-or-logistic backend. ``scikit-
    learn`` is in the dev extras already; falling back to a hand-rolled
    softmax-over-counts keeps the path airgap-friendly.
  * ``predict(features) -> [(tool, score), ...]`` sorted descending. Caller
    decides whether to use top-1, weighted-sample, or fall back.
  * Confidence threshold: ``predict_with_fallback`` returns ``None`` if
    top score < ``min_confidence`` (default 0.7) — operator code calls the
    LLM-based selector in that case.

Storage: pickled to ``~/.guardian/ranker.pkl`` (or any path passed in).
``KnowledgeBase``-style — load lazily, never auto-update.

Acceptance: top-1 accuracy on a held-out split > LLM-baseline accuracy
on the same split. Eval harness (A6) provides the held-out splits.
"""

from __future__ import annotations

import json
import math
import pickle
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


_DEFAULT_MODEL_PATH = Path.home() / ".guardian" / "ranker.pkl"


@dataclass
class RankerFeatures:
    """Inputs used at predict time.

    Keep aligned with ``core.telemetry.TelemetryRow`` fields used as features.
    """

    target_type: str           # ip | domain | url | unknown
    phase: str                 # reconnaissance | scanning | analysis | reporting
    prior_tool_count: int = 0
    prior_findings_count: int = 0


@dataclass
class _CountTable:
    """Naive Bayes-ish backend: P(tool | features) ∝ count(tool, feat) /
    count(feat). Cheap, robust on small corpora, no scipy dep.

    More importantly — it works deterministically on N=20 examples, which
    is the realistic dataset size for a single operator's first month.
    sklearn would happily train but overfit.
    """

    # nested counters: feature_key -> tool -> count
    by_target: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    by_phase: Dict[str, Counter] = field(default_factory=lambda: defaultdict(Counter))
    by_phase_target: Dict[Tuple[str, str], Counter] = field(default_factory=lambda: defaultdict(Counter))
    tool_totals: Counter = field(default_factory=Counter)
    n: int = 0

    def fit(self, rows: Iterable[Dict[str, Any]]) -> None:
        for r in rows:
            tool = r.get("tool")
            if not tool:
                continue
            # Only consider rows where the tool actually produced findings.
            # Failed runs are negative signal we encode by NOT counting them.
            yielded = int(r.get("findings_yielded") or 0)
            if not r.get("success", False) and yielded == 0:
                continue
            tt = r.get("target_type", "unknown")
            ph = r.get("phase", "unknown")
            # Weight by yield: a tool that found 5 findings gets weight 5.
            w = max(yielded, 1)
            self.by_target[tt][tool] += w
            self.by_phase[ph][tool] += w
            self.by_phase_target[(ph, tt)][tool] += w
            self.tool_totals[tool] += w
            self.n += 1

    def score(self, features: RankerFeatures) -> Dict[str, float]:
        """Return raw scores per tool. Caller normalises."""
        if self.n == 0:
            return {}

        # Combine three feature views with hand-tuned weights. Phase+target
        # overlap is the strongest signal — both nail down the workflow
        # phase. Single-feature falls back when the joint cell is empty.
        joint = self.by_phase_target.get((features.phase, features.target_type), Counter())
        target = self.by_target.get(features.target_type, Counter())
        phase = self.by_phase.get(features.phase, Counter())

        scores: Dict[str, float] = {}
        for tool in self.tool_totals:
            s = (
                3.0 * joint.get(tool, 0)
                + 1.5 * target.get(tool, 0)
                + 1.5 * phase.get(tool, 0)
                + 0.1 * self.tool_totals.get(tool, 0)  # prior
            )
            scores[tool] = s
        return scores


def _softmax(scores: Dict[str, float]) -> Dict[str, float]:
    """Numerically stable softmax — peak normalised to 1 first."""
    if not scores:
        return {}
    m = max(scores.values())
    exps = {k: math.exp(v - m) for k, v in scores.items()}
    z = sum(exps.values()) or 1.0
    return {k: v / z for k, v in exps.items()}


class ToolRanker:
    """Public interface for trained tool selection.

    ``train(rows)`` accepts either telemetry JSONL records (dicts) or
    ``TelemetryRow`` instances. ``predict(features, k=3)`` returns top-k
    ``(tool, probability)`` tuples. ``predict_with_fallback`` collapses
    that into a single tool when confidence is high enough, ``None``
    otherwise — caller invokes LLM selection.
    """

    def __init__(self, min_confidence: float = 0.7) -> None:
        self.min_confidence = min_confidence
        self._table = _CountTable()
        self._fitted = False

    # ── training ─────────────────────────────────────────────────────────────

    def train(self, rows: Iterable[Any]) -> int:
        """Fit on telemetry rows. Returns number of rows actually used."""
        normalised: List[Dict[str, Any]] = []
        for row in rows:
            if hasattr(row, "__dict__"):
                normalised.append(dict(vars(row)))
            elif isinstance(row, dict):
                normalised.append(row)
            else:
                continue
        self._table.fit(normalised)
        self._fitted = self._table.n > 0
        return self._table.n

    def train_from_jsonl(self, path: Path) -> int:
        """Convenience — read a telemetry JSONL written by core/telemetry.py."""
        rows: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return self.train(rows)

    # ── prediction ───────────────────────────────────────────────────────────

    def predict(self, features: RankerFeatures, k: int = 3) -> List[Tuple[str, float]]:
        if not self._fitted:
            return []
        scores = _softmax(self._table.score(features))
        return sorted(scores.items(), key=lambda x: x[1], reverse=True)[:k]

    def predict_with_fallback(self, features: RankerFeatures) -> Optional[str]:
        """Single-tool answer or ``None`` if the model isn't confident."""
        ranked = self.predict(features, k=1)
        if not ranked:
            return None
        tool, prob = ranked[0]
        return tool if prob >= self.min_confidence else None

    # ── persistence ──────────────────────────────────────────────────────────

    def save(self, path: Optional[Path] = None) -> Path:
        path = Path(path or _DEFAULT_MODEL_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as fh:
            pickle.dump({"table": self._table, "min_confidence": self.min_confidence}, fh)
        return path

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "ToolRanker":
        path = Path(path or _DEFAULT_MODEL_PATH)
        with open(path, "rb") as fh:
            obj = pickle.load(fh)
        ranker = cls(min_confidence=float(obj.get("min_confidence", 0.7)))
        ranker._table = obj["table"]
        ranker._fitted = ranker._table.n > 0
        return ranker
