"""Tests for core.workflow_schema — DSL v2 compiler."""

from __future__ import annotations

import pytest

from core.workflow_schema import (
    CompiledWorkflow,
    WorkflowCompileError,
    compile_workflow,
    evaluate_when,
    render_parameters,
)


class TestV1Migration:
    def test_v1_chains_sequential(self) -> None:
        doc = {
            "name": "legacy",
            "steps": [
                {"name": "discovery", "type": "tool", "tool": "httpx"},
                {"name": "vuln", "type": "tool", "tool": "nuclei"},
                {"name": "report", "type": "report"},
            ],
        }
        compiled = compile_workflow(doc)
        assert isinstance(compiled, CompiledWorkflow)
        # Sequential — each generation has exactly one step.
        assert compiled.levels == [["discovery"], ["vuln"], ["report"]]

    def test_v1_id_synthesis(self) -> None:
        doc = {"steps": [{"name": "weird name!", "type": "tool", "tool": "httpx"}]}
        compiled = compile_workflow(doc)
        # Sanitized: spaces and ! → underscore.
        assert "weird_name_" in compiled.steps


class TestV2Validation:
    def test_invalid_id_rejected(self) -> None:
        doc = {
            "version": 2,
            "steps": [{"id": "9bad", "tool": "httpx"}],
        }
        with pytest.raises(WorkflowCompileError):
            compile_workflow(doc)

    def test_unknown_dep_rejected(self) -> None:
        doc = {
            "version": 2,
            "steps": [
                {"id": "a", "tool": "httpx"},
                {"id": "b", "tool": "nuclei", "depends_on": ["nonexistent"]},
            ],
        }
        with pytest.raises(WorkflowCompileError):
            compile_workflow(doc)

    def test_self_dependency_rejected(self) -> None:
        doc = {
            "version": 2,
            "steps": [{"id": "a", "tool": "httpx", "depends_on": ["a"]}],
        }
        with pytest.raises(WorkflowCompileError):
            compile_workflow(doc)

    def test_cycle_rejected(self) -> None:
        doc = {
            "version": 2,
            "steps": [
                {"id": "a", "tool": "httpx", "depends_on": ["b"]},
                {"id": "b", "tool": "nuclei", "depends_on": ["a"]},
            ],
        }
        with pytest.raises(WorkflowCompileError):
            compile_workflow(doc)

    def test_duplicate_id_rejected(self) -> None:
        doc = {
            "version": 2,
            "steps": [
                {"id": "x", "tool": "httpx"},
                {"id": "x", "tool": "nuclei"},
            ],
        }
        with pytest.raises(WorkflowCompileError):
            compile_workflow(doc)


class TestParallelLevels:
    def test_independent_steps_parallel(self) -> None:
        doc = {
            "version": 2,
            "steps": [
                {"id": "discovery", "tool": "httpx"},
                {"id": "subs", "tool": "subfinder"},
                {"id": "vuln", "tool": "nuclei", "depends_on": ["discovery", "subs"]},
            ],
        }
        compiled = compile_workflow(doc)
        # Two roots in same generation, one dependent in next.
        assert compiled.levels == [["discovery", "subs"], ["vuln"]]

    def test_diamond_pattern(self) -> None:
        doc = {
            "version": 2,
            "steps": [
                {"id": "root", "tool": "httpx"},
                {"id": "left", "tool": "nuclei", "depends_on": ["root"]},
                {"id": "right", "tool": "subfinder", "depends_on": ["root"]},
                {
                    "id": "join",
                    "type": "report",
                    "depends_on": ["left", "right"],
                },
            ],
        }
        compiled = compile_workflow(doc)
        assert compiled.levels == [["root"], ["left", "right"], ["join"]]


class TestRenderParameters:
    def test_simple_substitution(self) -> None:
        out = render_parameters(
            {"target": "{{ discovery.parsed.host }}"},
            {"discovery": {"parsed": {"host": "example.com"}}},
        )
        assert out == {"target": "example.com"}

    def test_undefined_raises(self) -> None:
        with pytest.raises(WorkflowCompileError):
            render_parameters({"x": "{{ missing.field }}"}, {})

    def test_walks_nested_structures(self) -> None:
        out = render_parameters(
            {"args": ["{{ a }}", {"k": "{{ b }}"}]},
            {"a": "1", "b": "2"},
        )
        assert out == {"args": ["1", {"k": "2"}]}

    def test_passes_through_non_string(self) -> None:
        out = render_parameters({"n": 42, "b": True}, {})
        assert out == {"n": 42, "b": True}

    def test_no_template_no_render(self) -> None:
        # Strings without templates pass through unchanged (cheap path).
        out = render_parameters({"x": "literal value"}, {})
        assert out == {"x": "literal value"}


class TestSandboxIsolation:
    def test_no_filesystem_access(self) -> None:
        # SandboxedEnvironment forbids attribute-walk into builtins. Any open()
        # smuggling would have to go through globals, which the sandbox blocks.
        with pytest.raises(WorkflowCompileError):
            render_parameters(
                {"x": "{{ ''.__class__.__mro__[1].__subclasses__() }}"},
                {},
            )


class TestEvaluateWhen:
    def test_none_always_true(self) -> None:
        assert evaluate_when(None, {}) is True

    def test_truthy_passes(self) -> None:
        assert evaluate_when("hosts | length > 0", {"hosts": ["a", "b"]}) is True

    def test_falsy_blocks(self) -> None:
        assert evaluate_when("hosts | length > 0", {"hosts": []}) is False

    def test_undefined_raises(self) -> None:
        with pytest.raises(WorkflowCompileError):
            evaluate_when("missing > 0", {})
