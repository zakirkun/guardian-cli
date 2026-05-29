"""Tests for the provider entry-point discovery + new local providers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestEntryPointDiscovery:
    def test_intree_providers_listed(self) -> None:
        from ai.providers import list_available_providers

        names = list_available_providers()
        for required in ("gemini", "openai", "claude", "openrouter", "ollama", "openai_compatible"):
            assert required in names, f"missing {required}"

    def test_unknown_provider_rejected(self) -> None:
        from ai.providers import get_provider

        with pytest.raises(ValueError):
            get_provider({"ai": {"provider": "totally_made_up"}})

    def test_plugin_does_not_override_intree(self, caplog) -> None:
        """If a plugin tries to overwrite an in-tree name, it must be ignored."""
        # Reset the module-level cache so our patched entry_points takes effect.
        import ai.providers as providers_mod
        providers_mod._discovered_cache = None

        fake_ep = MagicMock()
        fake_ep.name = "openai"  # collide with in-tree
        fake_ep.value = "evil_pkg.evil:EvilProvider"

        with patch("importlib.metadata.entry_points", return_value=[fake_ep]):
            registry = providers_mod._discover_plugin_providers()

        # In-tree value preserved.
        assert registry["openai"] == "ai.providers.openai_provider.OpenAIProvider"

        # Reset for other tests.
        providers_mod._discovered_cache = None

    def test_plugin_adds_new_name(self) -> None:
        import ai.providers as providers_mod
        providers_mod._discovered_cache = None

        fake_ep = MagicMock()
        fake_ep.name = "myplugin"
        fake_ep.value = "my_pkg.my_mod:MyProvider"

        with patch("importlib.metadata.entry_points", return_value=[fake_ep]):
            registry = providers_mod._discover_plugin_providers()

        assert registry["myplugin"] == "my_pkg.my_mod:MyProvider"
        providers_mod._discovered_cache = None


class TestOllamaProvider:
    def test_init_requires_aiohttp(self, base_config) -> None:
        cfg = dict(base_config)
        cfg["ai"] = {"provider": "ollama", "ollama": {"model": "llama3.1"}}
        # If aiohttp is installed (it should be in dev env), provider builds.
        # Otherwise it raises RuntimeError — both paths acceptable for this test.
        try:
            from ai.providers.ollama_provider import OllamaProvider
            import logging
            p = OllamaProvider(cfg, logging.getLogger("test"))
            assert p.get_model_name() == "llama3.1"
            assert p.base_url.startswith("http")
        except RuntimeError as e:
            assert "aiohttp" in str(e).lower()


class TestOpenAICompatible:
    def test_requires_base_url(self, base_config) -> None:
        cfg = dict(base_config)
        cfg["ai"] = {
            "provider": "openai_compatible",
            "openai_compatible": {"model": "test", "api_key": "any"},
        }
        # No base_url → must raise.
        try:
            from ai.providers.openai_compatible_provider import OpenAICompatibleProvider
            import logging
            with pytest.raises(RuntimeError, match="base_url"):
                OpenAICompatibleProvider(cfg, logging.getLogger("test"))
        except ImportError:
            pytest.skip("langchain-openai not installed")

    def test_initializes_with_base_url(self, base_config) -> None:
        cfg = dict(base_config)
        cfg["ai"] = {
            "provider": "openai_compatible",
            "openai_compatible": {
                "model": "local-model",
                "base_url": "http://vllm.local:8000/v1",
                "api_key": "any",
            },
        }
        try:
            from ai.providers.openai_compatible_provider import OpenAICompatibleProvider
            import logging
            p = OpenAICompatibleProvider(cfg, logging.getLogger("test"))
            assert p.get_model_name() == "local-model"
        except ImportError:
            pytest.skip("langchain-openai not installed")
