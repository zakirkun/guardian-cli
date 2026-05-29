"""
AI Providers Module
Provider factory and registry for different AI providers
"""

from typing import Dict, Any, Optional
from utils.logger import get_logger


# In-tree provider registry. Maps name → "module.path.ClassName".
# Third parties extend this WITHOUT editing the dict by declaring an
# entry-point in their own pyproject.toml:
#
#   [project.entry-points."guardian.providers"]
#   ollama = "guardian_ollama.provider:OllamaProvider"
#
# At factory time we merge entry-point registrations on top of this dict.
# In-tree wins on name collisions — protects core providers from being
# silently overridden by a typo'd plugin.
PROVIDERS: Dict[str, str] = {
    "gemini": "ai.providers.gemini_provider.GeminiProvider",
    "openai": "ai.providers.openai_provider.OpenAIProvider",
    "claude": "ai.providers.claude_provider.ClaudeProvider",
    "openrouter": "ai.providers.openrouter_provider.OpenRouterProvider",
    # New in v4: shipped in-tree but follow the plugin contract.
    "ollama": "ai.providers.ollama_provider.OllamaProvider",
    "openai_compatible": "ai.providers.openai_compatible_provider.OpenAICompatibleProvider",
}

_ENTRY_POINT_GROUP = "guardian.providers"
_discovered_cache: Optional[Dict[str, str]] = None


def _discover_plugin_providers() -> Dict[str, str]:
    """Merge entry-point-declared providers on top of the in-tree dict.

    Cached after the first call — entry points are static at process
    start. In-tree names always win; a plugin trying to overwrite a
    core provider is logged at WARNING and ignored.
    """
    global _discovered_cache
    if _discovered_cache is not None:
        return _discovered_cache

    merged = dict(PROVIDERS)
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover — Python <3.8 unsupported
        _discovered_cache = merged
        return merged

    try:
        eps = entry_points(group=_ENTRY_POINT_GROUP)
    except TypeError:
        # Pre-3.10 entry_points() takes no kwargs.
        eps = entry_points().get(_ENTRY_POINT_GROUP, [])  # type: ignore[union-attr]

    for ep in eps:
        if ep.name in PROVIDERS:
            # In-tree wins — log and skip.
            try:
                get_logger().warning(
                    f"Provider plugin '{ep.name}' (from {ep.value}) "
                    f"would override in-tree provider — ignored."
                )
            except Exception:
                pass
            continue
        merged[ep.name] = ep.value

    _discovered_cache = merged
    return merged


def get_provider(config: Dict[str, Any]):
    """
    Factory function to create appropriate AI provider

    Args:
        config: Configuration dictionary

    Returns:
        Initialized provider instance

    Raises:
        ValueError: If provider is unknown
        RuntimeError: If provider initialization fails
    """
    logger = get_logger(config)

    registry = _discover_plugin_providers()

    ai_config = config.get("ai", {})
    provider_name = ai_config.get("provider", "gemini").lower()

    if provider_name not in registry:
        available = ", ".join(sorted(registry.keys()))
        raise ValueError(
            f"Unknown provider: {provider_name}. "
            f"Available providers: {available}"
        )

    provider_path = registry[provider_name]
    module_path, class_name = provider_path.rsplit(".", 1)

    try:
        import importlib
        module = importlib.import_module(module_path)
        provider_class = getattr(module, class_name)
        provider = provider_class(config, logger)
        logger.info(f"Loaded provider: {provider_name}")
        return provider

    except ImportError as e:
        raise RuntimeError(
            f"Failed to import provider {provider_name}: {e}. "
            f"Make sure required dependencies are installed."
        )
    except Exception as e:
        raise RuntimeError(f"Failed to initialize provider {provider_name}: {e}")


def list_available_providers() -> list:
    """Get list of available provider names (in-tree + plugin-declared)."""
    return sorted(_discover_plugin_providers().keys())


__all__ = ["get_provider", "list_available_providers", "PROVIDERS"]
