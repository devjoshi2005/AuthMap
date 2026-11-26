import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Supported production models for manual user selection
CURATED_PRODUCTION_MODELS = {
    "balanced": "openai/gpt-oss-120b",
    "complex": "openai/gpt-oss-120b",
    "openai/gpt-oss-120b": "openai/gpt-oss-120b",
    "openai/gpt-oss-120b": "openai/gpt-oss-120b",
}

DEFAULT_PRODUCTION_MODEL = "openai/gpt-oss-120b"

MODEL_MIGRATION_MAP = {
    "llama-3.1-70b-versatile": "openai/gpt-oss-120b",
    "llama-3.1-70b": "openai/gpt-oss-120b",
    "llama3-70b": "openai/gpt-oss-120b",
    "llama-70b": "openai/gpt-oss-120b",
    "llama-3.3-70b-versatile": "openai/gpt-oss-120b",
    "fast": "openai/gpt-oss-120b",
    "llama-3-8b": "openai/gpt-oss-120b",
    "llama3-8b": "openai/gpt-oss-120b",
    "llama-8b": "openai/gpt-oss-120b",
}

def normalize_model_name(model_name: Optional[str], default_model: str = DEFAULT_PRODUCTION_MODEL) -> str:
    """Resolves model from user's manual selection across curated tiers:
    - Balanced (Default): openai/gpt-oss-120b
    - Complex: openai/gpt-oss-120b
    
    No automated prompt complexity keyword switching or vector overrides.
    """
    if not model_name or model_name.lower() in ["auto", "", "default", "none"]:
        return default_model

    clean = model_name.strip().lower()
    if clean in CURATED_PRODUCTION_MODELS:
        return CURATED_PRODUCTION_MODELS[clean]
    if clean in MODEL_MIGRATION_MAP:
        return MODEL_MIGRATION_MAP[clean]
    if "120b" in clean or "complex" in clean or "deep" in clean or "slow" in clean:
        return "openai/gpt-oss-120b"
    return default_model


class PromptComplexityRouter:
    """Manual Model Routing Handler.
    Respects user's manual model choice with zero keyword or semantic difficulty overrides.
    """

    def __init__(self):
        pass

    def classify(self, query: str, requested_model: Optional[str] = None) -> Dict[str, Any]:
        """Returns normalized execution settings strictly honoring user manual model choice."""
        effective_model = normalize_model_name(requested_model, default_model=DEFAULT_PRODUCTION_MODEL)
        
        return {
            "difficulty": "MANUAL_USER_SELECTION",
            "category": "USER_CONTROLLED",
            "allocated_model": effective_model,
            "chosen_model": effective_model,
            "reasoning": f"Manual model preference applied: {effective_model}",
            "is_overview": False,
            "needs_graph": True,
            "needs_rag": True,
            "needs_web": False,
            "confidence": 1.0
        }


# Global Singleton Instance
_router_instance: Optional[PromptComplexityRouter] = None

def get_prompt_router() -> PromptComplexityRouter:
    global _router_instance
    if _router_instance is None:
        _router_instance = PromptComplexityRouter()
    return _router_instance
