from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch

from lucebox_formal.repair import _esbmc_ai_model_class


class RepairDependencyTests(unittest.TestCase):
    def test_esbmc_ai_config_does_not_reparse_adapter_cli(self) -> None:
        calls: list[dict] = []

        class FakeConfig:
            def __init__(self, **kwargs) -> None:
                calls.append(kwargs)

        class FakeAIModel:
            pass

        package = types.ModuleType("esbmc_ai")
        package.__path__ = []
        config = types.ModuleType("esbmc_ai.config")
        config.Config = FakeConfig
        models = types.ModuleType("esbmc_ai.ai_models")
        models.AIModel = FakeAIModel

        with patch.dict(
            sys.modules,
            {
                "esbmc_ai": package,
                "esbmc_ai.config": config,
                "esbmc_ai.ai_models": models,
            },
        ):
            model_class = _esbmc_ai_model_class()

        self.assertIs(model_class, FakeAIModel)
        self.assertEqual(calls, [{"_cli_parse_args": False}])


if __name__ == "__main__":
    unittest.main()
