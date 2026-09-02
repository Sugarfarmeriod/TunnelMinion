from pathlib import Path

import pytest
import scripts.run_real_model_evaluation as evaluation

from tunnelminion.model.configuration import FileModelConfigurationRepository
from tunnelminion.model.openai_compatible import OpenAICompatibleConfig


class FakeSecrets:
    def get(self, _name: str) -> str:
        return "test-key"

    def set(self, _name: str, _value: str) -> None:
        raise AssertionError("评估入口不得写入密钥")

    def delete(self, _name: str) -> None:
        raise AssertionError("评估入口不得删除密钥")


def test_configured_provider_reads_model_and_keyring_without_changing_them(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = FileModelConfigurationRepository(tmp_path / "model.json")
    repository.save(
        OpenAICompatibleConfig(endpoint="https://model.test/v1", model="deepseek-test")
    )
    monkeypatch.setattr(evaluation, "KeyringSecretStore", FakeSecrets)

    provider, model_name = evaluation._configured_provider(tmp_path)

    assert model_name == "deepseek-test"
    assert provider.capabilities.tool_calls is True


def test_estimated_cost_uses_separate_input_and_output_rates() -> None:
    assert evaluation._estimated_cost(1_000, 500, 0.22, 0.66) == pytest.approx(0.00055)
    assert evaluation._estimated_cost(1_000, 500, None, None) is None
