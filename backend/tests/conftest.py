import os

import pytest

# Set before any app module is imported so no test can reach the real LLM API.
os.environ["LLM_MODE"] = "mock"

from scripts.gen.dataset import VARIANTS, Dataset, build_dataset

SEED = 42


@pytest.fixture(scope="session")
def datasets() -> dict[int, Dataset]:
    """All three variants of seed 42, built in memory once per test session."""
    return {variant: build_dataset(SEED, variant) for variant in VARIANTS}
