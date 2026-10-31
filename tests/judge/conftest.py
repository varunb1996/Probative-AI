import pytest
from judge_support import golden_bundle


@pytest.fixture
def bundle():
    return golden_bundle("32a60c4fa80ff99c")
