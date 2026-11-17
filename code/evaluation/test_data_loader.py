"""A missing dataset must fail loudly, not load as empty."""

import pytest

from data_loader import DataLoader


def test_missing_dataset_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match="deletion_requests.csv not found"):
        DataLoader(tmp_path / "missing").load_deletion_requests()
