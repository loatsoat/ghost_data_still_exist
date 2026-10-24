"""
Data Loader - Loads all CSV input files from the dataset directory.
"""

import csv
import os
from pathlib import Path


class DataLoader:
    def __init__(self, dataset_dir):
        self.dataset_dir = Path(dataset_dir)

    def _read_csv(self, filename):
        """Read a CSV file and return list of dicts."""
        filepath = self.dataset_dir / filename
        if not filepath.exists():
            return []
        with open(filepath, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return list(reader)

    def load_deletion_requests(self):
        return self._read_csv('deletion_requests.csv')

    def load_sample_requests(self):
        return self._read_csv('sample_deletion_requests.csv')

    def load_sample_output(self):
        return self._read_csv('sample_output.csv')

    def load_user_identities(self):
        return self._read_csv('user_identities.csv')

    def load_user_audit_log(self):
        return self._read_csv('user_audit_log.csv')

    def load_system_activity(self):
        return self._read_csv('system_activity.csv')

    def load_deletion_rules(self):
        return self._read_csv('deletion_rules.csv')

    def load_evidence_manifest(self):
        return self._read_csv('evidence_files.csv')
