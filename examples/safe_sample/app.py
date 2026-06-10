"""Small safe-looking sample for RepoRisk validation.

The values here are placeholders for local testing and are not credentials.
"""

from __future__ import annotations

import hashlib
import os
import subprocess

import requests
import yaml
from yaml import SafeLoader


DEBUG = False
SERVICE_URL = "https://service.example.invalid"


def load_settings(config_text: str) -> dict[str, object]:
    parsed = yaml.load(config_text, Loader=SafeLoader)
    return parsed if isinstance(parsed, dict) else {}


def fetch_status() -> int:
    response = requests.get(SERVICE_URL, timeout=5, verify=True)
    return response.status_code


def run_local_echo(message: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["echo", message], check=False, capture_output=True, text=True, shell=False)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_local_placeholder() -> str:
    return os.environ.get("REPORISK_SAMPLE_PLACEHOLDER", "")
