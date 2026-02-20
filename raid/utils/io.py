import json
import os
from typing import Any


def ensure_dir(path: str) -> None:
    # Create the directory if it does not exist.
    os.makedirs(path, exist_ok=True)


def read_json(path: str) -> Any:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def write_json(path: str, data: Any) -> None:
    ensure_dir(os.path.dirname(path) or '.')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)


def read_text(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def write_text(path: str, text: str) -> None:
    ensure_dir(os.path.dirname(path) or '.')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
