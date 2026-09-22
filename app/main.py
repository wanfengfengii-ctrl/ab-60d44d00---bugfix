"""Uvicorn entrypoint: ``python -m app.main``."""
from __future__ import annotations

import os

import uvicorn

from .api import create_app
from .storage import Store


def main():
    data_dir = os.environ.get("DATA_DIR", "/data")
    port = int(os.environ.get("API_PORT", "8080"))
    host = os.environ.get("API_HOST", "0.0.0.0")
    store = Store(data_dir)
    app = create_app(store)
    uvicorn.run(app, host=host, port=port, log_level=os.environ.get("LOG_LEVEL", "info"))


if __name__ == "__main__":
    main()
