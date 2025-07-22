#!/bin/bash

rm -rf .venv
uv sync -p 3.12
uv run bootstrap.py
uv run server.py
