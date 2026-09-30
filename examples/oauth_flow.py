#!/usr/bin/env python3
"""Compatibility entry point for the hardened OAuth helper."""

import runpy
from pathlib import Path

runpy.run_path(str(Path(__file__).resolve().parents[1] / "oauth_flow.py"), run_name="__main__")
