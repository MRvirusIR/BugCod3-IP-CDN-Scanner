#!/usr/bin/env python3
"""Backwards-compatible entry point: ``python3 main.py [options]``."""

from bugcod3.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
