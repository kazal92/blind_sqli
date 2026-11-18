#!/usr/bin/env python3
"""기존 python sqli.py 실행 방식을 유지하는 진입점."""

from sqli_tool.main import main

if __name__ == "__main__":
    raise SystemExit(main())
