"""CLI 구성 요소의 생성과 자원 정리."""

import json
import sqlite3
import sys
from pathlib import Path

from .cli import get_arguments
from .engine import ExecutionError, Injector
from .http import HTTPClient, RequestError, parse_request
from .storage import ResultStore


def main(argv=None):
    args = get_arguments(argv)
    client = None
    store = None
    try:
        raw = Path(args.request_file).read_text(encoding="utf-8-sig")
        request = parse_request(raw, args.schema, args.parameter)
        # 결과 파일을 열 수 없는 경우 네트워크 실행 전에 실패한다.
        store = ResultStore(args.result_db)
        client = HTTPClient(request, args.timeout, args.proxy, not args.insecure)
        results = Injector(args, client).execute()
        store.save(args, results)
        print(json.dumps(results, ensure_ascii=False, indent=2))
        print(f"결과 저장 완료: {args.result_db}")
        return 0
    except (OSError, UnicodeError, RequestError, ExecutionError, sqlite3.Error) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("사용자가 작업을 중단했습니다.", file=sys.stderr)
        return 130
    finally:
        if client is not None:
            client.close()
        if store is not None:
            store.close()
