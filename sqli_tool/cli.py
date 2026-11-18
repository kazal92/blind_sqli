"""명령행 입력과 네트워크 실행 전 검증."""

import argparse
import math
import sys


class KoreanParser(argparse.ArgumentParser):
    def format_help(self):
        return super().format_help().replace("usage:", "사용법:")

    def format_usage(self):
        return super().format_usage().replace("usage:", "사용법:")

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"입력 오류: {message}\n")


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("1 이상의 정수를 입력하세요.")
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("0보다 큰 유한한 숫자를 입력하세요.")
    return number


def names(value):
    result = [part.strip().strip("'\"") for part in value.split(",")]
    if not all(result) or len(result) != len(set(result)):
        raise argparse.ArgumentTypeError("쉼표로 구분한 중복 없는 이름을 입력하세요.")
    return result


def get_arguments(argv=None):
    parser = KoreanParser(description="Blind SQL Injection 실습 도구", add_help=False)
    parser._optionals.title = "옵션"
    parser.add_argument("-h", "--help", action="help", help="도움말을 표시하고 종료")
    parser.add_argument(
        "-r", "--request-file", required=True, help="HTTP 요청 파일 (UTF-8)"
    )
    parser.add_argument(
        "-s",
        dest="schema",
        type=str.lower,
        choices=["http", "https"],
        default="https",
        help="통신 프로토콜 (기본: https)",
    )
    parser.add_argument("-p", dest="parameter", required=True, help="대상 파라미터")
    parser.add_argument(
        "--location",
        choices=["auto", "query", "form", "json", "xml"],
        default="auto",
        help="대상 위치. JSON은 -p에 /login/password 같은 JSON Pointer 사용 가능",
    )
    parser.add_argument(
        "-d",
        dest="result_db",
        default="result.db",
        help="결과 SQLite 파일 (기본: result.db)",
    )
    parser.add_argument(
        "-D", dest="select_db", help="DB 이름; Oracle·DB2는 스키마/소유자"
    )
    parser.add_argument(
        "-T", dest="select_table", type=names, help="테이블 이름; 쉼표로 여러 개 지정"
    )
    parser.add_argument(
        "-C", dest="select_column", type=names, help="덤프할 컬럼 이름; 쉼표로 구분"
    )
    parser.add_argument(
        "--dbms",
        required=True,
        type=str.lower,
        choices=["mysql", "oracle", "db2", "mssql", "postgresql"],
        help="DBMS 종류",
    )
    parser.add_argument(
        "--db-schema", help="MSSQL·PostgreSQL 스키마 (기본: dbo·public)"
    )
    parser.add_argument("--proxy", help="프록시 URL 또는 host:port")
    parser.add_argument(
        "--timeout", type=positive_float, default=30, help="요청 제한 시간(초)"
    )
    parser.add_argument(
        "--max-len",
        type=positive_int,
        default=256,
        help="문자열 길이 상한 (초과하면 중단)",
    )
    parser.add_argument(
        "--max-rows", type=positive_int, default=1000, help="행 수 상한 (초과하면 중단)"
    )
    parser.add_argument("--string", help="참 응답 본문에 있는 문자열 (대소문자 구분)")
    parser.add_argument(
        "--not-string", help="거짓 응답 본문에 있는 문자열 (대소문자 구분)"
    )
    parser.add_argument(
        "--insecure", action="store_true", help="실습 환경의 HTTPS 인증서 검증 생략"
    )
    parser.add_argument(
        "--order-by", type=names, help="덤프 정렬용 고유 컬럼; 복합키는 쉼표로 구분"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    for flag, description in [
        ("basic", "기본 정보"),
        ("dbs", "DB/소유자 목록"),
        ("tables", "테이블 목록"),
        ("columns", "컬럼 목록"),
        ("dump", "데이터 덤프 (모든 지원 DBMS)"),
    ]:
        mode.add_argument("--" + flag, action="store_true", help=description)
    args = parser.parse_args(argv)
    if args.string == "" or args.not_string == "":
        parser.error("판별 문자열은 빈 문자열일 수 없습니다.")
    args.mode = next(
        flag
        for flag in ["basic", "dbs", "tables", "columns", "dump"]
        if getattr(args, flag)
    )
    if args.mode in ("tables", "columns", "dump") and not args.select_db:
        parser.error("이 작업에는 -D가 필요합니다.")
    if args.mode in ("columns", "dump") and not args.select_table:
        parser.error("이 작업에는 -T가 필요합니다.")
    if args.dump:
        if len(args.select_table) != 1 or not args.select_column or not args.order_by:
            parser.error(
                "--dump에는 테이블 하나, -C, 고유 키를 지정한 --order-by가 필요합니다."
            )
    elif args.select_column or args.order_by:
        parser.error("-C와 --order-by는 --dump와 함께 사용하세요.")
    if args.db_schema and args.dbms not in ("mssql", "postgresql"):
        parser.error("--db-schema는 MSSQL·PostgreSQL에서 사용하세요.")
    if args.proxy and "://" not in args.proxy:
        args.proxy = "http://" + args.proxy
    return args
