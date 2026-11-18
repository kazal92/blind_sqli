"""DBMS별 메타데이터 SQL. HTTP 처리와 결과 저장에는 의존하지 않는다."""

from collections.abc import Callable
from dataclasses import dataclass


def literal(value):
    return "'" + value.replace("'", "''") + "'"


def identifier(value, dbms):
    if dbms == "mssql":
        return "[" + value.replace("]", "]]") + "]"
    if dbms == "mysql":
        return "`" + value.replace("`", "``") + "`"
    return '"' + value.replace('"', '""') + '"'


@dataclass(frozen=True)
class Query:
    label: str
    count: str
    item: Callable[[int], str]  # 내부 인덱스는 모든 DBMS에서 0부터 시작한다.


class Dialect:
    def __init__(self, dbms):
        self.name = dbms

    def length(self, expression):
        if self.name == "mssql":
            # LEN은 후행 공백을 제외하므로 끝에 구분자를 붙인다.
            return f"LEN(CAST(({expression}) AS nvarchar(max)) + N'#') - 1"
        return f"LENGTH(({expression}))"

    def character(self, expression, position):
        if self.name == "mssql":
            return f"UNICODE(SUBSTRING(CAST(({expression}) AS nvarchar(max)),{position},1))"
        return f"ASCII(SUBSTR(({expression}),{position},1))"

    def rows(self, label, source, value, order):
        count = f"SELECT COUNT(*) FROM {source}"

        def item(offset):
            if self.name == "oracle":
                return (
                    f"SELECT value FROM (SELECT value, ROWNUM rn FROM "
                    f"(SELECT {value} AS value FROM {source} ORDER BY {order})) WHERE rn={offset + 1}"
                )
            if self.name == "db2":
                return (
                    f"SELECT value FROM (SELECT {value} AS value, "
                    f"ROW_NUMBER() OVER(ORDER BY {order}) AS rn FROM {source}) AS q WHERE rn={offset + 1}"
                )
            if self.name == "mssql":
                return f"SELECT {value} FROM {source} ORDER BY {order} OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
            if self.name == "postgresql":
                return f"SELECT {value} FROM {source} ORDER BY {order} LIMIT 1 OFFSET {offset}"
            return f"SELECT {value} FROM {source} ORDER BY {order} LIMIT {offset},1"

        return Query(label, count, item)

    def basic(self):
        values = {
            "mysql": [("Version", "SELECT @@version"), ("User", "SELECT user()")],
            "oracle": [
                (
                    "Version",
                    "SELECT banner FROM V$VERSION WHERE banner LIKE 'Oracle%' AND ROWNUM=1",
                ),
                ("User", "SELECT USER FROM dual"),
            ],
            "db2": [("Current-DB", "SELECT CURRENT SERVER FROM SYSIBM.SYSDUMMY1")],
            "mssql": [("Version", "SELECT @@VERSION"), ("User", "SELECT SYSTEM_USER")],
            "postgresql": [("Version", "SELECT version()"), ("User", "SELECT current_user")],
        }
        single_row = {
            "oracle": "SELECT 1 FROM dual",
            "db2": "SELECT 1 FROM SYSIBM.SYSDUMMY1",
        }.get(self.name, "SELECT 1")
        return [
            Query(label, single_row, lambda offset, sql=sql: sql)
            for label, sql in values[self.name]
        ]

    def metadata(self, mode, database=None, table=None, schema=None):
        db = literal(database or "")
        tab = literal(table or "")
        if self.name == "mysql":
            sources = {
                "dbs": ("information_schema.schemata", "schema_name", "schema_name"),
                "tables": (
                    f"information_schema.tables WHERE table_schema={db}",
                    "table_name",
                    "table_name",
                ),
                "columns": (
                    f"information_schema.columns WHERE table_schema={db} AND table_name={tab}",
                    "column_name",
                    "ordinal_position",
                ),
            }
        elif self.name == "oracle":
            sources = {
                "dbs": ("(SELECT DISTINCT owner FROM all_tables) owners", "owner", "owner"),
                "tables": (f"all_tables WHERE owner={db}", "table_name", "table_name"),
                "columns": (
                    f"all_tab_columns WHERE owner={db} AND table_name={tab}",
                    "column_name",
                    "column_id",
                ),
            }
        elif self.name == "db2":
            sources = {
                "dbs": ("syscat.schemata", "schemaname", "schemaname"),
                "tables": (f"syscat.tables WHERE tabschema={db}", "tabname", "tabname"),
                "columns": (
                    f"syscat.columns WHERE tabschema={db} AND tabname={tab}",
                    "colname",
                    "colno",
                ),
            }
        elif self.name == "mssql":
            prefix = identifier(database or "", self.name)
            scope = literal(schema or "dbo")
            sources = {
                "dbs": ("sys.databases", "name", "name"),
                "tables": (
                    f"{prefix}.sys.tables t JOIN {prefix}.sys.schemas s ON t.schema_id=s.schema_id WHERE s.name={scope}",
                    "t.name",
                    "t.name",
                ),
                "columns": (
                    f"{prefix}.sys.columns c JOIN {prefix}.sys.tables t ON c.object_id=t.object_id JOIN {prefix}.sys.schemas s ON t.schema_id=s.schema_id WHERE s.name={scope} AND t.name={tab}",
                    "c.name",
                    "c.column_id",
                ),
            }
        elif self.name == "postgresql":
            scope = literal(schema or "public")
            # information_schema는 현재 연결된 데이터베이스만 조회한다.
            sources = {
                "dbs": ("pg_catalog.pg_database", "datname", "datname"),
                "tables": (
                    f"information_schema.tables WHERE table_catalog={db} AND table_schema={scope}",
                    "table_name",
                    "table_name",
                ),
                "columns": (
                    f"information_schema.columns WHERE table_catalog={db} AND table_schema={scope} AND table_name={tab}",
                    "column_name",
                    "ordinal_position",
                ),
            }
        else:
            raise ValueError("지원하지 않는 DBMS입니다.")
        return self.rows(mode, *sources[mode])

    def dump(self, database, table, columns, order_by):
        if self.name != "db2":
            raise ValueError("덤프는 DB2만 지원합니다.")
        source = ".".join(identifier(part, self.name) for part in [database, table])
        order = identifier(order_by, self.name)
        return [
            self.rows(
                column,
                source,
                f"COALESCE(CAST({identifier(column, self.name)} AS VARCHAR(32672)),'')",
                order,
            )
            for column in columns
        ]
