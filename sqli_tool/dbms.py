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

    def string_literal(self, value):
        if self.name == "mysql":
            return (
                f"CONVERT(0x{value.encode('utf-8').hex()} USING utf8mb4)"
                if value
                else "''"
            )
        return literal(value)

    def as_text(self, expression):
        value = f"({expression})"
        return {
            "mysql": f"CAST({value} AS CHAR CHARACTER SET utf8mb4)",
            "postgresql": f"CAST({value} AS TEXT)",
            "mssql": f"CAST({value} AS nvarchar(max)) COLLATE Latin1_General_100_BIN2",
            "oracle": f"TO_NCHAR({value})",
            "db2": f"CAST({value} AS VARCHAR(32672))",
        }[self.name]

    def length(self, expression):
        value = f"({expression})"
        if self.name == "mssql":
            return f"LEN({value} + N'#') - 1"
        if self.name == "mysql":
            return f"CHAR_LENGTH({value})"
        if self.name == "oracle":
            return f"LENGTH4({value})"
        if self.name == "db2":
            return f"CHARACTER_LENGTH({value},CODEUNITS32)"
        return f"LENGTH({value})"

    def unit_hex(self, expression, position):
        value = f"({expression})"
        if self.name == "mssql":
            return (
                f"CONVERT(varchar(4),CONVERT(varbinary(2),"
                f"SUBSTRING({value},{position},1)),2)"
            )
        if self.name == "oracle":
            return f"RAWTOHEX(UTL_I18N.STRING_TO_RAW(SUBSTR4({value},{position},1),'AL32UTF8'))"
        if self.name == "db2":
            return f"HEX(VARCHAR(SUBSTRING({value},{position},1,CODEUNITS32),4))"
        if self.name == "postgresql":
            return (
                f"UPPER(ENCODE(CONVERT_TO(SUBSTR({value},{position},1),'UTF8'),'hex'))"
            )
        return f"HEX(SUBSTRING({value},{position},1))"

    def ascii_length(self, expression):
        # HEX 출력만 대상으로 하므로 바이트·문자·UTF-16 길이가 모두 같다.
        return (
            f"LEN(({expression}))"
            if self.name == "mssql"
            else f"LENGTH(({expression}))"
        )

    def ascii_character(self, expression, position):
        substring = "SUBSTRING" if self.name == "mssql" else "SUBSTR"
        return f"ASCII({substring}(({expression}),{position},1))"

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
            "postgresql": [
                ("Version", "SELECT version()"),
                ("User", "SELECT current_user"),
            ],
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
        db = self.string_literal(database or "")
        tab = self.string_literal(table or "")
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
                "dbs": (
                    "(SELECT DISTINCT owner FROM all_tables) owners",
                    "owner",
                    "owner",
                ),
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

    def column_type(self, database, table, column, schema=None):
        db, tab, col = map(self.string_literal, (database, table, column))
        if self.name in ("mysql", "postgresql"):
            scope = (
                f"table_schema={db}"
                if self.name == "mysql"
                else (
                    f"table_catalog={db} AND table_schema={literal(schema or 'public')}"
                )
            )
            field = "data_type" if self.name == "mysql" else "udt_name"
            source = (
                f"information_schema.columns WHERE {scope} "
                f"AND table_name={tab} AND column_name={col}"
            )
        elif self.name == "oracle":
            field = "data_type"
            source = f"all_tab_columns WHERE owner={db} AND table_name={tab} AND column_name={col}"
        elif self.name == "db2":
            field = "typename"
            source = f"syscat.columns WHERE tabschema={db} AND tabname={tab} AND colname={col}"
        else:
            prefix = identifier(database, self.name)
            field = "ty.name"
            source = (
                f"{prefix}.sys.columns c JOIN {prefix}.sys.tables t ON c.object_id=t.object_id "
                f"JOIN {prefix}.sys.schemas s ON t.schema_id=s.schema_id "
                f"JOIN {prefix}.sys.types ty ON c.user_type_id=ty.user_type_id "
                f"WHERE s.name={literal(schema or 'dbo')} AND t.name={tab} AND c.name={col}"
            )
        return self.rows("type", source, field, field)

    def supports_type(self, name):
        name = name.lower().strip()
        allowed = {
            "mysql": "char varchar tinytext text mediumtext longtext enum set tinyint smallint "
            "mediumint int integer bigint decimal numeric float double real date time "
            "datetime timestamp year json",
            "postgresql": "text varchar bpchar name int2 int4 int8 float4 float8 numeric money "
            "bool date time timetz timestamp timestamptz interval uuid json jsonb xml",
            "mssql": "char varchar nchar nvarchar text ntext tinyint smallint int bigint bit "
            "decimal numeric float real money smallmoney date time datetime datetime2 "
            "smalldatetime datetimeoffset uniqueidentifier xml",
            "oracle": "char nchar varchar2 nvarchar2 number float binary_float binary_double "
            "date rowid urowid",
            "db2": "char character varchar graphic vargraphic smallint integer bigint decimal "
            "decfloat real double date time timestamp boolean",
        }
        return name in allowed[self.name].split() or (
            self.name == "oracle" and name.startswith("timestamp")
        )

    def supports_order_type(self, name):
        excluded = {"postgresql": {"json", "xml"}, "mssql": {"text", "ntext", "xml"}}
        return name.lower().strip() not in excluded.get(self.name, set())

    def table_source(self, database, table, schema=None):
        parts = [database, table]
        if self.name == "mssql":
            parts = [database, schema or "dbo", table]
        elif self.name == "postgresql":
            parts = [schema or "public", table]
        return ".".join(identifier(part, self.name) for part in parts)

    def duplicate_order(self, database, table, order_by, schema=None):
        source = self.table_source(database, table, schema)
        order = ",".join(identifier(name, self.name) for name in order_by)
        return (
            f"SELECT COUNT(*) FROM (SELECT {order} FROM {source} "
            f"GROUP BY {order} HAVING COUNT(*)>1) duplicate_keys"
        )

    def dump(self, database, table, columns, order_by, schema=None):
        source = self.table_source(database, table, schema)
        order = ",".join(identifier(name, self.name) for name in order_by)
        return [
            self.rows(column, source, identifier(column, self.name), order)
            for column in columns
        ]
