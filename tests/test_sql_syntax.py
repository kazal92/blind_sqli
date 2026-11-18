"""실제 서버 실행을 대체하지 않는, 네 DBMS의 SQL 파서 검사."""

import unittest

import sqlglot

from sqli_tool.dbms import Dialect


class SQLSyntaxTests(unittest.TestCase):
    def test_queries_and_predicates_parse_in_each_supported_dialect(self):
        for dbms, parser in [
            ("mysql", "mysql"),
            ("oracle", "oracle"),
            ("mssql", "tsql"),
            ("postgresql", "postgres"),
        ]:
            dialect = Dialect(dbms)
            queries = dialect.basic() + [
                dialect.metadata(mode, "LAB", "USERS", "public")
                for mode in ["dbs", "tables", "columns"]
            ]
            for query in queries:
                for offset in [0, 1]:
                    expression = query.item(offset)
                    statements = [
                        expression,
                        f"SELECT 1 WHERE ({query.count})>0",
                        f"SELECT 1 WHERE ({dialect.length(expression)})>0",
                        f"SELECT 1 WHERE ({dialect.character(expression, 1)})>65",
                    ]
                    for statement in statements:
                        with self.subTest(
                            dbms=dbms, query=query.label, offset=offset, sql=statement
                        ):
                            sqlglot.parse_one(
                                statement, read=parser, error_level=sqlglot.ErrorLevel.RAISE
                            )
