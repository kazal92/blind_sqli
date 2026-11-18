import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

from sqli_tool.cli import get_arguments
from sqli_tool.dbms import Dialect, Query, identifier, literal
from sqli_tool.engine import ExecutionError, Injector, bounded_integer
from sqli_tool.http import HTTPClient, RequestError, parse_request
from sqli_tool.main import main
from sqli_tool.storage import ResultStore

BASE = ["-r", "request.http", "-p", "password", "--dbms", "db2"]
RAW = "GET /db2?username=a%2Bb&password=x%27+AND+1%3D2+--+&empty=&tag=a&tag=b HTTP/1.1\r\nHost:127.0.0.1:5001\r\nCookie: test=example\r\n\r\n"


class CLITests(unittest.TestCase):
    def test_old_flags_and_quoted_name_lists(self):
        args = get_arguments(BASE + ["--columns", "-D", "TEST", "-T", "'USERS', 'ORDERS'"])
        self.assertEqual(args.select_table, ["USERS", "ORDERS"])

    def test_reject_invalid_combinations_before_execution(self):
        variants = [
            [],
            ["--tables"],
            ["--columns", "-D", "TEST"],
            ["--dump", "-D", "TEST", "-T", "USERS", "-C", "NAME"],
            ["--basic", "--tables"],
            ["--basic", "--timeout", "nan"],
            ["--basic", "--max-len", "0"],
            ["--basic", "-T", "A,A"],
        ]
        for extra in variants:
            with (
                self.subTest(extra=extra),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                get_arguments(BASE + extra)

    def test_dump_rejected_on_other_databases(self):
        for dbms in ["mysql", "oracle", "mssql", "postgresql"]:
            with (
                self.subTest(dbms=dbms),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                get_arguments(
                    [
                        "-r",
                        "r",
                        "-p",
                        "p",
                        "--dbms",
                        dbms,
                        "--dump",
                        "-D",
                        "D",
                        "-T",
                        "T",
                        "-C",
                        "C",
                        "--order-by",
                        "ID",
                    ]
                )

    def test_proxy_and_case_normalization(self):
        args = get_arguments(BASE + ["--basic", "--proxy", "127.0.0.1:8080", "-s", "HTTP"])
        self.assertEqual(args.proxy, "http://127.0.0.1:8080")
        self.assertEqual(args.schema, "http")


class RequestTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self):
        raw = 'POST / HTTP/1.1\nHost: localhost\nContent-Type: application/json\n\n{"password":"1=2", "password":"1=2"}'
        with self.assertRaises(RequestError):
            parse_request(raw, "http", "password")

    def test_malformed_url_returns_request_error(self):
        with self.assertRaises(RequestError):
            parse_request("GET //[ HTTP/1.1\nHost: localhost\n\n", "http", "password")

    def test_crlf_repeated_values_and_plus_round_trip(self):
        parsed = parse_request(RAW, "http", "password")
        self.assertEqual(parsed.condition, "x' AND 1=2 -- ")
        arguments = parsed.arguments("x' AND 1=1 -- ")
        prepared = requests.Request(parsed.method, parsed.url, **arguments).prepare()
        self.assertIn("username=a%2Bb", prepared.url)
        self.assertIn("tag=a&tag=b", prepared.url)
        self.assertIn("empty=", prepared.url)
        self.assertIn(
            "1%3D2",
            requests.Request(parsed.method, parsed.url, **parsed.arguments(parsed.condition))
            .prepare()
            .url,
        )
        self.assertEqual(parsed.headers["cookie"], "test=example")

    def test_json_charset_preserves_literal_plus_and_percent(self):
        raw = (
            "POST /api?token=x%2By HTTP/1.1\nHost: localhost\nContent-Type: Application/JSON; charset=utf-8\nContent-Length: 999\n\n"
            + json.dumps({"password": "x+%27 1=2", "other": {"keep": [1, 2]}})
        )
        parsed = parse_request(raw, "https", "password")
        args = parsed.arguments("1=1")
        self.assertEqual(parsed.condition, "x+%27 1=2")
        self.assertEqual(args["params"], [("token", "x+y")])
        self.assertEqual(args["json"]["other"], {"keep": [1, 2]})
        self.assertNotIn("content-length", args["headers"])
        args["json"]["other"]["keep"].append(3)
        self.assertEqual(parsed.body["other"]["keep"], [1, 2])

    def test_form_charset_and_query_are_preserved(self):
        raw = "POST /login?token=a HTTP/1.1\nHost: localhost\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\n\np=x+1%3D2&repeat=a&repeat=b"
        parsed = parse_request(raw, "http", "p")
        self.assertEqual(
            parsed.arguments("1=1")["data"], [("p", "1=1"), ("repeat", "a"), ("repeat", "b")]
        )
        self.assertEqual(parsed.query, [("token", "a")])

    def test_bad_input_is_rejected(self):
        requests_to_reject = [
            "",
            RAW.replace("Host:", "Invalid:"),
            RAW.replace("1%3D2", "1%3D1"),
            RAW.replace("&empty=", "&password=second&empty="),
            "POST / HTTP/1.1\nHost: localhost\nContent-Type: application/json\n\n[]",
            'POST / HTTP/1.1\nHost: localhost\nContent-Type: application/json\n\n{"password": 123}',
            "POST / HTTP/1.1\nHost: localhost\nContent-Type: text/plain\n\n1=2",
        ]
        for raw in requests_to_reject:
            with self.subTest(raw=raw), self.assertRaises(RequestError):
                parse_request(raw, "http", "password")

    def test_timeout_does_not_expose_url_or_turn_into_false(self):
        session = Mock()
        session.request.side_effect = requests.Timeout("secret-cookie-in-url")
        client = HTTPClient(parse_request(RAW, "http", "password"), session=session)
        with self.assertRaises(RequestError) as caught:
            client.size("1=2")
        self.assertNotIn("secret-cookie", str(caught.exception))

    def test_redirect_and_error_responses_stop_execution(self):
        for status in [302, 401, 403, 500]:
            session = Mock()
            session.request.return_value = SimpleNamespace(status_code=status, content=b"error")
            client = HTTPClient(parse_request(RAW, "http", "password"), session=session)
            with self.subTest(status=status), self.assertRaises(RequestError):
                client.size("1=2")

    def test_request_security_defaults(self):
        session = Mock()
        session.request.return_value = SimpleNamespace(status_code=200, content=b"ok")
        client = HTTPClient(parse_request(RAW, "http", "password"), session=session)
        self.assertEqual(client.size("1=2"), 2)
        self.assertTrue(session.request.call_args.kwargs["verify"])
        self.assertFalse(session.request.call_args.kwargs["allow_redirects"])
        client.close()
        session.close.assert_called_once()


class EngineTests(unittest.TestCase):
    def test_integer_boundaries_including_zero_and_exact_maximum(self):
        for limit in [1, 2, 20, 127, 1000]:
            for value in [0, 1, limit // 2, limit]:
                with self.subTest(limit=limit, value=value):
                    self.assertEqual(
                        bounded_integer(lambda middle, value=value: value > middle, limit), value
                    )
            with self.assertRaises(ExecutionError):
                bounded_integer(lambda middle, limit=limit: limit + 1 > middle, limit)

    def test_full_pipeline_with_sql_evaluation_and_sqlite_storage(self):
        """SQL을 실제 SQLite에서 평가하여 요청→판정→문자열→저장을 확인한다."""
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.create_function("ASCII", 1, lambda text: ord(text[0]) if text else 0)
        db.execute("CREATE TABLE sample (name TEXT)")
        db.executemany("INSERT INTO sample VALUES (?)", [("ALPHA",), ("BETA",)])

        class LabSession:
            def request(self, method, url, **kwargs):
                condition = dict(kwargs["params"])["password"]
                expression = condition.split(" AND ", 1)[1].rsplit(" -- ", 1)[0]
                truth = db.execute("SELECT (" + expression + ")").fetchone()[0]
                return SimpleNamespace(status_code=200, content=b"x" * (160 if truth else 100))

            def close(self):
                pass

        args = get_arguments(BASE + ["--dbs"])
        client = HTTPClient(parse_request(RAW, "http", "password"), session=LabSession())
        engine = Injector(args, client)
        query = Query(
            "dbs",
            "SELECT COUNT(*) FROM sample",
            lambda offset: f"SELECT name FROM sample ORDER BY name LIMIT 1 OFFSET {offset}",
        )
        engine.dialect.metadata = Mock(return_value=query)
        with contextlib.redirect_stdout(io.StringIO()):
            results = engine.execute()
        self.assertEqual(results, {"dbs": ["ALPHA", "BETA"]})
        store = ResultStore(":memory:")
        self.addCleanup(store.close)
        store.save(args, results)
        self.assertEqual(
            store.connection.execute("SELECT db_name FROM dbs_info ORDER BY db_name").fetchall(),
            [("ALPHA",), ("BETA",)],
        )
        self.assertEqual(
            json.loads(store.connection.execute("SELECT results_json FROM runs").fetchone()[0]),
            results,
        )

    def test_indistinguishable_baseline_stops_before_enumeration(self):
        client = Mock()
        client.request.condition = "1=2"
        client.size.return_value = 100
        with self.assertRaises(ExecutionError):
            Injector(get_arguments(BASE + ["--dbs"]), client).execute()


class DialectTests(unittest.TestCase):
    def test_all_dbms_have_metadata_and_basic_queries(self):
        for name in ["mysql", "oracle", "db2", "mssql", "postgresql"]:
            dialect = Dialect(name)
            for mode in ["dbs", "tables", "columns"]:
                query = dialect.metadata(mode, "lab's", "user's", "public")
                with self.subTest(dbms=name, mode=mode):
                    self.assertTrue(query.count.startswith("SELECT COUNT(*)"))
                    self.assertNotEqual(query.item(0), query.item(1))
            self.assertTrue(dialect.basic())

    def test_catalog_names_are_escaped(self):
        self.assertEqual(literal("O'Reilly"), "'O''Reilly'")
        self.assertEqual(identifier("a]b", "mssql"), "[a]]b]")
        self.assertEqual(identifier('a"b', "db2"), '"a""b"')
        query = Dialect("mssql").metadata("columns", "lab]x", "a'b", "sales")
        self.assertIn("[lab]]x].sys.columns", query.item(0))
        self.assertIn("s.name='sales'", query.item(0))
        self.assertIn("t.name='a''b'", query.item(0))

    def test_postgresql_filters_database_and_schema(self):
        sql = Dialect("postgresql").metadata("tables", "lab", schema="sales").item(0)
        self.assertIn("table_catalog='lab'", sql)
        self.assertIn("table_schema='sales'", sql)

    def test_db2_dump_uses_explicit_order_and_quoted_identifiers(self):
        query = Dialect("db2").dump("LAB", "USERS", ["NAME"], "ID")[0]
        self.assertIn('ORDER BY "ID"', query.item(0))
        self.assertIn('"LAB"."USERS"', query.count)


class StorageTests(unittest.TestCase):
    def test_basic_and_dump_with_no_dynamic_tables(self):
        store = ResultStore(":memory:")
        self.addCleanup(store.close)
        store.save(get_arguments(BASE + ["--basic"]), {"Current-DB": "LAB"})
        self.assertEqual(
            store.connection.execute("SELECT * FROM basic_results").fetchall(),
            [("Current-DB", "LAB")],
        )
        args = get_arguments(
            BASE + ["--dump", "-D", "LAB", "-T", "USERS", "-C", "NAME", "--order-by", "ID"]
        )
        store.save(args, {"USERS": [{"NAME": "O'Reilly"}]})
        self.assertEqual(
            store.connection.execute("SELECT data FROM data_dump").fetchone()[0], "O'Reilly"
        )

    def test_existing_database_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.db"
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE keep_me (value TEXT)")
            conn.execute("INSERT INTO keep_me VALUES ('original')")
            conn.commit()
            conn.close()
            store = ResultStore(path)
            try:
                self.assertEqual(
                    store.connection.execute("SELECT * FROM keep_me").fetchall(), [("original",)]
                )
            finally:
                store.close()

    def test_save_rolls_back_run_when_legacy_insert_fails(self):
        store = ResultStore(":memory:")
        self.addCleanup(store.close)
        store.connection.execute("DROP TABLE dbs_info")
        with self.assertRaises(sqlite3.Error):
            store.save(get_arguments(BASE + ["--dbs"]), {"dbs": ["LAB"]})
        self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0], 0)


class MainTests(unittest.TestCase):
    def test_missing_file_reports_error_without_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.db"
            with contextlib.redirect_stderr(io.StringIO()):
                code = main(
                    [
                        "-r",
                        str(Path(directory) / "absent"),
                        "-p",
                        "p",
                        "--dbms",
                        "mysql",
                        "--basic",
                        "-d",
                        str(output),
                    ]
                )
            self.assertEqual(code, 1)
            self.assertFalse(output.exists())

    def test_failure_closes_client_and_store(self):
        with tempfile.TemporaryDirectory() as directory:
            request_file = Path(directory) / "request.http"
            request_file.write_text(RAW)
            with (
                patch("sqli_tool.main.ResultStore") as store,
                patch("sqli_tool.main.HTTPClient") as client,
                patch("sqli_tool.main.Injector") as engine,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                engine.return_value.execute.side_effect = ExecutionError("test failure")
                self.assertEqual(
                    main(["-r", str(request_file), "-p", "password", "--dbms", "db2", "--basic"]), 1
                )
                store.return_value.close.assert_called_once()
                client.return_value.close.assert_called_once()
                store.return_value.save.assert_not_called()


if __name__ == "__main__":
    unittest.main()
