"""Offline regressions. Run: python -m unittest discover -s tests -v"""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqli_tool.cli import get_arguments
from sqli_tool.dbms import Dialect
from sqli_tool.engine import Injector, bounded_integer
from sqli_tool.http import HTTPClient, RequestError, parse_request
from sqli_tool.storage import ResultStore


def args(dbms='db2', mode='basic', extra=()):
    return get_arguments(['-r', 'unused.txt', '-p', 'password', '--dbms', dbms,
                          '--' + mode, *extra])


def post(body, content_type='application/json'):
    return ('POST /login?lang=ko HTTP/1.1\r\nHost:localhost\r\n'
            f'Content-Type: {content_type}\r\nContent-Length: 999\r\n\r\n{body}')


class RequestRegressions(unittest.TestCase):
    def test_crlf_and_lf_json_charset(self):
        for newline in ('\r\n', '\n'):
            for content_type in ('application/json', 'application/json; charset=utf-8'):
                with self.subTest(newline=newline, content_type=content_type):
                    raw = post('{"password":"a+b %27 1=1"}', content_type)
                    request = parse_request(raw.replace('\r\n', newline), 'http', 'password')
                    self.assertEqual(request.condition, 'a+b %27 1=1')
                    self.assertEqual(json.loads(request.arguments('1=2')['data'])['password'], '1=2')
                    self.assertNotIn('content-length', request.headers)
                    self.assertEqual(request.arguments('1=2')['params'], [('lang', 'ko')])

    def test_get_decodes_once_preserves_duplicates_and_empty(self):
        raw = ('GET /login?password=a%2Bb+c%2527+1=1&tag=a&tag=b&empty= HTTP/1.1\r\n'
               'Host:localhost\r\n\r\n')
        request = parse_request(raw, 'http', 'password')
        self.assertEqual(request.condition, 'a+b c%27 1=1')
        self.assertEqual(request.arguments('1=2')['params'],
                         [('password', '1=2'), ('tag', 'a'), ('tag', 'b'), ('empty', '')])

    def test_form_decodes_once_preserves_duplicates(self):
        request = parse_request(post('password=a%2Bb+1=1&tag=a&tag=b',
                                     'application/x-www-form-urlencoded'), 'http', 'password')
        self.assertEqual(request.condition, 'a+b 1=1')
        self.assertEqual(request.arguments('1=2')['data'],
                         [('password', '1=2'), ('tag', 'a'), ('tag', 'b')])

    def test_repeated_target_rejected(self):
        with self.assertRaises(RequestError):
            parse_request('GET /?password=1=1&password=other HTTP/1.1\nHost:localhost\n\n',
                          'http', 'password')

    def test_missing_and_nonstring_json_targets_rejected(self):
        for body in ('{}', '{"password":12}', '{"password":null}'):
            with self.subTest(body=body), self.assertRaises(RequestError):
                parse_request(post(body), 'http', 'password')

    def test_prepared_get_preserves_wire_values_and_request(self):
        request = parse_request('GET /?password=a%2Bb+1=1&tag=a&tag=b HTTP/1.1\nHost:localhost\n\n',
                                'http', 'password')
        session = requests.Session()
        self.addCleanup(session.close)
        before = list(request.query)
        prepared = session.prepare_request(requests.Request(
            request.method, request.url, **request.arguments(request.condition)))
        from urllib.parse import parse_qs, urlsplit
        self.assertEqual(parse_qs(urlsplit(prepared.url).query),
                         {'password': ['a+b 1=1'], 'tag': ['a', 'b']})
        self.assertEqual(request.query, before)

    def test_network_errors_abort(self):
        request = parse_request(post('{"password":"1=1"}'), 'http', 'password')
        for error in (requests.ConnectionError('offline'), requests.Timeout('timeout')):
            with self.subTest(error=type(error)):
                session = Mock()
                session.request.side_effect = error
                with self.assertRaises(RequestError):
                    HTTPClient(request, session=session).response('1=2')

    def test_http_errors_abort(self):
        request = parse_request(post('{"password":"1=1"}'), 'http', 'password')
        for status in (302, 401, 500):
            with self.subTest(status=status):
                session = Mock()
                session.request.return_value.status_code = status
                with self.assertRaises(RequestError):
                    HTTPClient(request, session=session).response('1=2')


class ExecutionRegressions(unittest.TestCase):
    def store(self):
        store = ResultStore(':memory:')
        self.addCleanup(store.close)
        return store

    def test_integer_boundaries_include_zero(self):
        for value in range(128):
            self.assertEqual(bounded_integer(lambda n: value > n, 127), value)

    def test_db2_basic_extracts_and_persists(self):
        options = args()
        engine = Injector(options, Mock())
        engine.text = Mock(return_value='TESTDB')
        results = engine.extract()
        self.assertEqual(results, {'Current-DB': 'TESTDB'})
        store = self.store()
        store.save(options, results)
        self.assertEqual(store.connection.execute('SELECT field,value FROM basic_results').fetchall(),
                         [('Current-DB', 'TESTDB')])
        self.assertEqual(json.loads(store.connection.execute('SELECT results_json FROM runs').fetchone()[0]),
                         results)

    def test_basic_version_and_user_storage(self):
        for dbms in ('mysql', 'oracle'):
            with self.subTest(dbms=dbms):
                engine = Injector(args(dbms), Mock())
                engine.text = Mock(side_effect=['version', 'user'])
                results = engine.extract()
                store = self.store()
                store.save(args(dbms), results)
                self.assertEqual(store.connection.execute('SELECT version,user FROM basic_info').fetchone(),
                                 ('version', 'user'))

    def test_empty_enumeration(self):
        for mode, extra in (('dbs', ()), ('tables', ('-D', 'TEST')),
                            ('columns', ('-D', 'TEST', '-T', 'USERS'))):
            with self.subTest(mode=mode):
                options = args(mode=mode, extra=extra)
                engine = Injector(options, Mock())
                engine.number = Mock(return_value=0)
                engine.text = Mock()
                results = engine.extract()
                self.assertEqual(results, {'USERS' if mode == 'columns' else mode: []})
                engine.text.assert_not_called()
                self.store().save(options, results)

    def test_mysql_first_row_offset_zero(self):
        engine = Injector(args('mysql', 'dbs'), Mock())
        engine.number = Mock(return_value=1)
        engine.text = Mock(return_value='TEST')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(engine.extract(), {'dbs': ['TEST']})
        query = engine.text.call_args.args[0]
        self.assertIn('LIMIT 0,1', query)

    def test_all_dbms_dump_cli_and_query_generation(self):
        for dbms in ('mysql', 'oracle', 'db2', 'mssql', 'postgresql'):
            with self.subTest(dbms=dbms):
                options = args(dbms, 'dump', ('-D', 'TEST', '-T', 'USERS', '-C', 'NAME', '--order-by', 'ID'))
                queries = Dialect(dbms).dump(options.select_db, options.select_table[0],
                                            options.select_column, options.order_by, options.db_schema)
                self.assertTrue(queries)
                self.assertEqual(queries[0].label, 'NAME')

    def test_invalid_cli_rejected_before_execution(self):
        for extra in ([], ['--basic', '--dump'], ['--tables'], ['--dump']):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    get_arguments(['-r', 'unused.txt', '-p', 'password', '--dbms', 'db2', *extra])
                self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
