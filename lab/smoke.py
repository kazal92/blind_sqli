"""실제 MySQL 웹 서버를 통한 CLI 검사. 모두 성공해야 배포를 진행한다."""
import json
import sqlite3
import tempfile
from pathlib import Path

from sqli_tool.main import main


def run():
    cases = [
        (['--basic'], lambda result: result['Version'].startswith('8.4.') and result['User'].startswith('lab_user@')),
        (['--dbs'], lambda result: 'lab' in result['dbs']),
        (['--tables', '-D', 'lab'], lambda result: result == {'tables': ['users']}),
        (['--columns', '-D', 'lab', '-T', 'users'], lambda result: result == {'users': ['id', 'username', 'password']}),
    ]
    with tempfile.TemporaryDirectory() as directory:
        for index, (options, check) in enumerate(cases):
            output = Path(directory) / f'result-{index}.db'
            status = main(['-r', '/app/lab/request.http', '-s', 'http', '-p', 'password',
                           '--dbms', 'mysql', '-d', str(output), *options])
            if status != 0:
                raise SystemExit(f'실제 DB 검사 실패: {options}')
            with sqlite3.connect(output) as connection:
                result = json.loads(connection.execute('SELECT results_json FROM runs ORDER BY id DESC LIMIT 1').fetchone()[0])
            if not check(result):
                raise SystemExit(f'예상과 다른 결과: {options}: {result}')
            print(f'실제 DB 검사 통과: {options}', flush=True)
    print('MySQL 8.4 실제 DB 검사 4개 통과', flush=True)


if __name__ == '__main__':
    run()
