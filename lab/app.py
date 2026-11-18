"""MySQL 실습 전용 로그인 서버. 취약 쿼리는 교육 목적으로 유지한다."""
import os

import pymysql
from flask import Flask, jsonify, render_template_string, request

PAGE = '''<!doctype html>
<html lang="ko"><meta charset="utf-8"><title>MySQL SQLi 실습</title>
<h1>MySQL 8.4 실습 로그인</h1>
<p>실습 계정: admin / lab-demo</p>
<form action="/login" method="get">
<label>아이디 <input name="username" value="admin"></label>
<label>비밀번호 <input name="password" value="lab-demo"></label>
<button>로그인</button></form><pre>{{ message }}</pre></html>'''
SUCCESS = 'LOGIN SUCCESS: ' + 'Authorized laboratory response. ' * 4
FAILURE = 'LOGIN FAILED'


def create_app(connect=None):
    app = Flask(__name__)

    def connection():
        factory = connect if connect is not None else pymysql.connect
        return factory(host=os.environ.get('MYSQL_HOST', 'db'),
                       user=os.environ.get('MYSQL_USER', 'lab_user'),
                       password=os.environ.get('MYSQL_PASSWORD', 'lab_only_password'),
                       database=os.environ.get('MYSQL_DATABASE', 'lab'),
                       connect_timeout=5, read_timeout=10, write_timeout=10,
                       autocommit=True, charset='utf8mb4')

    @app.get('/health')
    def health():
        try:
            with connection() as conn, conn.cursor() as cursor:
                cursor.execute('SELECT 1')
                cursor.fetchone()
            return jsonify(status='ok')
        except Exception:
            return jsonify(status='database unavailable'), 503

    @app.route('/', methods=['GET'])
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        data = request.form if request.method == 'POST' else request.args
        username, password = data.get('username'), data.get('password')
        message = ''
        if username is not None and password is not None:
            try:
                # 의도적인 실습 취약점. 일반 서비스 코드에 사용하지 않는다.
                query = f"SELECT id FROM users WHERE username='{username}' AND password='{password}'"
                with connection() as conn, conn.cursor() as cursor:
                    cursor.execute(query)
                    message = SUCCESS if cursor.fetchone() else FAILURE
            except Exception:
                return render_template_string(PAGE, message='실습 DB 연결 또는 SQL 실행 오류'), 500
        return render_template_string(PAGE, message=message)

    return app


if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=5080, debug=False)
