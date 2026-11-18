"""DB2 SQL Injection 실습 전용 서버. SQL 문자열 조합은 실습을 위해 유지한다."""

import os

from flask import Flask, g, jsonify, render_template, request


def create_app(driver=None):
    app = Flask(__name__)

    def connection():
        if "db2" not in g:
            db_driver = driver
            if db_driver is None:
                import ibm_db

                db_driver = ibm_db
            required = ["DB2_DATABASE", "DB2_USER", "DB2_PASSWORD"]
            if any(not os.environ.get(key) for key in required):
                raise RuntimeError("DB2 환경변수가 필요합니다.")
            conn_string = (
                f"DATABASE={os.environ['DB2_DATABASE']};"
                f"HOSTNAME={os.environ.get('DB2_HOST', '127.0.0.1')};"
                f"PORT={os.environ.get('DB2_PORT', '50000')};PROTOCOL=TCPIP;"
                f"UID={os.environ['DB2_USER']};PWD={os.environ['DB2_PASSWORD']};"
            )
            g.db_driver = db_driver
            g.db2 = db_driver.connect(conn_string, "", "")
        return g.db_driver, g.db2

    @app.teardown_appcontext
    def close_connection(error):
        conn = g.pop("db2", None)
        db_driver = g.pop("db_driver", None)
        if conn is not None:
            db_driver.close(conn)

    def login(username, password):
        db_driver, conn = connection()
        # 실습의 취약 지점. 일반 서비스의 로그인 코드로 사용하지 않는다.
        sql = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        statement = db_driver.prepare(conn, sql)
        try:
            db_driver.execute(statement)
            return bool(db_driver.fetch_assoc(statement))
        finally:
            db_driver.free_stmt(statement)

    @app.route("/db2", methods=["GET", "POST"])
    def db2_login():
        data = request.form if request.method == "POST" else request.args
        username, password = data.get("username"), data.get("password")
        message = ""
        if username and password:
            try:
                success = login(username, password)
                message = (
                    "Login 성공!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! " if success else "Login 실패"
                )
            except Exception:
                return render_template("db2.html", message="DB2 연결 또는 쿼리 실행 실패"), 500
        return render_template("db2.html", message=message)

    @app.route("/api/db2", methods=["POST"])
    def db2_api_login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not all(
            isinstance(data.get(key), str) and data[key] for key in ["username", "password"]
        ):
            return jsonify(status=400, message="username과 password 문자열이 필요합니다."), 400
        try:
            success = login(data["username"], data["password"])
        except Exception:
            return jsonify(status=500, message="DB2 연결 또는 쿼리 실행 실패"), 500
        # 기존 실습 응답 계약: 로그인 실패도 HTTP 200, 결과는 JSON status에 표시.
        if success:
            return jsonify(status=200, message="Login successful! " + "!" * 40)
        return jsonify(status=401, message="Invalid credentials!")

    @app.route("/api/ping-db2")
    def ping_db2():
        try:
            db_driver, conn = connection()
            statement = db_driver.exec_immediate(conn, "SELECT 1 FROM sysibm.sysdummy1")
            db_driver.free_stmt(statement)
            return jsonify(status="success", message="DB2 연결 성공!")
        except Exception:
            return jsonify(status="fail", message="DB2 연결 실패"), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("LAB_HOST", "127.0.0.1"),
        port=int(os.environ.get("LAB_PORT", "5001")),
        debug=False,
    )
