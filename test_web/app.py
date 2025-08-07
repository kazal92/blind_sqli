from flask import Flask, request, render_template, jsonify
import oracledb
import ibm_db

app = Flask(__name__)

# Oracle 연결
def get_connection():
    dsn = "192.168.219.100/XE"
    return oracledb.connect(user="C##kazal92", password="1234", dsn=dsn)

# DB2 전역 커넥션
db2_conn = None

DB2_CONN_STR = (
    "DATABASE=testdb;"
    "HOSTNAME=127.0.0.1;"
    "PORT=50000;"
    "PROTOCOL=TCPIP;"
    "UID=db2inst1;"
    "PWD=wnsgh123@@;"
)

def get_db2_connection():
    global db2_conn
    try:
        if db2_conn is None or not ibm_db.active(db2_conn):
            db2_conn = ibm_db.connect(DB2_CONN_STR, "", "")
    except Exception as e:
        print(f"[DB2] 연결 실패: {e}")
        db2_conn = None
    return db2_conn

# 🔹 DB2 로그인 페이지
@app.route('/db2', methods=['GET', 'POST'])
def db2_login():
    if request.method == 'POST':
        data = request.form
    else:
        data = request.args

    username = data.get('username')
    password = data.get('password')
    message = ""

    if username and password:
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            conn = get_db2_connection()
            stmt = ibm_db.prepare(conn, query)
            ibm_db.execute(stmt)
            result = ibm_db.fetch_assoc(stmt)
            message = "Login 성공!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! " if result else "Login 실패"
        except Exception as e:
            message = f"DB2 error: {str(e)}"

    return render_template('db2.html', message=message)

# 🔹 DB2 JSON API 로그인
@app.route('/api/db2', methods=['POST'])
def db2_api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        conn = get_db2_connection()
        stmt = ibm_db.prepare(conn, query)
        ibm_db.execute(stmt)
        result = ibm_db.fetch_assoc(stmt)

        if result:
            return jsonify({"status": 200, "message": "Login successful!", "username": username})
        else:
            return jsonify({"status": 401, "message": "Invalid credentials!"})
    except Exception as e:
        return jsonify({"status": 500, "message": f"DB2 error: {str(e)}"})

# 🔹 DB2 연결 테스트
@app.route('/api/ping-db2')
def ping_db2():
    try:
        conn = get_db2_connection()
        ibm_db.exec_immediate(conn, "SELECT 1 FROM sysibm.sysdummy1")
        return jsonify({"status": "success", "message": "DB2 연결 성공!"})
    except Exception as e:
        return jsonify({"status": "fail", "message": f"DB2 연결 실패: {str(e)}"})

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001, debug=True)
