from flask import Flask, request, render_template, jsonify
import oracledb

app = Flask(__name__)

# 오라클 데이터베이스 연결 정보
dsn = "192.168.219.100/XE"  # 회사

# oracledb로 연결
connection = oracledb.connect(user="C##kazal92", password="1234", dsn=dsn)

@app.route('/', methods=['GET', 'POST'])
def login():
    message = ""
    username = request.values.get('username')
    password = request.values.get('password')

    # SQL 인젝션이 가능한 쿼리
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchone()

            if result:
                message = "Login successful!"
            else:
                message = "Invalid credentials!"
    except oracledb.DatabaseError as e:
        message = f"Database error: {str(e)}"

    return render_template('login.html', message=message)


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        with connection.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchone()

            if result:
                return jsonify({
                    "status": 200,
                    "message": "Login successful!",
                    "username": username
                })
            else:
                return jsonify({
                    "status": 401,
                    "message": "Invalid credentials!"
                })
    except oracledb.DatabaseError as e:
        return jsonify({
            "status": 500,
            "message": f"Database error: {str(e)}"
        })

if __name__ == "__main__":
    app.run('0.0.0.0', port=5001, debug=True)
