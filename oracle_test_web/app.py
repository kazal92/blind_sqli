from flask import Flask, request, render_template, jsonify
import oracledb

app = Flask(__name__)

# 오라클 데이터베이스 연결 정보
dsn = "192.168.219.100/XE"  # 회사

# oracledb로 연결
connection = oracledb.connect(user="C##kazal92", password="1234", dsn=dsn)

@app.route('/', methods=['GET', 'POST'])
def login():
    # 요청 방식에 따라 source만 결정
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
            with connection.cursor() as cursor:
                cursor.execute(query)
                result = cursor.fetchone()
                message = "Login successful!" if result else "Invalid credentials!"
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
