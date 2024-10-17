from flask import Flask, request, render_template
import cx_Oracle
cx_Oracle.init_oracle_client(lib_dir="/Users/jjun/Downloads/instantclient_19_8")

app = Flask(__name__)

# 오라클 데이터베이스 연결 정보
# dsn = cx_Oracle.makedsn("192.168.219.100", 1521, service_name="xe")  # 회사
dsn = cx_Oracle.makedsn("192.168.0.32", 1521, service_name="xe")  # 삐집
connection = cx_Oracle.connect(user="C##kazal92", password="1234", dsn=dsn)

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
    except cx_Oracle.DatabaseError as e:
        message = f"Database error: {str(e)}"

    return render_template('login.html', message=message)

if __name__ == "__main__":
    app.run('0.0.0.0',port=5001,debug=True)