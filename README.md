# Blind SQL Injection CLI

원본 HTTP 요청 파일을 읽어 참·거짓 응답의 본문 크기로 조건을 판별하고, 조회 결과를 SQLite에 저장하는 Python 도구입니다. 직접 소유하거나 테스트 권한이 있는 환경에서 사용하세요.

## 설치

Python 3.10 이상이 필요합니다.

```sh
git clone https://github.com/kazal92/blind_sqli.git
cd blind_sqli
python -m venv .venv
```

Linux / macOS / WSL:

```sh
source .venv/bin/activate
python -m pip install -r requirements.txt
python sqli.py --help
```

Windows PowerShell에서는 활성화 없이 실행할 수 있습니다.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe sqli.py --help
```

이후 예제의 `python`을 `.\.venv\Scripts\python.exe`로 바꾸면 됩니다. 이 저장소에는 테스트 서버·DB·Docker 환경이 포함되어 있지 않습니다. 대상 웹 서버는 별도로 준비해야 합니다.

## 요청 파일 준비

Burp 등에서 저장한 원본 HTTP 요청을 UTF-8 파일로 준비합니다. `requests/` 폴더는 Git에서 제외됩니다. 헤더와 본문 사이의 빈 줄을 유지하세요.

```http
GET /login?username=example&password=example%27+AND+1%3D2+--+ HTTP/1.1
Host: 127.0.0.1:5080

```

위 요청은 형식 예시입니다. 경로·Host·로그인 값·SQL 문맥은 자신의 대상에 맞게 바꿔 `requests/target.http`에 저장하세요. 해당 서버가 저장소에 포함된 것은 아닙니다.

- `-p`로 지정한 값에 **거짓 조건 `1=2`가 정확히 한 번** 있어야 합니다. 이 부분만 조회 조건으로 교체합니다.
- GET은 쿼리, POST는 폼 또는 JSON 본문의 최상위 문자열 값을 대상으로 합니다.
- POST에서 쿼리 파라미터를 추출 대상으로 지정하는 기능은 없습니다.
- GET·폼의 URL 인코딩은 해석하지만 JSON 문자열의 `+`, `%`는 그대로 보존합니다.
- 요청 경로는 `/`로 시작해야 하며 `Host` 헤더가 필요합니다.
- 쿠키·인증 헤더는 필요한 경우 요청에 포함하고, 만료되면 갱신하세요.
- multipart, XML, 중첩 JSON 대상, GET 본문, 중복 HTTP 헤더·JSON 키는 지원하지 않습니다.

## 실행 순서

다음 명령은 MySQL을 사용하는 웹 서버에 맞는 요청 파일이 준비되어 있다고 가정합니다. 한 번에 실행 모드 하나를 지정합니다.

```sh
# 기본 정보: 버전·접속 사용자
python sqli.py -r requests/target.http -s http -p password --dbms mysql --basic

# 데이터베이스 목록
python sqli.py -r requests/target.http -s http -p password --dbms mysql --dbs

# 선택한 DB의 테이블
python sqli.py -r requests/target.http -s http -p password --dbms mysql --tables -D lab

# 선택한 테이블의 컬럼
python sqli.py -r requests/target.http -s http -p password --dbms mysql --columns -D lab -T users
```

**`-d`는 결과 파일, `-D`는 조회할 DB 또는 스키마입니다.** 기본 프로토콜은 HTTPS이므로 HTTP 서버에는 `-s http`를 지정하세요.

## 응답 크기 판별

실행을 시작하면 알려진 거짓(`1=2`)과 참(`1=1`) 요청을 번갈아 **각각 5번** 보냅니다. 측정한 범위와 판별 방향, 허용 범위를 화면에 출력합니다.

```text
거짓 응답: 1000~1008 bytes (5회 측정)
참 응답: 1150~1162 bytes (5회 측정)
판별 방향: 참 응답이 더 큼
거짓 허용 범위: 992~1016 bytes
참 허용 범위: 1138~1174 bytes
```

- 참 응답이 더 짧은 경우도 자동으로 처리합니다.
- 각 관측 범위 양쪽에 해당 범위의 변동 폭만큼 여유를 줍니다. 일정한 크기는 양쪽 1바이트 여유를 줍니다.
- 관측한 두 범위 사이 간격이 `--threshold`를 초과하고, 여유를 적용한 허용 범위도 서로 떨어져 있어야 실행합니다.
- 조회 응답이 참·거짓 어느 허용 범위에도 맞지 않으면 총 3회까지 요청합니다. 계속 불확실하면 중단합니다.
- 조회 판별 50회마다 다음 조회 전에 기준 요청을 다시 확인합니다. 저장 전에도 확인합니다.
- 기준 요청이 반대 범위에 들어오면 즉시 중단합니다. 범위 밖이면 최대 3회 확인하고 중단합니다. 기준을 자동으로 다시 학습하지 않습니다.

`--threshold` 기본값 20은 **초기 두 관측 범위의 최소 간격 조건**입니다. 예전의 `현재 크기 - 거짓 크기 > 20` 방식과 다릅니다. 헤더를 제외한 응답 본문 바이트 수를 사용합니다.

크기만으로 모든 오류를 구분할 수는 없습니다. 오류 페이지가 정상 응답과 같은 크기인 경우 등은 놓칠 수 있습니다. 자동 측정은 관측 표본을 기반으로 하며, 결과의 정확성을 보장하지 않습니다. 문자열·JSON·시간 기반 판별과 수동 기준 크기 지정은 현재 제공하지 않습니다.

## 옵션

| 옵션 | 용도 | 기본값 / 조건 |
|---|---|---|
| `-r`, `--request-file` | UTF-8 원본 요청 파일 | 필수 |
| `-p` | 조건식을 교체할 파라미터 | 필수 |
| `--dbms` | `mysql`, `oracle`, `db2`, `mssql`, `postgresql` | 필수, 자동 탐지 없음 |
| `-s` | `http` 또는 `https` | `https` |
| `-d` | 결과 SQLite 파일 | `result.db` |
| `--basic` | 기본 정보, DB2는 현재 DB | 실행 모드 |
| `--dbs` | DB·소유자·스키마 목록 | 실행 모드 |
| `--tables` | 테이블 목록 | `-D` 필수 |
| `--columns` | 컬럼 목록 | `-D`, `-T` 필수 |
| `--dump` | DB2 데이터 조회 | `-D`, 테이블 하나의 `-T`, `-C`, `--order-by` 필수 |
| `-D` | DB 이름, Oracle·DB2는 소유자·스키마 | 모드에 따라 필수 |
| `-T` | 테이블, 여러 개는 `"USERS,ORDERS"` | 컬럼 조회·덤프 |
| `-C` | 덤프 컬럼, 여러 개는 `"ID,NAME"` | 덤프 전용 |
| `--order-by` | DB2 덤프 정렬용 고유 컬럼 하나 | 덤프 전용, 고유성은 직접 확인 |
| `--db-schema` | MSSQL·PostgreSQL 스키마 | 각각 `dbo`, `public` |
| `--proxy` | 프록시 URL 또는 `host:port` | 지정하지 않음 |
| `--timeout` | 요청 한 건의 제한 시간(초) | `30` |
| `--threshold` | 초기 크기 범위 간 간격이 초과해야 할 값(바이트) | `20` |
| `--max-len` | 문자열 하나의 최대 길이 | `256` |
| `--max-rows` | 목록·덤프의 최대 행 수 | `1000` |
| `--insecure` | HTTPS 인증서 검증 생략 | 기본은 검증 |
| `-h`, `--help` | 전체 도움말 | 표시 후 종료 |

```sh
# Burp 프록시: Intercept를 끄거나 요청을 계속 전달해야 합니다.
python sqli.py -r requests/target.http -s http -p password --dbms mysql --basic --proxy 127.0.0.1:8080

# DB2 덤프: 실제 스키마·테이블·컬럼 이름을 지정하세요.
python sqli.py -r requests/db2.http -s http -p password --dbms db2 --dump -D LAB -T USERS -C "ID,NAME" --order-by ID -d db2-result.db

# SQL Server: DB와 스키마를 나누어 지정
python sqli.py -r requests/mssql.http -s http -p password --dbms mssql --tables -D lab --db-schema dbo

# PostgreSQL: 현재 연결된 DB 안에서 조회
python sqli.py -r requests/postgresql.http -s http -p password --dbms postgresql --columns -D lab --db-schema public -T users
```

## 지원 범위

| DBMS | 기본 정보 | DB 목록에 해당하는 범위 | 테이블·컬럼 | 덤프 |
|---|---|---|---|---|
| MySQL | 버전·사용자 | DB | 지원 | 미지원 |
| Oracle | 버전·사용자 | `all_tables`에 보이는 소유자 | 지원 | 미지원 |
| DB2 | 현재 DB | 스키마 | 지원 | 지원 |
| MSSQL | 버전·사용자 | DB | 지원, SQL Server 2012 이상 구문 | 미지원 |
| PostgreSQL | 버전·사용자 | DB | 현재 연결된 DB 내에서 지원 | 미지원 |

`--dbms`를 바꿔도 웹 서버의 DB 연결은 바뀌지 않습니다. Oracle·DB2의 `-D`는 실제 소유자·스키마 이름으로 지정합니다. PostgreSQL은 다른 DB로 연결을 전환하지 않습니다.

문자 추출은 **ASCII 0–127**만 지원합니다. 문자·길이·행 수의 상한을 넘으면 중단합니다. DB2 덤프의 NULL은 빈 문자열로 저장하며, 중복 정렬 값이나 조회 중 데이터 변경이 있으면 행별 일관성을 보장할 수 없습니다. DBMS별 지원은 구현 범위이며 모든 실제 서버·버전 검증을 의미하지 않습니다.

## 결과 확인과 오류 해결

성공하면 JSON과 `결과 저장 완료: ...`가 출력됩니다. 기본 파일은 현재 폴더의 `result.db`입니다. 저장 경로의 상위 폴더는 미리 만드세요. SQLite 도구에서 다음 SQL로 실행 기록을 확인할 수 있습니다.

```sql
SELECT id, created_at, dbms, mode, database_name, schema_name, results_json
FROM runs
ORDER BY id DESC;
```

실행 이력은 `runs`, 기본 정보는 `basic_results`·`basic_info`, 목록은 `dbs_info`·`table_info`·`column_info`, DB2 덤프는 `data_dump`에 저장합니다. DBMS·스키마별 결과 구분은 `runs`를 기준으로 하세요. 실패한 실행의 조회 결과는 저장하지 않지만 초기화 과정에서 빈 파일·테이블은 생성될 수 있습니다.

| 증상 | 확인할 내용 |
|---|---|
| 참·거짓 범위를 구분할 수 없음 | Repeater로 참·거짓 요청 비교. 동적 페이지·잘못된 SQL 문맥·DBMS 확인 |
| 응답 크기를 판별할 수 없음 / 기준 변경 | 세션 만료·오류 페이지·크기 변동 확인. 원인 확인 후 다시 실행 |
| HTTP 301·302 | 최종 URL의 요청을 저장. 리디렉션은 따라가지 않음 |
| HTTP 401·403 | 인증 정보·권한 확인 |
| HTTP 500 | 서버 로그·SQL 문맥·DBMS 확인 |
| 통신 실패 | Host·포트·프로토콜·인증서·프록시 확인 |
| 상한 초과 | 길이·행 수는 옵션 조정, 문자 코드 127 초과는 비ASCII 문자 가능성 |
| 빈 목록 | DB·스키마·테이블 이름과 조회 권한 확인 |
| 결과 파일 열기 실패 | 상위 폴더와 쓰기 권한 확인 |

## 파일 구성

```text
sqli.py                 CLI 진입점
sqli_tool/
  cli.py                옵션·입력 검증
  http.py               HTTP 요청 파싱·통신
  oracle.py             응답 크기 측정·판별·기준 확인
  dbms.py               DBMS별 SQL
  engine.py             이진 탐색·조회
  storage.py            SQLite 결과 저장
  main.py               실행·종료 처리
requirements.txt        실행 의존성
README.md               설치·사용법
.gitignore              요청·결과·캐시 제외
```
