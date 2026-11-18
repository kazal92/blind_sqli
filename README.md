# Blind SQL Injection 실습 도구

HTTP 요청 파일을 읽어 응답 크기 차이로 조건을 판별하고, 메타데이터와 결과를 SQLite에 저장하는 Python CLI입니다. 소유하거나 테스트 권한이 있는 실습 환경에서 사용하세요.

## 설치

Python 3.10 이상을 사용합니다.

```sh
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python sqli.py --help
```

CLI에는 requests만 필요합니다. Flask·DB2 드라이버는 실습 서버를 실행할 때 별도로 설치합니다.

## 요청 파일

Burp 등에서 복사한 원본 HTTP 요청을 UTF-8 파일로 저장하고 `-r`로 지정합니다. 대상 파라미터에는 거짓 조건 `1=2`가 정확히 한 번 들어 있어야 합니다. GET 쿼리, POST 폼, POST JSON의 최상위 문자열 파라미터를 지원합니다.

- `examples/request.http`는 localhost용 가상 데이터 예시입니다.
- `Content-Type`의 charset, CRLF, 빈 파라미터, 대상 외 반복 파라미터를 처리합니다.
- JSON 문자열의 `+`와 `%`는 URL 디코딩하지 않습니다.
- 대상 파라미터 중복, 중첩 JSON 대상, multipart, XML, GraphQL, GET 본문은 지원하지 않습니다.
- 인증 쿠키가 있는 실제 요청 파일은 Git에 올리지 마세요. `requests/` 폴더는 기본적으로 Git에서 제외합니다.

## 지원 범위

| DBMS | 기본 정보 | DB/소유자 목록 | 테이블·컬럼 | 데이터 덤프 |
|---|---|---|---|---|
| MySQL | 구현 | 구현 | 구현 | 미지원 |
| Oracle | 구현 | 소유자 목록 | 구현 | 미지원 |
| DB2 | 현재 DB | 스키마 목록 | 구현 | 구현 |
| MSSQL (SQL Server 2012 이상) | 구현 | 구현 | 구현 | 미지원 |
| PostgreSQL | 구현 | 구현 | 현재 연결된 DB | 미지원 |

위 표는 구현 범위이며 실제 DB 서버별 동작 검증 완료를 뜻하지 않습니다. 로컬 자동 테스트는 모의 HTTP 응답과 SQLite SQL 평가를 사용합니다. SQL 구문 검사는 SQLGlot이 지원하는 MySQL·Oracle·T-SQL·PostgreSQL에 대해 수행하며 DB2의 실제 엔진 검증은 별도입니다.

MSSQL은 `-D`로 데이터베이스를, `--db-schema`로 스키마를 선택합니다(기본 `dbo`). PostgreSQL의 기본 스키마는 `public`이며, `-D`에는 현재 연결된 DB 이름을 지정해야 합니다. PostgreSQL은 이 도구로 다른 DB에 연결을 전환하지 않습니다. Oracle·DB2에서 `-D`는 소유자/스키마입니다.

현재 문자열 처리는 ASCII(0–127)를 대상으로 합니다. 한글 등 범위를 넘는 문자, 설정한 길이/행 수 상한 초과는 조용히 잘라내지 않고 오류로 중단합니다. SQL NULL은 메타데이터 추출에서 지원하지 않으며 DB2 덤프에서는 빈 문자열로 저장하므로 NULL과 빈 문자열은 구분되지 않습니다.

## 실행 예시

아래 요청 파일은 각 DBMS에 연결된 자신의 실습 서버에 맞게 준비해야 합니다.

```sh
# 기본 정보: 기존 실행 파일과 옵션 유지, -r 추가
python sqli.py -r examples/request.http -s http -p password --dbms db2 --basic -d result.db

# SQL Server: DB와 스키마를 구분
python sqli.py -r requests/mssql.http -s http -p password --dbms mssql --tables -D lab --db-schema dbo

# PostgreSQL: 현재 연결된 DB의 스키마 선택
python sqli.py -r requests/postgresql.http -s http -p password --dbms postgresql --columns -D lab --db-schema public -T users

# 여러 테이블의 컬럼 확인
python sqli.py -r requests/db2.http -s http -p password --dbms db2 --columns -D LAB -T "USERS,ORDERS"

# 기존 DB2 덤프: 정렬이 안정적인 고유 컬럼을 직접 지정
python sqli.py -r requests/db2.http -s http -p password --dbms db2 --dump -D LAB -T USERS -C "ID,NAME" --order-by ID
```

`--order-by`는 단일 고유 컬럼을 받습니다. 고유성은 도구가 검사하지 않으며, 동시 데이터 변경이나 중복 정렬 값이 있으면 행 간 일관성을 보장할 수 없습니다. 자동 PK 검색과 `ORDER BY 1` 대체 처리는 제거했습니다.

추가 옵션:

- `--proxy 127.0.0.1:8080`: 프록시 사용. `http://`를 생략할 수 있습니다.
- `--timeout 30`: 요청 제한 시간(초).
- `--max-len 256`: 문자열 길이 상한.
- `--max-rows 1000`: 행 수 상한.
- `--threshold 20`: 참 응답이 거짓 기준 응답보다 커야 하는 바이트 수.
- `--insecure`: 자체 서명 인증서를 사용하는 실습 환경에서 TLS 검증 생략.

참 응답이 더 짧거나 응답 길이가 계속 변하는 페이지는 이 판별 방식에 맞지 않습니다. 처음에 참/거짓을 구분할 수 있는지 검사합니다. 통신 실패, 리디렉션, HTTP 오류는 거짓으로 처리하지 않고 중단합니다. `-s`의 기본값은 HTTPS이며 HTTP 실습 서버에는 `-s http`를 지정하세요.

## SQLite 저장과 이전 버전의 차이

- `basic_info`, `dbs_info`, `table_info`, `column_info`, `data_dump` 테이블을 유지합니다.
- DB2의 현재 DB처럼 기존 기본 정보 테이블에 맞지 않는 필드는 `basic_results`에 저장합니다.
- `runs`에는 DBMS·DB·스키마·실행 모드·전체 결과 JSON을 실행별로 저장합니다. 서로 다른 DBMS/스키마의 결과를 구분할 때 이 테이블을 사용하세요. 기존 목록 테이블은 호환용이며 DBMS·스키마 구분이 없습니다.
- DB2 덤프는 임의 이름의 SQLite 테이블을 만들지 않고 `data_dump`에 저장합니다. 기존에 생성된 테이블은 삭제하지 않습니다.
- Version·User 기본 정보 호환 테이블은 해당 필드를 포함한 최근 성공 실행 결과로 갱신합니다. 전체 실행 기록은 `runs`에 남습니다.
- 결과 저장은 실행별 트랜잭션입니다. 실행 도중 실패하면 해당 실행의 결과는 저장하지 않습니다.
- `REQUEST_STRING` 상수는 제거했습니다. 로컬에서 사용하던 요청은 먼저 별도 파일로 옮기고 `-r`을 추가하세요.

## DB2 실습 서버

```sh
cd test_web
python -m pip install -r requirements.txt
# .env.example을 참고하여 셸에서 DB2_DATABASE, DB2_USER, DB2_PASSWORD 등을 설정
python app.py
```

`.env`는 자동으로 읽지 않습니다. DB2 서버와 USERS 테이블/실습 데이터는 별도로 준비해야 합니다. 기본 접속 주소는 `127.0.0.1:5001`이며 디버그 모드는 꺼져 있습니다. 다른 환경에서 접근해야 하면 `LAB_HOST`를 직접 지정합니다. 서버의 SQL 문자열 조합은 SQL Injection 실습을 위해 의도적으로 유지했습니다.

현재 서버는 DB2만 제공합니다. Oracle HTML 템플릿은 남아 있지만 Oracle 서버 라우트는 구현되어 있지 않습니다. 과거 `bak/sqli_bak.py`는 참고용이며 현재 CLI의 지원 범위에 포함하지 않습니다. 공개 소스에 포함되었던 자격 증명은 현재 파일에서 제거했지만 과거 Git 기록에는 남습니다. 실제 사용한 자격 증명은 교체해야 합니다.

## 개발·자동 검사

```sh
python -m pip install -r requirements-dev.txt
python -m ruff check sqli.py sqli_tool tests test_web/app.py
python -m unittest discover -s tests -v
```

GitHub Actions는 push/PR에서 Python 3.10·3.12·3.13으로 위 검사를 실행하도록 설정했습니다. GitHub에 반영하기 전에는 Actions가 실행되지 않습니다. 실제 DB 통합 테스트나 배포는 자동 실행하지 않습니다.

구조:

```text
sqli.py               실행 진입점
sqli_tool/cli.py       한국어 옵션·입력 검증
sqli_tool/http.py      요청 파싱·HTTP 통신
sqli_tool/dbms.py      DB별 SQL과 공통 인터페이스
sqli_tool/engine.py    공통 실행 흐름
sqli_tool/storage.py   SQLite 저장
sqli_tool/main.py      구성 요소 연결·종료 처리
```

SQL 구현 참고: [SQL Server 시스템 카탈로그](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/querying-the-sql-server-system-catalog-faq), [SUBSTRING](https://learn.microsoft.com/en-us/sql/t-sql/functions/substring-transact-sql), [PostgreSQL information_schema.columns](https://www.postgresql.org/docs/current/infoschema-columns.html).
