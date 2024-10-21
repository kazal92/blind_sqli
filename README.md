# Blind SQL Injection 발견 시 데이터 추출 자동화 도구
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


## 사용법  
BurpSuite 요청 데이터에 참/거짓(1=1) 조건문을 포함한 데이터를 REQUEST_STRING 변수에 추가하여 사용 (URL 디코딩 안해도됨)


결과 데이터는 .db 파일로 저장되며, DB나 테이블을 지정할 때 싱글쿼터를 생략 가능함 ex) "USERS, EXAMPLE_TABLE" <BR><BR>

기본 정보 추출:  
`python sqli.py -s http --dbms oracle -p username -d oracle_result.db --basic `<br><br>
  <img src="https://github.com/kazal92/Code/blob/main/images/console_result_basic.png" alt="설명" style="width:70%;height:auto;"><br><br>
DB 목록 추출:  
`python sqli.py -s http --dbms oracle -p username -d oracle_result.db --dbs `<br><br>
<img src="https://github.com/kazal92/Code/blob/main/images/console_result_dbs.png" alt="설명" style="width:70%;height:auto;"><br><br>

테이블 목록 추출:  
`python sqli.py -s http --dbms oracle -p username -d oracle_result.db --tables -D C##KAZAL92`<br><br>
<img src="https://github.com/kazal92/Code/blob/main/images/console_result_tables.png" alt="설명" style="width:70%;height:auto;"><br><br>
컬럼 목록 추출:  
`python sqli.py -s http --dbms oracle -p username -d oracle_result.db --columns -D C##KAZAL92 -T "'USERS', 'EXAMPLE_TABLE'"`<br><br>
<img src="https://github.com/kazal92/Code/blob/main/images/console_result_columns.png" alt="설명" style="width:70%;height:auto;"><br><br>
