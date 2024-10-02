**SQL 인젝션 발견 시 조건식을 포함한 request를 코드 내 붙혀넣으면됨
**
```
usage: sqli.py [-h] [-s SCHEMA] [-p PARAMETER] [-d RESULT_DB] [--proxy PROXY] [--dbms DBMS] [--basic] [--dbs] [--tables] [--columns]

optional arguments:
  -h, --help     show this help message and exit
  -s SCHEMA      http? https?
  -p PARAMETER   target param
  -d RESULT_DB   Database name for storing results ex) -d result_db.db
  --proxy PROXY  Use a proxy to connect to the target URL
  --dbms DBMS    SELECT DBMS : MySQL, Oracle, MSSQL, PostgreSQL
  --basic        Basic info extraction
  --dbs          Enumerate DBMS databases
  --tables       Enumerate Tables
  --columns      Enumerate columns
```

  ex)
  `python sqli.py -s http -p title --dbms mysql --dbs -d result_db.db`

  
