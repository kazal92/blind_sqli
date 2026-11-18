"""원본 요청을 보존하고 파라미터 하나만 교체하여 전송한다."""

import json
from dataclasses import dataclass
from decimal import Decimal
from email.message import Message
from urllib.parse import parse_qsl, urlsplit

import requests

from .targets import (
    TargetError,
    json_bytes,
    json_path,
    json_replace,
    json_value,
    parse_xml,
    xml_bytes,
    xml_replace,
    xml_target,
)


class RequestError(ValueError):
    pass


def reject_json_constant(value):
    raise RequestError("JSON NaN·Infinity 값은 지원하지 않습니다.")


def utf8_content_type(value):
    header = Message()
    header["Content-Type"] = value
    header.set_param("charset", "utf-8", header="Content-Type", replace=True)
    return str(header["Content-Type"])


def json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RequestError("중복 JSON 키는 지원하지 않습니다.")
        result[key] = value
    return result


@dataclass
class ParsedRequest:
    method: str
    url: str
    headers: dict
    query: list
    body: object
    location: str
    parameter: str
    condition: str
    body_kind: str = ""
    path: tuple = ()

    def arguments(self, condition):
        query = list(self.query)
        body = self.body
        if self.location == "query":
            query = [
                (key, condition if key == self.parameter else value)
                for key, value in query
            ]
        elif self.location == "json":
            body = json_replace(self.body, self.path, condition)
        elif self.location == "xml":
            body = xml_replace(self.body, self.parameter, condition)
        else:
            body = [
                (key, condition if key == self.parameter else value)
                for key, value in body
            ]
        result = {"params": query, "headers": dict(self.headers)}
        if self.method == "POST":
            if self.body_kind == "json":
                result["data"] = json_bytes(body)
            elif self.body_kind == "xml":
                result["data"] = (
                    body if self.location == "xml" else xml_bytes(self.body)
                )
            else:
                result["data"] = body
        return result


def parse_request(raw, protocol, parameter, location="auto"):
    raw = raw.replace("\r\n", "\n").lstrip("\n")
    head, _, body_text = raw.partition("\n\n")
    lines = head.splitlines()
    try:
        method, target, version = lines[0].split()
    except (IndexError, ValueError) as exc:
        raise RequestError("첫 줄은 METHOD /path HTTP/1.1 형식이어야 합니다.") from exc
    method = method.upper()
    if method not in ("GET", "POST") or not version.startswith("HTTP/"):
        raise RequestError("GET·POST HTTP 요청만 지원합니다.")
    headers = {}
    for line in lines[1:]:
        key, separator, value = line.partition(":")
        if not separator or not key.strip():
            raise RequestError("HTTP 헤더 형식을 확인하세요.")
        key = key.strip().lower()
        if key in headers:
            raise RequestError("중복 HTTP 헤더는 지원하지 않습니다.")
        headers[key] = value.strip()
    host = headers.get("host")
    if not host or any(char in host for char in "/?#@ \\"):
        raise RequestError("올바른 Host 헤더가 필요합니다.")
    try:
        split = urlsplit(target)
    except ValueError as exc:
        raise RequestError("HTTP 요청 경로 형식을 확인하세요.") from exc
    if split.scheme or split.netloc or not target.startswith("/") or split.fragment:
        raise RequestError("요청 경로는 /로 시작하는 상대 경로여야 합니다.")
    if headers.get("content-encoding", "identity").lower() != "identity":
        raise RequestError(
            "압축된 요청 본문은 지원하지 않습니다. 압축을 해제한 요청을 저장하세요."
        )
    query = parse_qsl(split.query, keep_blank_values=True)
    body_kind, data, path = "", None, ()
    try:
        if method == "GET":
            if body_text.strip():
                raise RequestError("GET 요청 본문은 지원하지 않습니다.")
            if location not in ("auto", "query"):
                raise RequestError("GET 대상 위치는 query여야 합니다.")
            location = "query"
        else:
            content_type = (
                headers.get("content-type", "").split(";", 1)[0].strip().lower()
            )
            if content_type == "application/json" or content_type.endswith("+json"):
                try:
                    data = json.loads(
                        body_text,
                        object_pairs_hook=json_object,
                        parse_constant=reject_json_constant,
                        parse_float=Decimal,
                    )
                    json_bytes(data)
                except RequestError:
                    raise
                except (ValueError, RecursionError) as exc:
                    raise RequestError("JSON 본문 형식을 확인하세요.") from exc
                body_kind = "json"
                headers["content-type"] = utf8_content_type(headers["content-type"])
            elif content_type == "application/x-www-form-urlencoded":
                data, body_kind = (
                    parse_qsl(body_text.strip(), keep_blank_values=True),
                    "form",
                )
                headers["content-type"] = utf8_content_type(headers["content-type"])
            elif content_type in (
                "application/xml",
                "text/xml",
            ) or content_type.endswith("+xml"):
                data, body_kind = parse_xml(body_text), "xml"
                headers["content-type"] = utf8_content_type(headers["content-type"])
            elif body_text.strip() or location != "query":
                raise RequestError("POST 본문은 폼·JSON·XML만 지원합니다.")
            if location == "auto":
                location = body_kind
            if location != "query" and location != body_kind:
                raise RequestError(
                    "--location이 요청 본문의 Content-Type과 맞지 않습니다."
                )
        if location == "query":
            values = [value for key, value in query if key == parameter]
        elif location == "form":
            values = [value for key, value in data if key == parameter]
        elif location == "json":
            path = json_path(data, parameter)
            values = [json_value(data, path)]
        elif location == "xml":
            values = [xml_target(data, parameter)[2]]
        else:
            raise RequestError("대상 파라미터 위치를 확인하세요.")
    except TargetError as exc:
        raise RequestError(str(exc)) from exc
    if len(values) != 1 or not isinstance(values[0], str):
        raise RequestError("대상 파라미터는 문자열 값 하나로 지정해야 합니다.")
    condition = values[0]
    if condition.count("1=1") != 1:
        raise RequestError("대상 파라미터에 참 조건 1=1이 정확히 한 번 필요합니다.")
    # requests가 본문과 길이, 압축 방식을 다시 계산하도록 한다.
    for key in ("content-length", "transfer-encoding", "connection", "accept-encoding"):
        headers.pop(key, None)
    return ParsedRequest(
        method,
        f"{protocol}://{host}{split.path}",
        headers,
        query,
        data,
        location,
        parameter,
        condition,
        body_kind,
        path,
    )


class HTTPClient:
    def __init__(self, request, timeout=30, proxy=None, verify=True, session=None):
        self.request = request
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.verify = verify
        self.session = session if session is not None else requests.Session()

    def response(self, condition):
        try:
            response = self.session.request(
                self.request.method,
                self.request.url,
                **self.request.arguments(condition),
                timeout=self.timeout,
                proxies=self.proxies,
                verify=self.verify,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            # 예외 문자열에는 파라미터나 인증 정보가 포함될 수 있다.
            raise RequestError(
                f"HTTP 요청 실패 ({type(exc).__name__}). 연결·인증서·프록시를 확인하세요."
            ) from exc
        if not 200 <= response.status_code < 300:
            raise RequestError(f"HTTP {response.status_code} 응답: 실행을 중단합니다.")
        return response

    def size(self, condition):
        return len(self.response(condition).content)

    def close(self):
        self.session.close()
