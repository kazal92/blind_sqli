"""JSON Pointer와 XML 요소·속성의 대상 값을 선택한다."""

import copy
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from decimal import Decimal
from xml.dom import Node, minidom
from xml.parsers.expat import ExpatError


class TargetError(ValueError):
    pass


def json_bytes(document):
    # 대상 외의 고정밀 소수도 float로 반올림하지 않고 보존한다.
    def encode(value):
        if isinstance(value, dict):
            return (
                "{"
                + ",".join(
                    json.dumps(key) + ":" + encode(item) for key, item in value.items()
                )
                + "}"
            )
        if isinstance(value, list):
            return "[" + ",".join(encode(item) for item in value) + "]"
        if isinstance(value, Decimal):
            if not value.is_finite():
                raise TargetError("JSON 숫자는 유한한 값이어야 합니다.")
            return str(value)
        return json.dumps(value, ensure_ascii=False, allow_nan=False)

    return encode(document).encode("utf-8")


def json_path(document, parameter):
    if parameter == "":
        return ()
    if not parameter.startswith("/"):
        if not isinstance(document, dict) or parameter not in document:
            raise TargetError(
                "JSON 최상위 키를 찾을 수 없습니다. 중첩 값에는 JSON Pointer를 사용하세요."
            )
        return (parameter,)
    path = []
    node = document
    for part in parameter[1:].split("/"):
        if re.search(r"~(?![01])", part):
            raise TargetError("JSON Pointer의 ~는 ~0 또는 ~1로 이스케이프하세요.")
        key = part.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", key):
                raise TargetError("JSON 배열에는 0부터 시작하는 인덱스를 지정하세요.")
            try:
                key = int(key)
            except ValueError as exc:
                raise TargetError("JSON 배열 인덱스가 너무 큽니다.") from exc
        elif not isinstance(node, dict):
            raise TargetError("JSON 경로의 중간 값은 객체 또는 배열이어야 합니다.")
        try:
            node = node[key]
        except (KeyError, IndexError) as exc:
            raise TargetError("JSON Pointer 경로에 대상 값이 없습니다.") from exc
        path.append(key)
    return tuple(path)


def json_value(document, path):
    for key in path:
        document = document[key]
    return document


def json_replace(document, path, value):
    if not path:
        return value
    result = copy.deepcopy(document)
    parent = json_value(result, path[:-1])
    parent[path[-1]] = value
    return result


@dataclass
class XMLDocument:
    root: ET.Element
    document: minidom.Document


def parse_xml(text):
    # 외부 엔티티뿐 아니라 내부 DTD·엔티티 확장도 받지 않는다.
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I):
        raise TargetError("XML DTD·엔티티 선언은 지원하지 않습니다.")
    # 파일은 UTF-8로 읽으며 전송도 UTF-8로 통일한다.
    text = re.sub(
        r"(<\?xml\s[^?]*?encoding\s*=\s*)(['\"])[^'\"]*\2",
        r'\1"utf-8"',
        text,
        count=1,
        flags=re.I,
    )
    try:
        return XMLDocument(
            ET.fromstring(text), minidom.parseString(text.encode("utf-8"))
        )
    except (ET.ParseError, ExpatError, ValueError) as exc:
        raise TargetError("XML 본문 형식을 확인하세요.") from exc


def xml_target(root, selector):
    root = root.root if isinstance(root, XMLDocument) else root
    path, attribute = selector, None
    if "/@" in selector:
        path, attribute = selector.rsplit("/@", 1)
    elif selector.startswith("@"):
        path, attribute = ".", selector[1:]
    if not path or (attribute is not None and not attribute):
        raise TargetError("XML 요소 또는 속성 경로를 지정하세요.")
    try:
        elements = root.findall(path) if path != "." else [root]
    except (KeyError, SyntaxError) as exc:
        raise TargetError(
            "XML 경로 형식을 확인하세요. 루트 기준 ./요소 또는 .//요소를 사용하세요."
        ) from exc
    if len(elements) != 1:
        raise TargetError(
            "XML 대상은 정확히 하나여야 합니다. 경로·이름공간·인덱스를 확인하세요."
        )
    element = elements[0]
    if attribute is not None:
        if attribute not in element.attrib:
            raise TargetError("XML 속성을 찾을 수 없습니다.")
        return element, attribute, element.attrib[attribute]
    if len(element):
        raise TargetError("XML 대상은 자식 요소가 없는 텍스트 요소여야 합니다.")
    return element, None, element.text or ""


def xml_bytes(document):
    return document.document.toxml(encoding="utf-8")


def xml_replace(document, selector, value):
    element, attribute, _ = xml_target(document, selector)
    index = next(
        index for index, node in enumerate(document.root.iter()) if node is element
    )
    cloned = document.document.cloneNode(deep=True)
    target = cloned.getElementsByTagName("*")[index]
    if attribute is None:
        for child in list(target.childNodes):
            if child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE):
                target.removeChild(child)
        target.appendChild(cloned.createTextNode(value))
    elif attribute.startswith("{"):
        uri, local = attribute[1:].split("}", 1)
        target.getAttributeNodeNS(uri, local).value = value
    else:
        target.setAttribute(attribute, value)
    # DOM이 접두사·선언·비대상 CDATA 등을 보존하므로 SOAP QName도 유지한다.
    return cloned.toxml(encoding="utf-8")
