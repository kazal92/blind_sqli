"""응답 크기 또는 문자열로 참·거짓을 판별한다."""


class ExecutionError(ValueError):
    pass


class SizeOracle:
    CHECK_INTERVAL = 50

    def __init__(self, client):
        self.client = client
        self.references = {}
        self.checks = 0

    def read(self, predicate):
        condition = self.client.request.condition.replace("1=1", predicate)
        return self.client.size(condition)

    def calibrate(self):
        self.references = {True: self.read("1=1"), False: self.read("1=2")}
        for truth, size in self.references.items():
            print(f"{'참' if truth else '거짓'} 응답: {size} bytes (1회 측정)")
        if self.references[True] == self.references[False]:
            raise ExecutionError(
                "참·거짓 응답 크기가 같습니다. --string 또는 --not-string을 지정하세요."
            )
        print("측정한 참·거짓 크기와 정확히 일치하는 응답으로 판별합니다.")

    def classify(self, value):
        for truth, reference in self.references.items():
            if value == reference:
                return truth
        return None

    def verify(self):
        for truth in (True, False):
            if self.classify(self.read("1=1" if truth else "1=2")) is not truth:
                raise ExecutionError(
                    "참·거짓 기준이 변경되었습니다. 세션·페이지를 확인하세요."
                )
        self.checks = 0

    def check(self, predicate):
        if not self.references:
            raise ExecutionError("참·거짓 기준 확인이 필요합니다.")
        if self.checks >= self.CHECK_INTERVAL:
            self.verify()
        result = self.classify(self.read(predicate))
        if result is None:
            raise ExecutionError(
                "응답을 참·거짓으로 판별할 수 없습니다. 실행을 중단합니다."
            )
        self.checks += 1
        return result


class StringOracle(SizeOracle):
    def __init__(self, client, string=None, not_string=None):
        super().__init__(client)
        self.string = string
        self.not_string = not_string

    def read(self, predicate):
        condition = self.client.request.condition.replace("1=1", predicate)
        return self.client.response(condition).text

    def classify(self, value):
        true_match = self.string in value if self.string is not None else None
        false_match = self.not_string in value if self.not_string is not None else None
        if true_match is not None and false_match is not None:
            return true_match if true_match != false_match else None
        return true_match if true_match is not None else not false_match

    def calibrate(self):
        for truth in (True, False):
            response = self.read("1=1" if truth else "1=2")
            if self.classify(response) is not truth:
                raise ExecutionError(
                    "참·거짓 응답이 지정한 문자열 기준과 맞지 않습니다. 판별 문자열을 확인하세요."
                )
        self.references = {True: True, False: False}
        print("문자열 판별: 참·거짓 요청 각 1회 확인 완료 (대소문자 구분)")
