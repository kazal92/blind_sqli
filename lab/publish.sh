#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."

export LAB_IMAGE="${LAB_IMAGE:-kazal92/blind-sqli-lab}"
export LAB_UID="${SUDO_UID:-$(id -u)}"
export LAB_GID="${SUDO_GID:-$(id -g)}"
mkdir -p requests lab/results
if [[ $(id -u) == 0 ]]; then
    chown "$LAB_UID:$LAB_GID" requests lab/results
fi
docker info >/dev/null
docker compose version
echo '1/4: MySQL 8.4 및 실습 웹 서버 이미지 빌드'
docker compose -f lab/compose.yaml build --pull db web
echo '2/4: localhost:5080 실습 서버 시작'
docker compose -f lab/compose.yaml up -d --wait --wait-timeout 180 db web
echo '3/4: 실제 MySQL을 통한 기본 정보·DB·테이블·컬럼 검사'
docker compose -f lab/compose.yaml run --rm --no-deps --entrypoint python cli -m lab.smoke
echo '4/4: 테스트한 이미지를 Docker Hub에 업로드'
docker push "$LAB_IMAGE:mysql84-db"
docker push "$LAB_IMAGE:mysql84"
docker manifest inspect "$LAB_IMAGE:mysql84-db" >/dev/null
docker manifest inspect "$LAB_IMAGE:mysql84" >/dev/null
echo "완료: $LAB_IMAGE:mysql84-db 및 $LAB_IMAGE:mysql84"
echo '실습 주소: http://127.0.0.1:5080'
echo '계정: admin / lab-demo'
echo 'Burp 요청을 requests/burp.http에 저장한 후 아래 명령으로 테스트하세요.'
echo 'sudo bash lab/run.sh --tables -D lab'
