#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")/.."
export LAB_UID="${SUDO_UID:-$(id -u)}"
export LAB_GID="${SUDO_GID:-$(id -g)}"
if [[ ! -f requests/burp.http ]]; then
    echo 'Burp의 거짓 조건 요청을 requests/burp.http에 먼저 저장하세요.' >&2
    exit 1
fi
mkdir -p lab/results
if [[ $(id -u) == 0 ]]; then
    chown "$LAB_UID:$LAB_GID" lab/results
fi
docker compose -f lab/compose.yaml run --rm --no-deps cli \
    -r /requests/burp.http -s http -p password --dbms mysql \
    -d /results/burp-result.db "$@"
