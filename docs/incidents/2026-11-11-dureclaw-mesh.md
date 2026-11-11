# 2026-11-11 — DureClaw mesh 컨테이너가 호스트 Tailscale을 flush해 SSH 전면 장애

## 요약

E2E 테스트(`dureclaw-core`의 `mesh-docker` 잡)가 운영 GPU 서버에서 실행되면서,
보조 tailscaled 인스턴스가 호스트의 iptables 체인을 지우고 동일 대역 IP를 점유해
**전 사용자 SSH가 약 17시간 중단**되었다. 테스트 종료 후 컨테이너가 정리되지 않아
재부팅 후에도 재발했다.

| 항목 | 내용 |
|---|---|
| 발생 | 2026-11-11 05:11 KST (E2E 실행 05:09~05:19) |
| 복구 | 2026-11-11 22:47 KST (`docker stop dureclaw-core-mesh-node-1`) |
| 영향 | GPU 서버 SSH(:2322) 타임아웃, JupyterLab 접속 불가 |
| 오판 포인트 | `tailscale ping`은 정상 → 모니터링이 "정상"으로 판단 |

## 원인

### 1) iptables 체인 공유
`docker-compose.mesh.yml`의 `mesh-node`는 `network_mode: host`에서 두 번째 tailscaled를 띄운다.
tailscaled는 인터페이스가 아니라 **체인 이름** 기준으로 룰을 관리하므로 기동 시 호스트 룰을 삭제한다.

```
cleanup: delete and flush chain ts-input
cleanup: delete and flush chain ts-forward
cleanup: delete and flush chain ts-postrouting
```

`ts-input`의 `-i tailscale0 -j ACCEPT`가 사라지면 `ufw`의 `INPUT policy DROP`이
tailnet 전체에 적용된다. `tailscale ping`은 tailscaled가 직접 응답하므로 계속 성공한다.

### 2) IP 대역 충돌
메시 Headscale이 메인 tailnet과 같은 `100.64.0.0/10` + 순차 할당을 사용해
첫 노드가 `100.64.0.1`을 받았고, 이는 관리자 노드의 tailnet IP와 충돌했다.
호스트가 해당 주소를 자기 것으로 인식하면서 관리자 패킷이 martian으로 폐기되었다.

```
dureclaw0: inet 100.64.0.1/32
ip route get 100.64.0.1 → local 100.64.0.1 dev lo
```

## 복구

```
docker stop dureclaw-core-mesh-node-1
```

## 재발 방지

1. E2E 워크플로에 teardown 추가: `docker compose -f docker-compose.mesh.yml down -v` (`if: always()`)
2. `mesh-node`에 `--netfilter-mode=off` (iptables 미관여)
3. 메시 전용 대역 분리: `100.100.0.0/16`
4. host-network tun을 쓰는 E2E는 운영 러너에서 분리

## 교훈 (이 저장소에 반영된 것)

- **헬스체크는 데이터 평면을 봐야 한다.** `tailscale ping` 대신 TCP 2322 연결 + SSH 배너를 확인하는
  `ops-watch/health_check.py`를 추가했다. 상태 전이 시 Discord 알림, `last_ok`/`since` 기록.
- **호스트 네트워크를 공유하는 보조 데몬은 체인 이름까지 충돌한다.** 격리 수준(프로세스/네트워크/iptables)을
  분리하지 않으면 "인터페이스와 포트를 다르게 했다"는 것으로는 부족하다.
- **테스트 인프라는 종료를 보장해야 한다.** `restart: unless-stopped` + teardown 부재는
  재부팅 후에도 장애를 되살린다.

## 참고

- 외부 이슈: `DureClaw/dureclaw-core#27`
- 관련 코드: `ops-watch/health_check.py`, `ops-watch/endpoint_tracker.py`(실제 `host_info` 기반 OS 판별)
