# linux-machine-4090

연구실 공용 GPU 서버 **martin-B650M-K** (RTX 4090 24GB, Ubuntu 24.04) 운영 저장소.
학생 계정 관리, 보안 하드닝, 모니터링(labops), 점검 기록을 여기서 관리한다.

| 항목 | 값 |
|---|---|
| 접속 | `ssh linux-builder` (= `martin@100.64.0.2 -p 2322`, Tailscale/Headscale 전용) |
| Headscale | 이 서버의 docker `headscale`, 공개 주소 `https://headscale-tunnel.example` (ngrok 고정 dev 도메인, systemd `ngrok-headscale`) |
| 데이터 | `/mnt/data/users/<user>` (700), 홈의 `~/data` 링크. 관리자 데이터는 `/mnt/data/users/admin2` |
| 알림 | Discord 웹훅 (`/etc/labops/discord-webhook.url`, root 600 — 저장소에 없음) |

## 구성

| 경로 | 내용 |
|---|---|
| `labops/` | 운영 도구: `labctl`(사용자 추가·제거·연장), `users.yaml`(사용자 목록), auditd·acct·Falco·GPU 수집·SSH 접속/GPU 임계 알림·`labreq` 권한 요청 큐. 설치: `sudo bash ~/labops/install.sh` — 자세한 내용은 [labops/README.md](labops/README.md) |
| `harden.sh` | 학생 egress 방화벽, sshd `Match Group students`, sudo 정리, 미사용 계정 잠금 등 하드닝 (멱등) |
| `mitigate-cve-2026-98432.sh` | 커널 수정판 전까지 IPv4 IP 옵션 TCP 차단(nft, systemd `cve-2026-98432`) |
| `headscale/` | ACL(`acl.hujson`: admin=전체, students=`gpu4090:2322`만), 학생 Headscale 등록 스크립트 |
| `add-user-student1.sh`, `finish-student1.sh` | 첫 학생 계정 수동 생성 기록 (이후 사용자는 `labctl add`) |
| `build-envs.sh`, `setup-student1-env.sh`, `examples/` | 연구 환경: venv `qwen3vl`(py3.12, torch 2.15/cu132), `vidlada`(py3.10, torch 2.5.1/cu124), 모델 캐시, 예제 |
| `SECURITY_AUDIT_2026-11-04.md` | 보안 점검 보고서 (발견 → 조치 → 재부팅 후 최종 상태) |

## 비밀값 (커밋 금지, `.gitignore`)

`secrets/`(Discord 웹훅), `email-reply-student1.txt`(학생 Headscale 키), `fix-control-plane.sh`(관리자 재사용 키).
새 비밀값은 저장소에 넣지 말고 서버의 root 600 파일로만 둔다.

## 자주 쓰는 작업

```bash
sudo labctl --dry-run sync && sudo labctl sync     # users.yaml 반영
sudo labctl add <user> / remove <user> / extend <user> <YYYY-MM-DD>
labctl list ; labctl report ; labctl requests      # 상태, GPU 사용, 권한 요청 (martin, sudo 불필요)
sudo bash ~/labops/install.sh                      # labops 재배포 (멱등)
```

주의: ngrok은 항상 `--url <고정 도메인>`으로만 실행한다 (맨 `ngrok http`는 임시 주소를 만들어 tailnet 제어가 끊긴다).
NVIDIA 드라이버 패키지는 업데이트 직후 반드시 재부팅한다.

## 남은 일 (2026-11-04 기준)

- CVE-2026-98432 수정 커널(≥ 6.8.0-149) 대기 — Livepatch 활성화됨, 수정 후 nft 완화 해제
- HF 토큰·`GEMINI_API_KEY` 재발급, NucBox Headscale 재연결, `0.0.0.0:487`(root) 확인
- 학생 첫 로그인 후 auditd `student_exec` 실기록 확인
- 정기 CVE 스윕: `baryonlabs/security-sweep` 적용 검토 (서버 trivy 설치 경로 결정 필요)
