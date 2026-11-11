# Baryon GPU Lab — 4090 서버 운영 · 보안 · 관제 스택

> **한 대의 RTX 4090 워크스테이션을 여러 연구원이 안전하게 나눠 쓰기 위한, 실제 운영 중인 구성 그대로의 코드.**
> Headscale 사설망 · 계정 수명주기 · egress 방화벽 · 감사/런타임 탐지 · 셀프호스팅 관제 콘솔 · LLM 기반 티켓 트리아지를 하나의 저장소에 담았습니다.

<sub>English abstract: An end-to-end operations stack for a single-GPU research workstation — private tailnet (Headscale), per-user isolation and lifecycle, egress firewalling, auditd/Falco detection, a self-hosted observability console, and schema-constrained LLM triage with provider fallback (agy → opencode → openrouter).</sub>

---

## 1. 이 저장소는 무엇인가

연구실 규모(사용자 3~10명, GPU 1~2대)에서 흔히 생기는 문제는 **성능이 아니라 운영**입니다.
누가 어떤 계정으로 들어오는지, GPU를 누가 얼마나 쓰는지, 실수로 LAN이나 다른 사용자 홈에 접근하지 않는지, 사고가 났을 때 근거가 남는지.

이 저장소는 그 문제들을 **한 대의 서버에서 실제로 돌아가는 형태로** 해결한 결과물입니다.

| 구성 | 내용 |
|---|---|
| `headscale/` | 사설 Tailnet(WireGuard) 제어 서버 연동, ACL, 학생 키 재발급 절차 |
| `labops/` | 사용자 레지스트리, 계정 수명주기(`labctl`), auditd 규칙, Falco 룰, 특권 요청 큐 |
| `ops-watch/` | 관제 대시보드(23450), GPU/NVMe/스토리지/프로세스 메트릭, 티켓 워크플로, LLM 트리아지, SSH 워치독 |
| `scripts/` | `setup/` 사용자·환경 구성, `hardening/` 서버 하드닝 및 CVE 임시 완화 |
| `docs/` | 아키텍처, 보안 감사 보고서, 실제 사고 기록 |
| `examples/` | GPU 추론/LoRA 예제, Jupyter MCP 클라이언트 |

---

## 2. 왜 오픈소스로 공개하는가 (의의)

### 2.1 "작은 연구실"을 위한 완결된 보안 운영 레퍼런스가 없다
대기업용 Kubernetes/SSO/EDR 스택은 넘치지만, **GPU 한 대 + 사용자 다섯 명** 규모에 맞는 현실적인 구성은 문서화되어 있지 않습니다.
이 저장소는 ACL · 계정 만료 · egress 차단 · 감사 로그 · 알림 · 온보딩 자동화를 **하나의 재현 가능한 세트**로 제공합니다. 다른 연구실은 fork 해서 사용자 목록과 IP만 바꾸면 됩니다.

### 2.2 실패와 오판을 함께 공개한다
운영 도구는 "잘 될 때"보다 **"잘못 판단할 때"** 가 위험합니다. 이 저장소에는 실제 사고가 기록되어 있습니다.

- `tailscale ping`은 정상인데 SSH만 죽는 장애 → **ping은 tailscaled가 응답하는 것이고 데이터 평면과 다르다**는 사실을 모르면 몇 시간을 잃습니다.
- 두 번째 tailscaled 컨테이너가 같은 iptables 체인(`ts-input`)을 flush해 전 사용자 SSH가 17시간 중단된 사고 → `docs/incidents/2026-11-11-dureclaw-mesh.md`
- 그 결과 `ops-watch`에 **TCP 2322 + SSH 배너** 기반 워치독을 추가했습니다. (`ops-watch/health_check.py`)

같은 함정을 다른 팀이 반복하지 않도록, 탐지 공백과 그 보완 과정을 그대로 남깁니다.

### 2.3 LLM 운영 자동화의 "현실적인" 패턴
LLM을 관제에 붙일 때 필요한 것은 멋진 프롬프트가 아니라 **스키마 강제 · 폴백 · 감사 기록**입니다.

- 온톨로지(`ontology.json`) 기반 판정 + JSON Schema 강제 출력
- 제공자 폴백 체인: **`agy` → `opencode` → `openrouter`** (하나가 빈 응답/거부/타임아웃이면 다음으로)
- 어떤 제공자·모델이 판단했는지 worklog에 `llm:<provider>` 태그로 기록
- 추측(호스트명 기반 OS 판별)을 실제 데이터(Headscale `host_info`)로 교체한 과정

"LLM이 알아서 다 한다"가 아니라, **틀릴 수 있음을 전제로 설계하는 방법**을 공유합니다.

### 2.4 개인정보·시크릿을 코드와 분리하는 템플릿
사용자 이메일, SSH 공개키, Discord 웹훅, 초대 메일 본문은 **코드와 같은 저장소에 두면 안 됩니다.**
이 저장소는 `secrets/`, `private/`, `state/`를 기본적으로 배제하고, 공개 전 점검용 체크리스트(§7)를 제공합니다.

### 2.5 단일 GPU에서 멀티유저 인프라로 가는 최소 경로
GPU 1대 → 사용자별 격리 → 원격 접속 → 사용량 관제 → 사고 대응까지, **과하지 않은 최소 구성**으로 단계별 확장이 가능하도록 정리했습니다.

---

## 3. 아키텍처

![Baryon Lab 4090 서버 아키텍처](docs/architecture.png)

> 원본(HTML, 확대 가능): [`docs/architecture.html`](docs/architecture.html)
> — **서버 설치 항목**(호스트 서비스·Docker·스토리지), **맥용 관리자 앱**(Ops-Watch), **Discord 알림 경로**까지 한 장에 정리했습니다.

- **접속**: Tailnet 전용, SSH는 비표준 `2322`, 키 인증만 허용
- **격리**: 학생 계정은 `gpu4090:2322`만 허용(ACL), egress 방화벽으로 LAN·타 노드·관리 포트 차단
- **관제**: 5분 주기 저널 스캔 + 60초 SSH 도달성 워치독 + GPU/온도/스토리지
- **트리아지**: 온톨로지 기반 LLM 분석(스키마 강제) + 제공자 폴백

상세 다이어그램: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## 4. 빠른 시작

### 요구사항
- Ubuntu 24.04 (단일 GPU 서버), Docker, Python 3.11+
- Headscale(또는 Tailscale) 제어 서버
- 관제 대시보드를 띄울 관리자 머신(서버와 SSH 연결)

### 1) 서버 하드닝
```bash
sudo bash scripts/hardening/harden.sh          # 즉시 적용
sudo bash scripts/hardening/harden.sh --reboot # 커널 업그레이드 + 재부팅 포함
sudo bash scripts/hardening/mitigate-cve-2026-98432.sh  # 커널 패치 전 임시 완화
```

### 2) 사설망 (Headscale)
```bash
bash headscale/onboard-student.sh <username>
bash headscale/reissue-student-key.sh <username>            # 미리보기
bash headscale/reissue-student-key.sh <username> --execute  # 노드 만료 + 새 키 발급
```
ACL: [`headscale/acl.hujson`](headscale/acl.hujson)

### 3) 사용자 수명주기
```bash
sudo bash labops/install.sh
sudo labctl sync            # users.yaml → 시스템 계정/Headscale 반영
sudo labctl status <user>
```

### 4) 관제 콘솔
```bash
cd ops-watch
OPS_WATCH_PORT=23450 python3 dashboard.py
# http://localhost:23450
```

주요 환경변수:

| 변수 | 기본값 | 설명 |
|---|---|---|
| `OPS_WATCH_PORT` | `23450` | 대시보드 포트 |
| `OPS_WATCH_SCAN_INTERVAL` | `300` | 저널 자동 스캔 주기(초) |
| `OPS_WATCH_SSH_HOST` / `_PORT` | `100.64.0.2` / `2322` | SSH 워치독 대상 |
| `OPS_WATCH_LLM_CHAIN` | `agy,opencode,openrouter` | LLM 폴백 순서 |
| `OPS_WATCH_MODEL` | `gemini-3.8-flash-medium` | `agy` 모델 |
| `OPS_WATCH_OPENCODE_MODEL` | `opencode-go/deepseek-v4.1-flash` | `opencode` 모델 |
| `OPS_WATCH_OPENROUTER_MODEL` | `deepseek/deepseek-v4.1-flash` | OpenRouter 모델 |
| `OPENROUTER_API_KEY` | – | OpenRouter 키(없으면 `~/.config/baryon/env` 등에서 탐색) |

---

## 5. 보안 모델

| 계층 | 통제 |
|---|---|
| 네트워크 | Tailnet ACL(관리자 전체 / 학생 `gpu4090:2322`), `ufw default deny`, `student-egress`(LAN·docker망·관리 포트 차단) |
| 계정 | 키 전용 SSH, 비표준 포트, `AllowUsers`, 계정 만료(`chage -E`), sudo 최소화 |
| 런타임 | auditd 규칙(`labops/audit`), Falco 룰(`labops/falco`), 커널 CVE 임시 완화(nftables) |
| 관제 | 저널 스캔 → 티켓, 단말/OS 변경 추적, 프로세스 이상 탐지, SSH 도달성(TCP+배너) |
| 비밀 | `secrets/`·`private/`·`state/` 저장소 배제, 웹훅/키 파일 분리 |

> ⚠️ 이 저장소의 기본 설정은 **단일 관리자·신뢰된 연구실**을 전제로 합니다. 인터넷에 직접 노출하는 용도가 아니며, 공개 배포 시 ACL·계정 목록·IP를 반드시 자신의 환경에 맞게 바꾸세요.

---

## 6. 운영 런북

- **신규 연구원 온보딩**: `labctl sync` → Headscale pre-auth key 발급 → 개인 JupyterLab 컨테이너 → 접속 안내
- **VPN 키 재발급(의심 단말)**: `headscale/reissue-student-key.sh <user> --execute`
- **사고 대응**: ops-watch 티켓 → LLM 분석(또는 수동) → 승인 시 allowlist 액션 실행 → worklog 기록
- **장애 복구**: `docs/incidents/` 참고. SSH 불통 시 *데이터 평면* 확인(TCP 2322), `iptables -S ts-input`, `ip addr show tailscale0`

---

## 7. 공개(Open Source) 전 체크리스트

이 저장소는 현재 **프라이빗**입니다. 공개 전에 아래를 반드시 처리하세요.

- [ ] `secrets/`, `private/`, `emails/`, `state/`, `*.log` 미포함 확인
- [ ] `labops/users.yaml`의 실제 이메일·SSH 공개키 → 예시 값으로 교체
- [ ] `scripts/hardening/harden.sh`의 ngrok URL·호스트명 등 환경 상수 일반화
- [ ] `headscale/acl.hujson`의 사용자/그룹 이름 일반화
- [ ] git 히스토리 시크릿 스캔 (`gitleaks detect --no-git=false`)
- [ ] 라이선스 결정 및 `LICENSE` 추가
- [ ] `SECURITY.md`(취약점 신고 절차) 추가
- [ ] 저장소 이름/설명/토픽 정리

## 8. 라이선스

**TBD** — 공개 시점에 결정합니다. (권장: Apache-2.0 또는 MIT)

## 9. 기여 / 문의

이슈와 PR을 환영합니다. 보안 관련 제보는 공개 이슈 대신 저장소 관리자에게 비공개로 연락해 주세요.

---

<sub>Built and operated by Baryon Labs. 이 문서의 구성·수치는 실제 운영 서버(`martin-B650M-K`, RTX 4090 24GB)를 기준으로 작성되었습니다.</sub>
