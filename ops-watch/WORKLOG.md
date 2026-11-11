# 운영 업무기록 (Durable Worklog)

이 문서는 `state/ops-watch.db`의 운영 판단·승인·분석 이력을 요약합니다.

## 최근 운영 로그

### 2026-11-08 11:40:22 — operator-note (Ticket #2)
```text
Discord Webhook URL 신규 채널로 교체 및 테스트 발송 완료:
1. 신규 Webhook URL:
   https://discord.com/api/webhooks/1568816187939233824/<REDACTED>
2. 적용 위치:
   - 로컬: secrets/discord-webhook.url
   - GPU 서버(martin-B650M-K): /home/martin/.labops-discord-webhook.url (chmod 600)
3. 검증 결과:
   - 로컬 및 GPU 서버 양쪽에서 테스트 발송 결과 HTTP 204/200 정상 전달 확인 (notified: true)
   - 10분 주기 systemd --user timer 및 crontab에 즉시 반영됨.
```

### 2026-11-08 11:39:27 — operator-note (Ticket #2)
```text
⚡ RTX 4090 GPU 사용량 10분 주기 감시 및 10% 이상 변동 시 학생용 Discord 웹훅 알림 시스템 구축 완료:
1. 기능 및 트리거 조건:
   - 10분 주기로 GPU 연산 점유율(utilization.gpu %) 및 VRAM 점유율(vram_pct %) 확인.
   - 직전 통지 시점 대비 GPU 연산률 또는 VRAM 점유율이 10%p 이상 변동 시 Discord 웹훅 자동 발송.
   - 예: 0% -> 80% (훈련 시작 감지), 80% -> 0% (실험 종료 및 VRAM 반납 감지).
2. 메시지 구성 (학생 연구원 친화적 안내):
   - 상태 뱃지: 🟢 여유 (사용 가능) / 🟡 일부 사용 중 / 🔴 훈련 중 (점유율 높음)
   - 변동 내역: GPU 연산률 및 VRAM 점유율 전후 비교 수치
   - 상세 지표: GPU 점유율, VRAM 사용/가용 용량(GB), 온도, 소비 전력(W)
   - 실행 중인 프로세스 목록: 점유 사용자(student1 등), PID, 작업명, 점유 VRAM(GB)
   - 학생 연구원 에티켓: JupyterLab 'Kernel -> Shut Down All Kernels' VRAM 반납 규정 및 개인별 접속 링크
3. 배포 및 이중화 구성:
   - GPU 서버(martin-B650M-K) 자체에 /home/martin/scripts/gpu-discord-notifier.py 영구 배치
   - systemd --user timer (gpu-discord-notifier.timer, OnCalendar=*:0/10) 및 crontab 이중 등록 (Linger=yes 적용으로 24시간 무중단 동작)
   - 로컬 ops-watch 웹 대시보드(http://localhost:23450) 연동: GET /api/gpu/discord_status 및 1클릭 즉시 브로드캐스트 버튼 추가
```

### 2026-11-06 23:05:55 — operator-note (Ticket #2)
```text
Student One 연구원 2번째 기기(노트북/태블릿/PC) 등록용 Pre-Auth Key 발급 및 안내 메일 발송 완료:
1. 대상 계정: student1 (User ID: 2, group:students)
2. 발급된 2번째 기기 전용 Headscale Pre-Auth Key (90일 유효):
   hskey-<REDACTED>
3. 이메일 발송 결과 (gog CLI / admin@example.com):
   - 수신: student1@example.com
   - Message ID: 1a1b12dfbd5ec67c
   - 제목: [martin-B650M-K] Student One 연구원 2번째 기기(노트북/태블릿/PC) 등록 및 VPN 연결 가이드 (Bilingual Guide)
   - 본문 파일: emails/email-2nd-device-student1.txt
4. 포함된 지침:
   - macOS / Windows / Linux 1줄 터미널 연결 명령어
   - iPadOS / iOS / Android Tailscale 앱 Custom Coordination Server 설정 절차
   - 전용 JupyterLab(포트 8889) 및 8TB jupyter_home 스토리지 동기화 안내
   - 다중 기기 사용 시 24GB VRAM Shut Down All Kernels 회수 에티켓 안내
```

### 2026-11-06 19:05:47 — operator-note (Ticket #2)
```text
연구실 전체 인프라 및 관제 아키텍처 다이어그램 문서(ARCHITECTURE.md) 생성 완료:
1. 문서 저장 위치:
   - 아티팩트: architecture_specification.md
   - 프로젝트 루트: ARCHITECTURE.md
2. 수록된 핵심 아키텍처 도식:
   - 1) 클라이언트 - Headscale(Zero-Trust VPN) - GPU 서버(martin-B650M-K) 전체 흐름 다이어그램 (Mermaid)
   - 2) 사용자별 독립 컨테이너 포트(8888, 8889, 8890, 8891) 및 토큰 매핑 명세
   - 3) NVMe(914GB) OS 디스크 보호를 위한 8TB HDD jupyter_home 및 캐시 3중 마운트 구조도 (Mermaid)
   - 4) Ops-Watch(Falco eBPF, process_inspector, storage_monitor, Auto-Ontology, Jupyter MCP) 관제 계층도 (Mermaid)
```

### 2026-11-06 09:12:44 — operator-note (Ticket #2)
```text
PID 288277 (/usr/bin/dbus-daemon deleted) 이상 프로세스 경보 원인 규명 및 조치 완료:
1. 원인 분석:
   - 2026-11-06 08:25:17 KST에 apt/dpkg에 의해 dbus-daemon(1.16.2-2ubuntu4) 패키지가 자동 업그레이드됨.
   - 디스크 상의 /usr/bin/dbus-daemon 바이너리가 새 버전으로 교체되었으나, 05:05에 실행된 기존 martin 사용자 세션 dbus(PID 288277)가 메모리에 남아 있어 커널에서 '/usr/bin/dbus-daemon (deleted)'로 표기됨.
   - 악성코드 침투가 아닌 정상적인 리눅스 패키지 업데이트(needrestart 대상)에 따른 False Positive임.
2. 조치 내역:
   - 'systemctl --user daemon-reload && systemctl --user restart dbus.service' 실행하여 신규 바이너리(PID 660875)로 깔끔하게 재시작 완료.
   - 현재 호스트 상에 삭제된 바이너리를 실행 중인 프로세스 0개 확인.
3. 관제 엔진(process_inspector.py) 오탐 방지 로직 개선:
   - 프로세스 소유자(user)를 'unknown'이 아닌 실제 계정으로 파싱하도록 보완.
   - /usr/bin 등 표준 시스템 경로의 바이너리가 디스크에 여전히 존재하는 경우 패키지 업데이트(info)로 분류하여 불필요한 CRITICAL 경보 방지.
```

### 2026-11-06 07:50:57 — operator-note (Ticket #2)
```text
관리자(martin) iPad 기기 추가용 Headscale Pre-Auth Key 발급 완료:
1. 대상 계정: martin (User ID: 1, group:admin 관리자 권한)
2. 발급된 사전 인증키 (유효기간 90일 / 2160시간):
   hskey-<REDACTED>
3. iPad Tailscale 앱 설정 정보:
   - Login Server URL: https://headscale-tunnel.example
   - 권한 범위: Headscale ACL상 group:admin (*:*) 전체 포트 무제한 접근 보장 (100.64.0.2:8888 관리자 주피터랩 포함)
```

### 2026-11-06 07:49:07 — operator-note (Ticket #2)
```text
gog CLI를 통한 공식 영문+국문(Bilingual) 인프라 및 전용 JupyterLab 이용 가이드 발송 완료:
1. 발송 계정: admin@example.com (gog v0.46.0 OAuth 연동)
2. 수신자 및 발송 내역:
   - Student One 연구원 (student1@example.com): Message ID 1a1ade5dc9a35336
     제목: [martin-B650M-K] 연구실 RTX 4090 인프라 이용 및 전용 JupyterLab 접속 가이드 (Bilingual Guide)
     본문: emails/email-bilingual-student1.txt
   - Student Two 연구원 (student2@example.com): Message ID 1a1ade5ef2aead79
     제목: [martin-B650M-K] Lab RTX 4090 Infrastructure & Dedicated JupyterLab User Guide (Bilingual Guide)
     본문: emails/email-bilingual-student2.txt
   - Student Three 연구원 (student3@example.com): Message ID 1a1ade601cf8abe8
     제목: [martin-B650M-K] 연구실 RTX 4090 인프라 이용 및 전용 JupyterLab 접속 가이드 (Bilingual Guide)
     본문: emails/email-bilingual-student3.txt
3. 공통 포함 내용:
   - Headscale WireGuard VPN 개인별 1회용 인증키 및 접속 명령어
   - 개인별 격리 컨테이너 및 JupyterLab URL/보안 토큰
   - 8TB /workspace(jupyter_home), data_root/, home/ 스토리지 및 HF_HOME/TORCH_HOME 캐시 리다이렉트 필수 안내
   - 단일 RTX 4090 24GB VRAM 공유 수칙 및 Shut Down All Kernels 반납 규정
   - 비표준 SSH(2322) 포트 및 GPU 실시간 모니터링 안내
```

### 2026-11-06 07:38:34 — operator-note (Ticket #2)
```text
학생 3명(Student One, Student Two, Student Three) 대상 공식 인프라 및 주피터랩 사용법 안내 메일 작성 완료:
1. 대상 및 파일 생성:
   - Student One 연구원: emails/email-guide-student1.txt (포트: 8889, 암호학적 난수 토큰, jupyter_home 작업폴더)
   - Student Two 연구원: emails/email-guide-student2.txt (영문 공식 가이드, 포트: 8890)
   - Student Three 연구원: emails/email-guide-student3.txt (포트: 8891, 1회용 VPN키 및 주피터랩 안내)
2. 포함된 공식 지침 5단계:
   - Step 1: Headscale WireGuard VPN 연결 및 1회용 인증키
   - Step 2: 개인 전용 JupyterLab 격리 컨테이너 접속 (포트 및 보안 토큰)
   - Step 3: 스토리지 분리 원칙 (8TB jupyter_home 기본 마운트 및 HF_HOME 캐시 리다이렉트 필수 코드)
   - Step 4: 단일 GPU(24GB VRAM) 에티켓 및 Kernel Shut Down 절차
   - Step 5: SSH 접속(2322) 및 nvidia-smi GPU 모니터링 방법
```

### 2026-11-06 07:20:38 — operator-note (Ticket #2)
```text
주피터랩 시작 폴더를 /mnt/data/users/martin/jupyter_home/ 으로 독립 분리 적용 완료:
1. 호스트 디렉터리 생성 및 권한 설정:
   - /mnt/data/users/martin/jupyter_home 생성 (소유자 martin:martin, 755 권한 부여)
2. 컨테이너 볼륨 구성 최적화:
   - /workspace: /mnt/data/users/martin/jupyter_home (기본 시작 폴더, 깨끗한 전용 프로젝트 작업공간)
   - /workspace/data_root: /mnt/data/users/martin (상위 대용량 데이터셋 및 캐시 공유 폴더)
   - /workspace/home: /home/martin (개인 홈 NVMe 보조 마운트)
3. martin_jupyter 컨테이너 recreate 및 실시간 검증 완료:
   - 주피터랩 시작 시 즉시 jupyter_home 폴더로 진입하여 파일들이 섞이지 않고 깔끔하게 관리됨.
4. Live Lab Guide 및 대시보드 템플릿 최신 경로 반영.
```

### 2026-11-06 07:08:20 — operator-note (Ticket #2)
```text
주피터랩 시작 작업 폴더 변경 및 Live Lab Guide 최신화 완료:
1. JupyterLab 컨테이너 작업 디렉토리(/workspace) 변경:
   - 변경 전: /home/martin (호스트 루트 NVMe 914GB 파티션 마운트)
   - 변경 후: /mnt/data/users/martin (호스트 대용량 8TB HDD 파티션 마운트)
   - 개인 홈 디렉토리 연동: /workspace/home 에 /home/martin 을 보조 마운트하여 설정 파일 및 dotfiles 접근 보장.
   - 효과: 주피터랩 접속 시 즉시 8TB 대용량 스토리지로 진입하여 비디오 데이터셋, HuggingFace 캐시 다운로드 시 루트 디스크(NVMe) 용량 고갈 위험 근본 차단.
   - martin_jupyter 컨테이너 재배포 및 호스트 /mnt/data/users/martin 실시간 동기화 검증 완료.
2. docker_monitor.py 및 docker-compose.yml 템플릿 전원 동기화:
   - student1, student2, student3 및 신규 사용자 프로비저닝 시에도 동일하게 /mnt/data/users/{username} 이 기본 시작 디렉토리로 설정되도록 수정.
3. 연구실 인프라 사용법 & 연구 가이드 (Live Lab Guide) 업데이트:
   - 대시보드 탭(tab-guide) 및 독립 웹 안내문(/guide, docs/LAB_RESEARCH_GUIDE.html) 동시 개편.
   - GPU 서버 Headscale IP(100.64.0.2) 및 비표준 SSH 포트(2322) 명시.
   - 사용자별 주피터랩 배정 현황(martin: 8888, student1: 8889, student2: 8890, student3: 8891) 표 추가.
   - 시작 폴더 구조 및 HuggingFace 캐시 설정 안내문 최신화.
```

### 2026-11-06 06:08:21 — operator-note (Ticket #2)
```text
Headscale Zero-Trust ACL 정책 업데이트 및 Ops-Watch VPN 관리 탭 권한 가시화 완료:
1. Headscale ACL (/etc/headscale/acl.hujson):
   - group:students 허용 대상에 gpu4090:8888-8895 (JupyterLab 포트 범위) 신규 추가 반영 및 docker restart headscale 적용 완료.
   - 학생(student1 외)은 오직 본인 단말 + GPU 서버(100.64.0.2)의 SSH(:2322) 및 주피터랩(:8888-8895)만 접근/노출되며, 관리자 PC(100.64.0.1) 및 타 학생 장비는 100% 완전 격리/비가시 유지.
2. Ops-Watch VPN 관리 탭 (tab-vpn) 상세 목록 고도화:
   - 노드 목록에 '접근 권한 (ACL Scope)' 컬럼 추가 및 권한 범위 실시간 가시화.
   - 'Headscale 제로 트러스트(Zero-Trust) ACL 격리 정책' 전용 가이드 카드 제공 (관리자 vs 학생 권한/노출 비교).
```

### 2026-11-06 05:57:24 — operator-note (Ticket #2)
```text
Headscale VPN 전용 관리 탭 (tab-vpn) 신규 구축 및 세부 인프라 목록 관제 연동 완료:
1. 상단 통계 카드 (KPIs):
   - 총 등록 노드: 6개 (🟢 온라인 4대 / ⚪ 오프라인 2대)
   - 사설망 IP 풀: 100.64.0.0/10 (서버: 100.64.0.2)
   - 네임스페이스: 4명 (martin, student1, student2, student3)
   - 활성 사전인증키: 5개
2. 섹션 1 - 연결된 단말 및 노드 목록 (Nodes Table):
   - ID, 단말명/호스트명, 소유 사용자, IPv4/IPv6, OS 자동판별 뱃지(🍎 macOS, 🐧 Linux, 🪟 Windows), 실시간 연결 상태, 최근 통신(상대 시간), 만료일
   - 원클릭 제어: IP 복사, [🚫 세션 만료(Expire)], [🗑 노드 삭제(Delete)]
3. 섹션 2 - 사전 인증키 발급 및 이력 관리 (Pre-Auth Keys):
   - Key ID, 사용자, 키 마스킹, 다회용/1회용, 상태(유효/사용완료/만료), 만료일시
   - 원클릭 작업: [📋 온보딩 복사], [⏹ 만료]
   - 신규 키 발급 모달: 대상 사용자, 유효기간(24h~1y), Reusable 옵션 설정 및 발급 결과 즉시 복사
4. 섹션 3 - 연구원 온보딩 간편 가이드:
   - macOS / Linux / Windows 플랫폼별 tailscale up 원클릭 접속 스크립트 제공
5. 백엔드 REST API 연동:
   - GET /api/metrics/vpn
   - POST /api/vpn/key/create, /api/vpn/node/expire, /api/vpn/node/delete, /api/vpn/key/expire

```

### 2026-11-06 05:46:10 — operator-note (Ticket #2)
```text
NVIDIA Container Toolkit 설치 및 관리자 전용 주피터랩(martin_jupyter) RTX 4090 GPU 가속 가동 성공:
1. NVIDIA Container Toolkit 정상 설치 완료:
   - nvidia-container-cli 탑재 (/usr/bin/nvidia-container-cli)
   - Docker 데몬 내 NVIDIA GPU 런타임 정상 등록
2. 주피터랩 컨테이너(martin_jupyter) 가동 및 GPU 검증:
   - 컨테이너 상태: Up (:8888)
   - GPU 가속 상태: CUDA Available: True, Device: NVIDIA GeForce RTX 4090, VRAM: 25.25 GB
3. Headscale VPN (100.64.0.2:8888) 및 로컬 LAN (192.168.219.47:8888) 접속 통로 개방

```

### 2026-11-06 05:28:01 — operator-note (Ticket #2)
```text
사용자 관리 목록에서 도커 컨테이너 & 다중 사용자 주피터랩 관리 통합 완료:
1. 사용자별 주피터랩 등록 및 런타임 상태 표기:
   - 등록 컨테이너명 (예: martin_jupyter, student1_jupyter 등)
   - 실행 상태 뱃지 (🟢 실행 중 (:port) / ⏸️ 중지됨 (:port) / ⚪ 등록됨(대기) / ❌ 미등록)
   - 원클릭 접속 링크 ([🔗 열기 ↗], [📋 복사]) 및 컨테이너 생애주기 즉시 제어 ([▶ 기동], [⏹ 정지])
2. 미등록 사용자 원클릭 프로비저닝:
   - [➕ 프로비저닝] 클릭 시 다음 가용 포트 자동 계산 및 docker-compose.yml 연동 등록
3. 사용자 탭 상단 주피터랩 전체 통계 바 추가:
   - 등록 컨테이너 수, 활성 실행 중 수, 할당 포트 범위(8888~8891+) 실시간 표기
4. /api/users/provision-jupyter POST 엔드포인트 연동

```

### 2026-11-06 04:59:07 — operator-note (Ticket #2)
```text
Ops-Watch v2 독립 앱화 및 GPU 컨테이너·NVMe 온도 관제 시스템 구축 완료:
1. macOS 네이티브 앱 번들 생성 (/Applications/Ops-Watch.app 및 데스크톱 바로가기):
   - 크롬 기반 독립 앱 윈도우 모드(--app) 구동 및 전용 AppIcon.icns 탑재
   - 포트 충돌 방지를 위해 기본 포트를 8080에서 23450으로 전면 격리 변경
2. Step 1 & 2 호스트 인프라 자동화 스크립트 배포 (linux-builder):
   - ~/setup_nvidia_docker.sh: NVIDIA Container Toolkit, nvme-cli, nvtop 및 Docker 런타임 설정 자동화
   - ~/jupyter-infra/docker-compose.yml: 사용자별(martin 8888, kim 8889, kumud 8890) JupyterLab 컨테이너 및 DeepSpeed ZeRO-2 ds_config.json 템플릿 구성
3. Step 4 Ops-Watch v2 코어 엔진 및 대시보드 탭 연동 완료:
   - hardware_thermals.py: /sys/class/hwmon 센서 기반 실시간 NVMe 온도(53.9°C, 65°C 주의/75°C 위험) 및 CPU 온도(45.9°C) 모니터링
   - docker_monitor.py: 호스트 9개 컨테이너 실시간 상태 감시 및 원클릭 생애주기 제어(/api/containers/control)
   - 웹 대시보드 상단 NVMe 실시간 온도 뱃지 및 '🐳 도커 & 주피터' 탭 신설
```
