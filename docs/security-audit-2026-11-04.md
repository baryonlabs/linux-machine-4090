# martin-B650M-K (RTX 4090) — 학생 계정·보안 점검 (2026-11-04)

점검 방식: `martin` 계정(비-root) 읽기 전용 점검 + b300에서 공인 IP(211.112.160.46) 외부 포트 스캔.
root 전용 항목(ufw 규칙, 각 사용자 authorized_keys, chage, crontab)은 확인 불가.

## 1. 학생 계정 현황

| 계정 | uid | 그룹 | 마지막 로그인 (출발지) | Headscale 등록 | 비고 |
|---|---|---|---|---|---|
| student5 | 1001 | video, render, users | 2026-05-22 (100.108.20.61) | ❌ | 5개월 미사용 |
| student6 | 1002 | **sudo**, users | 2026-05-15 (100.68.130.16) | ❌ | **sudo 권한**, 6개월 미사용 |
| student3 | 1003 | sglang | 2026-10-22 (100.64.105.88) | ❌ | GPU 그룹 아님 (dev 666이라 사용은 가능) |
| student4 | 1004 | — | 로그인 이력 없음 | ❌ | 미사용 계정 |
| student1 | 1005 | video, render, users | 아직 없음 | ✅ (ACL: 2322만) | 신규 |

- 기존 학생들의 접속 IP는 **구 Tailscale(tailscale.com) tailnet** 대역. 10/25 Headscale 전환 이후 기존 학생 4명은 **현재 네트워크 경로가 없음**(공인 IP 포트 미개방, Headscale 미등록).
- 모든 홈 디렉터리 `750` — 학생 간 상호 열람 불가 ✅
- `/mnt/data` 교수님 폴더 `o-rwx` 적용 완료 ✅ (이전 권한: `~/mnt-data-perms.before.txt`)
- student1 후속 작업(`finish-student1.sh`: `/mnt/data/student1`, 스모크 테스트, ollama keep-alive) **미실행**.

## 2. 외부 노출

- 공인 IP 외부 스캔(b300 → 211.112.160.46, 20개 포트): **열린 포트 없음** ✅
- SSH: 2322, 키 전용, root 로그인 금지, `AllowUsers` 화이트리스트 ✅
- Tailnet: ACL로 학생은 `100.64.0.2:2322`만 ✅
- LAN(192.168.219.0/24)에는 Docker 게시 포트(80/443/5000/9080/9091/9621)와 ollama(11434), RustDesk(21118)가 열려 있음. Docker 게시 포트는 **ufw를 우회**함.

## 3. 발견 사항 (심각도순)

### 🔴 H1. Docker registry(:5000) 무인증 — 로컬 사용자 누구나 이미지 push 가능
- `curl 127.0.0.1:5000/v2/_catalog` → `agentapi-claude, agentapi-opencode, dashboard, mcp-gateway, mcp-google-calendar, slack-gif-creator`
- 학생이 같은 태그로 악성 이미지를 push하면 martin이 pull/run할 때 실행 → docker 그룹 = 사실상 root.
- 조치: registry에 htpasswd 인증 추가, 또는 사용하지 않으면 중지. (127.0.0.1 바인딩만으로는 로컬 학생 차단 불가)

### 🔴 H2. ngrok 에이전트 API(127.0.0.1:4040) — 로컬 사용자 누구나 조작 가능
- 로컬 학생이 `DELETE /api/tunnels/command_line` → Headscale 공개 URL 중단(전체 tailnet 신규 접속 불가),
  `POST /api/tunnels` → 임의 로컬 포트(registry, ollama 등)를 교수님 ngrok 계정으로 인터넷 공개 가능. 요청 인스펙터로 트래픽 열람도 가능.
- 조치: ngrok 설정에 `web_addr: false`(또는 인스펙터 비활성) 후 재시작.

### 🔴 H3. SSH 포트포워딩 허용 — Tailscale ACL 우회
- `AllowTcpForwarding` 기본값(yes). 학생이 `ssh -L`/`-D`로 4090을 경유해 LAN(NAS 192.168.219.50:2294 등), 교수님 다른 tailnet 노드(b300·Mac mini), 로컬 서비스(registry·ollama·ngrok API)에 접근 가능 → ACL로 2322만 허용한 의미가 사라짐.
- 조치(`/etc/ssh/sshd_config.d/99-user-manager-hardening.conf` 끝에):
  ```
  Match User *,!martin
      AllowTcpForwarding local
      PermitOpen localhost:* 127.0.0.1:*
      X11Forwarding no
      PermitTunnel no
      GatewayPorts no
  ```
  (머신 자신의 localhost로만 포워딩 허용 → VS Code Remote-SSH·Jupyter는 동작, LAN/tailnet 우회는 차단. 로컬 서비스는 셸로도 닿으므로 H1·H2 조치가 별도로 필요)

### 🟠 M1. student6 계정에 sudo 권한
- 6개월 미사용 계정이 root 권한 보유. 의도된 것이 아니라면 `sudo gpasswd -d student6 sudo`, 장기 미사용이면 `usermod -L -e 1`로 잠금.

### 🟠 M2. martin 계정 NOPASSWD sudo: `/usr/bin/install`, `/bin/mv` (`/etc/sudoers.d/oah-agent`)
- `sudo install`/`mv`로 `/etc/sudoers.d` 등 임의 파일 교체 가능 → **martin 탈취 = 비밀번호 없이 root**.
- 조치: oah-agent에 필요한 정확한 경로/인자로 제한하거나 래퍼 스크립트 하나만 허용.

### 🟠 M3. Ollama(:11434) 무인증, 0.0.0.0 바인딩
- 로컬 학생/LAN이 모델 실행·pull·**삭제**(`/api/delete`) 가능, VRAM 점유로 학습 방해.
- 조치: `OLLAMA_HOST=127.0.0.1`(LAN 차단), keep-alive 0(`finish-student1.sh`), 필요 시 리버스 프록시 인증.

### 🟠 M4. 보안 업데이트 미적용 + 재부팅 필요
- `/var/run/reboot-required` 존재, NVIDIA 590 드라이버 보안 업데이트 20건 대기(unattended-upgrades는 활성).
- 조치: 학생 작업 없는 시간에 `sudo apt upgrade && sudo reboot`.

### 🟡 L1. 장기 미사용 계정 (student4 로그인 이력 없음, student5·student6 5~6개월)
- 조치: 사용 여부 확인 후 `usermod -L -e 1 <user>` 잠금 또는 `AllowUsers`에서 제거. 계정마다 만료일(`usermod -e`) 설정 권장.

### 🟡 L2. 로컬 정보 노출
- netdata(127.0.0.1:19999) — 모든 사용자 프로세스/명령줄 열람 가능.
- `X11Forwarding yes` — 불필요하면 `no`.
- `/tmp/RustDesk` 777(sticky 없음), RustDesk가 LAN에 열려 있음.

### 🟢 확인 결과 양호
- LightRAG(:9621) — `LIGHTRAG_API_KEY` 설정됨, 무인증 요청은 `API Key required` ✅
- Headscale 디버그(:9091) — `debug access denied` ✅
- SOCKS 프록시(:1080) — `ALLOWED_IPS=100.64.0.5`(b300)만 허용, 로컬 요청 실패 ✅
- Postgres — 127.0.0.1 바인딩 + 비밀번호 ✅
- Headscale `data/` 777·`db.sqlite` 644이나 상위 `/home/martin` 750이라 학생 접근 불가 (정리 권장)
- uid 0은 root뿐, 비정상 SUID 없음(chrome-sandbox, pppd는 표준), `/etc`·`/usr` world-writable 파일 없음
- 이전에 world-readable이던 HF 토큰·`GEMINI_API_KEY`·`OPENAI_API_KEY` 파일 → 600 적용 완료 (**키 재발급 권장**)

## 4. 조치 현황 (2026-11-04)

| 항목 | 조치 | 상태 |
|---|---|---|
| H1 registry | `127.0.0.1:5000`로 재바인딩(LAN 차단, 볼륨 유지) + 학생 egress 방화벽에서 5000 차단 | ✅ 바인딩 완료 / ⏳ 방화벽 |
| H2 ngrok API | `ngrok.yml`에 `web_addr: false` + systemd 서비스화(재부팅 생존, `--url` 고정) | ✅ 설정 / ⏳ 재시작 |
| H3 포워딩·피벗 | `students` 그룹 egress 방화벽(LAN·tailnet·docker망·관리 포트 차단) + sshd `Match Group students` | ⏳ scripts/hardening/harden.sh |
| M1 student6 sudo | `gpasswd -d` | ⏳ scripts/hardening/harden.sh |
| M2 NOPASSWD install/mv | `/usr/local/bin/ollama`만 남김 | ⏳ scripts/hardening/harden.sh |
| M3 ollama | keep-alive 0 + ufw LAN 차단 + 학생 차단 | ⏳ scripts/hardening/harden.sh |
| M4 업데이트·재부팅 | `scripts/hardening/harden.sh --reboot` (NVIDIA 라이브러리 불일치 방지 위해 재부팅과 묶음) | ⏳ 사용자 시점 |
| L1 미사용 계정 | student5·student6·student4 잠금(`usermod -L -e 1`) | ⏳ scripts/hardening/harden.sh |
| L2 기타 | Headscale `9080/9091` → 127.0.0.1, `data/` 755, `/tmp/RustDesk` sticky, 학생 X11 off | ✅ 일부 / ⏳ |
| 비밀정보 | HF 토큰·.env·secret.yaml 600 | ✅ (키 재발급은 사용자) |

백업: `~/headscale/docker-compose.yml.bak.*`, `~/.config/ngrok/ngrok.yml.bak.*`, `/root/*.bak.*`(sshd, sudoers)

## 5. CVE-2026-98432 (커널 IPv4 TCP UAF, CVSS 9.8) — 2026-11-04

- 영향: 실행 커널 6.8.0-136, 설치 커널 6.8.0-147 모두 취약. Ubuntu noble `linux` 수정판 6.8.0-149 미배포(`pro fix`: "A fix is coming soon").
- 노출: 인터넷 포트 없음. LAN·tailnet 리스너, **비-root 로컬 사용자도 `setsockopt(IP_OPTIONS)`로 IP 옵션 SYN 전송 가능**(martin으로 확인, 완화 전 CONNECTED).
- 완화(적용 ✅): `scripts/hardening/mitigate-cve-2026-98432.sh` — nft `table ip cve_2026_98432` prerouting/raw에서 `ip hdrlength != 5` TCP drop, systemd `cve-2026-98432.service`로 영속. 검증: loopback·tailnet IP·LAN IP·MacBook→tailnet 모두 IP-옵션 SYN BLOCKED, 일반 SYN OK.
- 후속: 6.8.0-149+ 설치·재부팅 후 `sudo systemctl disable --now cve-2026-98432 && sudo rm /etc/nftables.d/cve-2026-98432.nft`. Livepatch(`sudo pro attach`) 권장.

## 6. 최종 상태 재점검 (2026-11-04 01:25 KST, 조치 완료 후)

점검 근거: `martin`(비-root) 직접 측정 + b300 외부 스캔. root 전용 항목(iptables·ufw 규칙, 계정 잠금, sudoers 내용)은 관리자가 실행한 `scripts/hardening/harden.sh` / `fix-control-plane.sh`(journal `fixcp`) / `scripts/hardening/mitigate-cve-2026-98432.sh` 출력으로 확인.

### 6.1 발견 사항별 최종 판정

| 항목 | 최종 상태 | 근거 | 판정 |
|---|---|---|---|
| H1 registry 무인증 | `127.0.0.1:5000`만 리슨, 학생 egress에서 5000 차단 | `docker ps`, fixcp verify `blocked 127.0.0.1:5000` | ✅ 해소 (로컬 martin 계정은 여전히 무인증 push 가능 — 관리자 본인) |
| H2 ngrok 에이전트 API | `127.0.0.1:4040` 응답 없음(000), systemd `ngrok-headscale` active/enabled, 고정 도메인 `headscale-tunnel.example` | `curl :4040`, `/health` 200 | ✅ 해소 |
| H3 포워딩·셸 피벗 | sshd `Match Group students`(local 포워딩·localhost만, X11·터널 off), `student-egress` active/enabled | sshd 설정, fixcp verify: 5000/11434/19999/NAS 2294/b300 22/Mac mini 22 전부 `blocked`, pypi 200 | ✅ 해소 |
| M1 student6 sudo | `sudo` 그룹 = martin만 | `getent group sudo` | ✅ 해소 |
| M2 NOPASSWD install/mv | `oah-agent` → `/usr/local/bin/ollama`만 (파일 440 root) | scripts/hardening/harden.sh 출력 `parsed OK` | ✅ 해소 |
| M3 ollama | `OLLAMA_KEEP_ALIVE=0`, ufw `11434 on enp6s0 DENY`, 학생 차단 | `systemctl show`, scripts/hardening/harden.sh ufw 출력 | ✅ 해소 (바인딩은 0.0.0.0 유지 — docker 브리지용) |
| M4 업데이트·재부팅 | **reboot-required, 보안 업데이트 29건 대기** | `/var/run/reboot-required`, `apt list` | ⏳ 미해소 — `sudo bash ~/harden.sh --reboot` 필요 |
| L1 미사용 계정 | student5·student6·student4 잠금(`-L -e 1`), student1 만료 2027-01-04 | scripts/hardening/harden.sh `locked …`, fixcp `Account expires: Jan 04, 2027` | ✅ 해소 |
| L2 기타 | `/tmp/RustDesk` 1777, Headscale `data/` 755, 9080/9091 → 127.0.0.1, 학생 X11 off | `stat`, `docker ps` | ✅ 해소 (netdata는 학생 egress로 차단) |
| 비밀정보 노출 | HF token·.env·secret.yaml 600, 재스캔 결과 world-readable 비밀 파일 0건 | `stat`, `find -perm -0004` | ✅ 해소 / ⏳ **HF·Gemini 키 재발급(사용자)** |
| CVE-2026-98432 | nft 완화 active/enabled, IP-옵션 SYN 차단(학생: 적용 전 REACHES → 후 BLOCKED) | mitigate 스크립트 1회차 출력, martin·tailnet 재검증 | 🟠 완화됨 / ❌ 커널 미수정(`pro fix`: not resolved) |

### 6.2 현재 노출 면

- 인터넷(공인 IP 211.112.160.46): b300 재스캔 13개 포트 **모두 닫힘** ✅
- Tailnet: Headscale ACL — admin(martin)=전체, students(student1)=`gpu4090:2322`만. 노드 5개 IP 유지(NucBox만 offline, 미전환).
- LAN에 남은 0.0.0.0 리스너: 2322(SSH 키전용), 80/443(Caddy, 미사용), 9621(LightRAG, API 키), 7483(martin node 서버), 487(root 프로세스, 미식별), RustDesk 21118 — 학생은 egress로 LAN 접근 불가.
- 디렉터리: `/mnt/data/users` 711, `users/admin2`·`users/student1` 700, 홈 750. 교수님 데이터는 `users/admin2`로 이동(구 경로는 심볼릭 링크).

### 6.3 남은 위험 / 할 일

1. **M4 재부팅 + 보안 업데이트** — GPU 작업 없는 시간에 `sudo bash ~/harden.sh --reboot`. (재부팅 생존 확인 대상: `ngrok-headscale`, `student-egress`, `cve-2026-98432`, docker 컨테이너 restart 정책)
2. **CVE-2026-98432 커널 수정판(≥ 6.8.0-149)** 대기 — 배포 후 업데이트·재부팅, 완화 규칙 해제. `sudo pro attach`로 Livepatch 활성화 권장(현재 미연결).
3. **키 재발급** — HF 토큰, `GEMINI_API_KEY` (과거 world-readable).
4. **martin의 docker 그룹 = 사실상 root** — martin 계정 탈취 시 비밀번호 없이 root. rootless docker 전환 검토 또는 위험 수용.
5. 미식별 리스너 `0.0.0.0:487`(root) 확인, 미사용이면 Caddy(80/443) 중지.
6. NucBox Headscale 재연결, 기존 학생(student3 등) 계속 사용 시 Headscale 등록 + ACL `group:students` 추가.

## 7. 재부팅 후 점검 (2026-11-04 02:44 부팅, 커널 6.8.0-147)

- 보안 업데이트 적용 + 재부팅 완료(`apt-get upgrade && reboot`). `reboot-required` 해제. M4 → ✅ (NVIDIA 590 보안 패키지 20건만 남음, 아래)
- 서비스 19개 전부 active(ssh, tailscaled, docker, ngrok-headscale, student-egress, cve-2026-98432, labops-fw, ufw, auditd, acct, falco-modern-bpf, falcosidekick, ollama, labops 타이머·소켓), failed 유닛 0(thunderbird snap 잔재 제외)
- 컨테이너 6개 자동 기동(registry, headscale, kb-lightrag, kb-postgres(healthy), b300-socks, headscale-caddy). `glm-cloudflared`는 재시작 루프(25,833회)여서 restart=no + 중지.
- Headscale `/health` 200, 노드 4/5 online(NucBox 미전환). GPU 정상(590.48.01).
- CVE-2026-98432: nft 완화 재부팅 후에도 BLOCKED, 커널 6.8.0-147도 미수정(`pro fix`: not resolved).
- 노출: Falco health 127.0.0.1:8765, ngrok API 꺼짐 유지.
- 남은 일: NVIDIA 590 보안 업데이트 20건(`apt upgrade`에서 보류됨 — 드라이버 패키지 갱신은 별도 점검 창에서 `sudo apt-get install --only-upgrade nvidia-driver-590-open ...` 후 즉시 재부팅), CVE 수정 커널(≥6.8.0-149) 대기, Livepatch, 키 재발급, NucBox, 0.0.0.0:487 확인.
