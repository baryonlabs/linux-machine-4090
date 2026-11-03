# labops — 공유 GPU 서버(RTX 4090) 운영 툴킷

이 서버(martin-B650M-K, Ubuntu 24.04) 한 대를 위한 작은 운영 도구 모음입니다. 사용자 수명주기, 활동 로그,
GPU 사용량 집계, 이상 탐지, 일간/주간 보고, 학생 권한 요청 큐를 다룹니다. 검증된 오픈소스
(auditd, acct, Falco, falcosidekick, Lynis)를 쓰고, 그 사이를 stdlib Python과 bash로 잇습니다. 서버에 pip 의존성은 없습니다.

```
설치:    sudo bash ~/labops/install.sh            (멱등, 끝에 PASS/FAIL 체크리스트 출력)
제거:    sudo bash ~/labops/uninstall.sh [--purge] [--purge-packages]
```

## 1. 구조

```
            ┌──────────── /etc/labops/users.yaml (사용자 레지스트리, 기준 데이터)
 labctl ────┤ sync/add/remove/extend → 계정·그룹·chage·AllowUsers(sshd -t)·/mnt/data/users/<u>
 (sudo)     │                        → Headscale 사용자/pre-auth key/ACL group:students (policy check 후 재시작)
            └ 감사/Falco 대상 uid 목록 재생성 (51-labops-students.rules, labops_00_students.yaml)

 커널 ──┬─ auditd (execve·권한상승·설정파일·shadow·IP_OPTIONS·ptrace·모듈) → /var/log/audit/audit.log
        ├─ acct (프로세스 회계) → /var/log/account/pacct
        └─ Falco modern_ebpf (커널 모듈/DKMS 없음) → journald + falcosidekick(127.0.0.1:2801, root만) → Discord(WARNING+)

 타이머 ─┬─ 1분   labops-gpu-collect   nvidia-smi PID→사용자 → /var/lib/labops/gpu.db
        ├─ 5분   labops-audit-alert   중요 auditd 키(CVE-2026-98432 등) → Discord
        ├─ 08:00 labops-daily         일간 요약 → Discord
        ├─ 월 09:00 labops-weekly-lynis  하드닝 지수 + 변화량 → Discord
        └─ 10분  labops-executor      권한 요청 만료/알림 재시도

 학생 labreq ─ /run/labops/req.sock ─ labops-reqd(User=labops, SO_PEERCRED) → /var/lib/labops/requests/
 martin labctl approve ─ /var/lib/labops/decisions/ (martin만 쓰기) → labops-executor(root, 고정 카탈로그) → apt-get
```

파일 위치: 코드 `/opt/labops`, 명령 `/usr/local/sbin/labctl`, `/usr/local/bin/labreq`, 설정 `/etc/labops/`
(`labops.conf`, `users.yaml`, `discord-webhook.url` root 600, `falcosidekick.env` root 600).

## 2. 사용자 추가/제거

레지스트리 `/etc/labops/users.yaml`을 고친 뒤 적용합니다. 모든 명령은 `--dry-run`을 지원하고 몇 번을 다시 실행해도 결과가 같습니다(멱등).

```bash
sudoedit /etc/labops/users.yaml                 # 항목 추가: name, full_name, role, state, expires, headscale, ssh_pubkey, notes
sudo labctl --dry-run add newstudent           # 계획만 출력
sudo labctl add newstudent                     # 계정, 그룹(video,render,users,students), 키, 만료일, AllowUsers,
                                               # /mnt/data/users/<u>(700)+~/data, Headscale 사용자+1회용 키(60일)+ACL
sudo labctl add newstudent --new-key           # Headscale 키 재발급(키는 생성할 때만 보임)
sudo labctl add newstudent --build-envs ~/build-envs.sh   # 선택: 학생 계정으로 연구 환경 빌드
sudo labctl extend kimsunghyun 2027-03-04      # 만료 연장(레지스트리도 갱신)
sudo labctl remove kimsunghyun                 # 오프보딩: 잠금+만료, AllowUsers 제거, 세션 종료,
                                               # Headscale 노드/키 만료 + ACL 제거, 데이터는 _archive/<u>-<날짜>로 이동(삭제 없음)
sudo labctl sync                               # 레지스트리 전체 적용 (locked/removed 상태는 잠그고 AllowUsers에서 뺌)
labctl list                                    # 상태·만료·최근 로그인·Headscale 온라인 (martin으로 실행 가능)
labctl report --days 7                         # 사용자별 GPU 시간, 최대 VRAM, 동시 작업 수, 24시간 넘은 작업
```

- sudo 없이 martin으로 실행하면 OS 단계는 `[needs sudo]`로 건너뛰고, Headscale 단계(docker)만 수행합니다.
- sshd 변경 전에 `/var/backups/labops/`에 백업하고 `sshd -t`를 통과할 때만 reload합니다(실패하면 자동 복원).
  Headscale ACL은 `headscale policy check`를 통과할 때만 교체하고 `docker restart headscale`로 반영합니다.
- admin 계정(martin)과 sudo를 실행한 본인은 잠그거나 제거하지 않습니다.
- **주의:** 현재 레지스트리 기준으로 `sudo labctl sync`를 실행하면 잠긴 3개 계정(ts01088978343, lying3178, jiayiqu12)이
  AllowUsers에서 빠지고, imshen19가 video/render/users 그룹에 추가되며 `/mnt/data/users/imshen19`가 생깁니다.
  설치 스크립트는 sync를 자동 실행하지 않고 계획만 보여줍니다.

## 3. 무엇을 기록하나 / 기록하지 않나

| 항목 | 도구 | 위치 | 보존 |
|---|---|---|---|
| 학생이 실행한 모든 명령(execve, 인자 포함) | auditd `student_exec` (학생별 loginuid 규칙) | /var/log/audit/audit.log | 50MB×10 회전 (약 500MB) |
| sudo/su/pkexec 시도, setuid/setgid 실행 | auditd `priv_esc`, `setuid_exec` | 〃 | 〃 |
| passwd/shadow/group/sudoers/sshd/audit/labops 설정 변경 | auditd `identity`,`sudoers`,`sshd_config`,… | 〃 | 〃 |
| 로그인 사용자의 /etc/shadow 읽기, ptrace, 커널 모듈 로드 | auditd | 〃 | 〃 |
| `setsockopt(IPPROTO_IP, IP_OPTIONS)` (CVE-2026-98432) — 모든 사용자 | auditd `cve_2026_98432` | 〃 + 5분 내 Discord | 〃 |
| 모든 프로세스의 종료 기록(명령 이름, CPU 시간) | acct | /var/log/account/pacct (`lastcomm`, `sa`) | Ubuntu 기본 일일 회전 |
| 로그인/로그아웃, SSH 실패 | sshd/journald, wtmp | journalctl, `last` | 시스템 기본값 |
| 이상 행위(아래 Falco 규칙) | Falco | journalctl -u falco-modern-bpf, Discord | journald 기본값 |
| GPU 사용(1분마다 PID, 사용자, 명령 200자, VRAM) | labops-gpu-collect | /var/lib/labops/gpu.db (root:adm 640) | 400일 |
| 권한 요청과 처리 결과 | labops-reqd/executor | /var/lib/labops/requests, /var/log/labops/requests.log | 52주 회전 |
| Lynis 보고서 | lynis | /var/lib/labops/lynis/ | 26주 |

**기록하지 않는 것:** 키 입력, TTY 내용, 화면 출력, 파일 내용, 네트워크 페이로드는 기록하지 않습니다(pam_tty_audit 미사용).
단, execve 인자는 남기 때문에 학생이 명령줄에 비밀번호나 토큰을 직접 쓰면 그 값이 audit 로그에 남습니다. 학생 안내문에 이 점을 적었습니다.
admin(martin)의 명령은 execve 규칙 대상이 아닙니다(권한 상승, 설정 변경 같은 공통 규칙에만 해당).

**execve 대상 방식:** auditd의 `-F gid`는 프로세스의 *주* 그룹만 비교하므로 보조 그룹인 `students`를 걸러낼 수 없습니다.
그래서 `labctl sync`가 `students` 그룹원과 레지스트리 학생의 uid마다 `-F auid=<uid>` 규칙을 만듭니다(51-labops-students.rules).
auid(loginuid)는 로그인할 때 정해지고 sudo/su/setuid를 거쳐도 바뀌지 않으며, 그 세션의 cron, tmux, nohup에도 그대로 이어집니다.
학생을 추가하거나 제거하면 sync가 규칙을 다시 만들고 `augenrules --load`로 반영합니다. 규칙은 immutable(`-e 2`)로 두지 않았습니다. 재부팅 없이 갱신하기 위해서입니다.

## 4. 알림 읽는 법 (Discord)

- **Falco (falcosidekick):** WARNING 이상만 전송됩니다. 규칙 이름이 `LabOps …`이면 학생 대상 커스텀 규칙입니다.
  - `LabOps student session process running as root` (CRITICAL): 학생 세션의 root 프로세스. 권한 상승 성공 가능성이 있으니 즉시 확인합니다.
  - `… runs crypto-miner` / `… mining pool port` (CRITICAL): 채굴 의심.
  - `… connects to internal network`: LAN/tailnet 접근 시도(egress 방화벽이 차단하며, 시도 자체가 신호입니다).
  - `… reads sensitive auth file`, `… probes other users' files`, `… writes to system directories`, `… uses privilege tool`,
    `… creates raw or packet socket`, `… launches container tooling`: 정찰 또는 권한 상승 시도.
  - 기본 Falco 규칙(stable 25개)은 martin 세션과 패키지 관리자(apt, dpkg 등)를 예외로 둡니다.
  - 세부 내용: `journalctl -u falco-modern-bpf --since -1h -o cat | jq .` (해당 시각 전후)
- **labops audit alert (5분):** `cve_2026_98432`, `modules`, `identity`, `sudoers`, `sshd_config`, `shadow_read` 등 키별 건수와 예시를 보여줍니다.
  자세한 내용: `sudo ausearch -i -k <키> -ts today`. labctl로 계정이나 sshd를 바꾸면 `identity`/`sshd_config` 알림이 뜨는 것이 정상입니다.
- **labops daily (08:00):** 로그인, SSH/sudo 실패, 학생별 상위 명령, GPU 시간, Falco/감사 키 건수, 대기 중인 권한 요청,
  디스크 사용량, 보안 업데이트와 재부팅 필요 여부, CVE-2026-98432 상태를 보여줍니다. 2000자를 넘으면 여러 메시지로 나눠 보냅니다.
- **labops weekly lynis (월 09:00):** 하드닝 지수와 지난주 대비 변화, 새 경고, 해결된 제안을 보여줍니다.
- **labops-requests:** 새 권한 요청, 처리 결과(✅ 완료 / ❌ 실패 / 🚫 거절 / 📝 확인).
- 사용자가 입력한 텍스트는 `allowed_mentions: none`으로 보내므로 @everyone 같은 멘션이 동작하지 않습니다.

## 5. 학생 권한 요청 큐 (labreq)

학생에게는 sudo를 주지 않습니다. 학생이 요청하면 관리자가 검토하고, root 실행기는 **고정된 카탈로그**에 있는 작업만 수행합니다.

```
학생:   labreq install ffmpeg sox --reason "audio preprocessing"
        labreq other "port 8888 forwarding for jupyter"      # 자동 실행되지 않으며 관리자에게만 알립니다
        labreq status [id] | labreq cancel <id>
관리자(martin, sudo 불필요):
        labctl requests [--history] [id]      # 대기 목록 + 검증 결과(apt-cache policy / apt-get -s)
        labctl approve <id>                   # 검증을 통과해야만 승인 파일이 기록됩니다
        labctl reject <id> --reason "..."
```

- **신원:** 요청자는 유닉스 소켓의 `SO_PEERCRED`(커널이 제공하는 uid)로만 판별합니다. 요청 본문에는 사용자 이름이 들어가지 않습니다.
  공용 쓰기 스풀 디렉터리(1733) 방식 대신 소켓 방식을 고른 이유: 학생이 쓸 수 있는 디렉터리가 전혀 없어서
  심볼릭/하드링크 공격, 디스크 채우기, 다른 사람의 요청 엿보기가 원천적으로 불가능합니다. 처리기는 연결 하나마다 짧게 실행되고(Accept=yes),
  권한 없는 `labops` 사용자로 돌며 네트워크가 없습니다(PrivateNetwork). `students` 그룹원만 요청할 수 있고, 1인당 대기 요청은 최대 5개, 7일이 지나면 만료됩니다.
- **승인:** martin이 `/var/lib/labops/decisions/<id>.json`(martin 전용 700)에 *요청 id와 요청 내용의 sha256만* 씁니다.
  실행기는 작업 내용을 승인 파일이 아니라 `labops`가 쓴 요청 파일에서 가져오며, 파일 소유자, 해시, 요청자의 학생 여부를 다시 확인합니다.
- **카탈로그:** `apt-install`만 있습니다. 패키지 이름은 `^[a-z0-9][a-z0-9+.-]{1,62}$`, 최대 20개이고, 후보 버전은 Ubuntu 공식 아카이브
  (mirror.kakao.com, archive/security.ubuntu.com의 noble, -updates, -security, -backports)에서만 받습니다. PPA나 서드파티(docker, doppler 등)는 거부합니다.
  이미 설치된 패키지도 거부합니다. 거부 목록: linux-*, nvidia-*, libnvidia-*, cuda-*, *-dkms, openssh-*, sudo, docker*, tailscale*, systemd*, ufw, iptables*, nftables,
  auditd, falco*, libpam-*, apt/dpkg, grub* 등(`lib/labops_apt.py`). `apt-get -s`로 미리 돌려 봐서 **제거나 업그레이드가 하나라도 생기거나**,
  의존성에 거부 대상 또는 비 Ubuntu 출처 패키지가 끼면 거부합니다. 실행 직전에 다시 검증한 뒤 `apt-get install -y --no-install-recommends --no-upgrade`로 설치합니다.
- **기록:** journald(`journalctl -u labops-executor`), `/var/log/labops/requests.log`, auditd(`auditctl -m` 메시지, 키 `labops_decision`/`labops_executor`),
  Discord, 요청 파일(학생은 `labreq status`로 결과와 출력 끝부분을 확인).
- martin이 승인할 수 있다고 해서 임의의 root 권한이 생기지는 않습니다. martin이 할 수 있는 최대치는 "검증을 통과한 Ubuntu 패키지 설치"입니다.
  (참고: martin은 docker 그룹이라 원래 root와 같은 수준입니다. 감사 보고서 6.3-4 참고.)

## 6. 자원 사용 예상치

- Falco modern_ebpf: RSS 약 50~150MB, CPU 1~3%(syscall 양에 따라 다름). 설치 스크립트가 시작 25초 뒤 실측값을 체크리스트에 출력합니다.
- falcosidekick: RSS 약 20~30MB. auditd: 학생이 pip/conda 빌드를 돌리면 execve가 몰리므로 버퍼를 16384로 잡았고, 로그는 최대 500MB입니다.
- GPU 수집기: 1분마다 0.2초 미만, DB는 대략 프로세스 1개당 하루 1,440행, 1년에 수십 MB입니다.
- 일간 보고서의 `du`는 /mnt/data/users 전체를 읽습니다(nice와 idle I/O로 실행, 사용자당 최대 15분).

## 7. 운영 메모

- 규칙 변경: 저장소의 `labops/falco/labops_rules.yaml`을 고친 뒤 install.sh를 다시 실행합니다(검증 후 반영). Falco 규칙 자동 업데이트(falcoctl)는
  꺼 두었습니다. 기본 규칙이 바뀌면 override가 깨질 수 있어서이고, 규칙 업데이트는 `apt` 업그레이드와 함께 합니다.
- Falco는 `setsockopt` level IPPROTO_IP를 UNKNOWN으로만 표시해서 IP_OPTIONS를 정확히 구분하지 못합니다. 그래서 auditd가 담당합니다.
- `sudo labctl audit-rules`: setuid 바이너리 목록을 다시 스캔합니다(패키지를 설치한 뒤).
- 테스트: `python3 -m unittest discover -s labops/tests -v`

## 8. 학생 안내문 (사용 정책 메일용, English)

> **Monitoring notice.** For security and fair sharing of this GPU server, we log your logins (time and source address),
> the commands you execute (program name and arguments, recorded by the Linux audit system), process accounting
> records, and your GPU usage (process, memory and duration). Automated detection flags activity such as probing
> other users' files, attempts to gain root, cryptocurrency mining, and connections into the internal network.
> We do **not** record keystrokes, terminal contents, file contents or network payloads. Do not put passwords or
> tokens directly on the command line, because command arguments are logged. Logs are kept for a limited time
> (typically a few weeks to a year) and are only accessed by the lab administrator.
> Need a system package? Run `labreq install <pkg> --reason "..."`; the admin reviews it.
