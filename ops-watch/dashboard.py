#!/usr/bin/env python3
"""OPS-WATCH Web Dashboard & Control Console with Full Observability.

Features:
- Approval Tickets & AI Triage (Antigravity LLM + Auto-Ontology)
- User-by-user Usage Records (labops users, GPU access, Headscale state)
- Unauthorized Access Attempts & Falco/Auditd Anomalies
- System CVE Issues & Hardening Verification (CVE-2026-98432, H1~H3, M1~M4)
- GPU Telemetry & Allocation (NVIDIA RTX 4090 24GB, per-user compute)
- Agent Historical Memory & Apache Ossie / NVIDIA Auto-Ontology Explorer
- Durable Worklog Management
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict

import analysis_llm
import health_check
import ops_watch
import system_metrics
from auto_ontology_bridge import AutoOntologyBridge

PORT = int(os.environ.get("OPS_WATCH_PORT", 23450))
# Bind to loopback by default: this console can start/stop containers, create VPN
# keys and add users, and it exposes Jupyter tokens. Override only on a trusted host:
#   OPS_WATCH_BIND=0.0.0.0
BIND = os.environ.get("OPS_WATCH_BIND", "127.0.0.1")
BASE_DIR = pathlib.Path(__file__).parent.resolve()

# Automatic journal scan (was manual-only before 2026-11-11).
SCAN_INTERVAL = int(os.environ.get("OPS_WATCH_SCAN_INTERVAL", "300"))
_last_scan: Dict[str, Any] = {"ts": 0, "made": 0, "error": None}

HTML_PAGE = """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OPS-WATCH // Security & GPU Operator Console</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #151d2e;
      --card-border: #222f47;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #10b981;
      --accent-hover: #059669;
      --danger: #ef4444;
      --warning: #f59e0b;
      --info: #38bdf8;
      --purple: #a855f7;
      --code-bg: #080c14;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; padding: 24px; }
    header { display: flex; justify-content: space-between; align-items: center; padding-bottom: 20px; border-bottom: 1px solid var(--card-border); margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
    .brand { display: flex; align-items: center; gap: 14px; }
    .brand-logo { width: 40px; height: 40px; background: linear-gradient(135deg, #10b981, #06b6d4); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 18px; color: white; box-shadow: 0 4px 12px rgba(16,185,129,0.3); }
    .brand h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }
    .brand span { font-size: 13px; color: var(--text-muted); display: block; }
    .status-bar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    .badge { font-size: 11px; font-weight: 600; padding: 4px 10px; border-radius: 9999px; display: inline-flex; align-items: center; gap: 6px; }
    .badge-online { background: #064e3b; color: #34d399; border: 1px solid #059669; }
    .badge-local { background: #3b2c04; color: #fbbf24; border: 1px solid #d97706; }
    .badge-danger { background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }
    .badge-warning { background: #451a03; color: #fcd34d; border: 1px solid #f59e0b; }
    .badge-model { background: #1e1b4b; color: #a5b4fc; border: 1px solid #4f46e5; }
    .badge-gpu { background: #143528; color: #7ee787; border: 1px solid #238636; }
    .btn { background: var(--accent); color: white; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 600; font-size: 13px; cursor: pointer; transition: all 0.2s; display: inline-flex; align-items: center; gap: 6px; }
    .btn:hover { background: var(--accent-hover); transform: translateY(-1px); }
    .btn-secondary { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
    .btn-secondary:hover { background: #334155; }
    .btn-sm { padding: 5px 10px; font-size: 12px; }
    .tabs { display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; overflow-x: auto; }
    .tab-btn { background: transparent; border: none; color: var(--text-muted); padding: 8px 14px; font-weight: 600; font-size: 13px; cursor: pointer; border-radius: 6px; transition: all 0.2s; white-space: nowrap; }
    .tab-btn.active { background: var(--card-bg); color: var(--text); border: 1px solid var(--card-border); }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px; padding: 20px; margin-bottom: 16px; }
    .ticket-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
    .ticket-title { font-size: 16px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
    .ticket-category { background: #451a03; color: #f97316; padding: 2px 8px; border-radius: 4px; font-size: 11px; text-transform: uppercase; font-weight: bold; }
    .ticket-category.credential { background: #450a0a; color: #f87171; }
    .ticket-category.privilege { background: #3b0764; color: #c084fc; }
    .ticket-category.network { background: #082f49; color: #38bdf8; }
    .evidence-box { background: var(--code-bg); border: 1px solid #1e293b; border-radius: 6px; padding: 12px; font-family: monospace; font-size: 12px; color: #cbd5e1; margin-bottom: 14px; word-break: break-all; }
    .triage-box { background: #0b1329; border-left: 4px solid var(--info); border-radius: 4px; padding: 14px; margin-bottom: 14px; }
    .triage-box.critical { border-left-color: var(--danger); background: #1c1017; }
    .triage-box.warning { border-left-color: var(--warning); background: #1c170d; }
    .triage-meta { display: flex; gap: 10px; align-items: center; margin-bottom: 8px; font-size: 12px; font-weight: bold; }
    .triage-summary { font-size: 13px; line-height: 1.5; color: #e2e8f0; margin-bottom: 8px; }
    .triage-precedent { font-size: 12px; color: #94a3b8; background: #080c14; padding: 6px 10px; border-radius: 4px; border: 1px dashed #334155; }
    .card-actions { display: flex; gap: 8px; justify-content: flex-end; align-items: center; margin-top: 14px; border-top: 1px solid var(--card-border); padding-top: 14px; }
    
    /* Grid layout for Users & GPU */
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 16px; margin-bottom: 20px; }
    .grid-3 { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 20px; }
    
    .stat-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 10px; padding: 18px; }
    .stat-val { font-size: 26px; font-weight: 800; color: #38bdf8; margin: 6px 0; }
    .stat-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }

    /* Progress bar */
    .bar-wrap { background: #080c14; border-radius: 6px; height: 10px; overflow: hidden; margin: 8px 0; }
    .bar-fill { background: linear-gradient(90deg, #10b981, #06b6d4); height: 100%; border-radius: 6px; transition: width 0.3s; }
    .bar-fill.high { background: linear-gradient(90deg, #f59e0b, #ef4444); }

    /* Table styles */
    .data-table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
    .data-table th { text-align: left; padding: 10px 12px; background: #0c1220; color: var(--text-muted); font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--card-border); }
    .data-table td { padding: 12px; border-bottom: 1px solid #1a2333; color: #cbd5e1; }
    .data-table tr:hover { background: rgba(255,255,255,0.02); }

    .search-box { width: 100%; max-width: 400px; padding: 9px 14px; background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 6px; color: white; font-size: 13px; margin-bottom: 16px; }
    .search-box:focus { outline: none; border-color: var(--accent); }
    .term-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; }
    .term-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 8px; padding: 16px; }
    .term-name { font-size: 15px; font-weight: bold; color: #38bdf8; margin-bottom: 6px; }
    .term-desc { font-size: 13px; color: #cbd5e1; line-height: 1.4; }
    .timeline-item { border-left: 2px solid var(--card-border); padding-left: 16px; margin-left: 8px; margin-bottom: 18px; position: relative; }
    .timeline-item::before { content: ""; position: absolute; left: -7px; top: 0; width: 12px; height: 12px; border-radius: 50%; background: var(--accent); }
    .timeline-date { font-size: 11px; color: var(--text-muted); margin-bottom: 4px; }
    .timeline-body { font-size: 13px; background: var(--code-bg); padding: 10px; border-radius: 6px; margin-top: 6px; white-space: pre-wrap; font-family: monospace; }
    .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.3); border-radius: 50%; border-top-color: white; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .toast { position: fixed; bottom: 20px; right: 20px; background: #151d2e; border: 1px solid #10b981; color: white; padding: 12px 20px; border-radius: 8px; font-size: 13px; display: none; z-index: 9999; box-shadow: 0 10px 20px rgba(0,0,0,0.6); }
    /* Modal Styles */
    .modal-overlay { position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.75); display: none; justify-content: center; align-items: center; z-index: 10000; backdrop-filter: blur(4px); }
    .modal-box { background: #151d2e; border: 1px solid #334155; border-radius: 12px; width: 90%; max-width: 520px; padding: 24px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.7); }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid #222f47; padding-bottom: 12px; }
    .modal-header h3 { font-size: 17px; font-weight: 700; color: #f8fafc; }
    .form-group { margin-bottom: 14px; }
    .form-label { display: block; font-size: 12px; font-weight: 600; color: #94a3b8; margin-bottom: 6px; text-transform: uppercase; }
    .form-input { width: 100%; padding: 9px 12px; background: #080c14; border: 1px solid #334155; border-radius: 6px; color: #f8fafc; font-size: 13px; }
    .form-input:focus { outline: none; border-color: #10b981; }
    .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .form-checkbox { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #cbd5e1; cursor: pointer; }
    .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; border-top: 1px solid #222f47; padding-top: 16px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-logo">OW</div>
      <div>
        <h1>OPS-WATCH // Security & GPU Operator Console</h1>
        <span>Host: martin-B650M-K • NVIDIA GeForce RTX 4090 24GB • Headscale VPN Mesh</span>
      </div>
    </div>
    <div class="status-bar">
      <div id="nvme-header-badge" class="badge" style="background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid #10b981;">NVMe: --°C</div>
      <div id="ssh-health-badge" class="badge badge-local" title="TCP 2322 도달성 (tailscale ping 아님)">SSH 2322: 확인 중...</div>
      <div id="ontology-status" class="badge badge-local">Auto-Ontology: Loading...</div>
      <div class="badge badge-gpu" id="gpu-header-badge">GPU: RTX 4090 (Active)</div>
      <div class="badge badge-model">LLM: gemini-3.8-flash-medium</div>
      <button class="btn btn-secondary" style="color: #38bdf8; border-color: rgba(56,189,248,0.4);" onclick="switchTab('guide')"><span>📖</span> 사용가이드</button>
      <button class="btn" onclick="triggerScan(this)"><span>🔍</span> 로그 스캔 (Scan)</button>
    </div>
  </header>

  <div id="global-lockdown-banner" style="display: none; background: #7f1d1d; border: 1px solid #ef4444; color: white; padding: 12px 20px; border-radius: 8px; margin-bottom: 20px; justify-content: space-between; align-items: center; box-shadow: 0 4px 14px rgba(239,68,68,0.4);">
    <div style="display: flex; align-items: center; gap: 12px;">
      <span style="font-size: 20px;">🚨</span>
      <div>
        <strong style="font-size: 14px;">[긴급 발령] 전체 학생 비상 락다운 (Global Panic Lockdown) 활성화 중</strong>
        <p style="font-size: 12px; color: #fca5a5; margin-top: 2px;">모든 학생의 Headscale VPN 통신 및 활성 세션이 강제 격리되었습니다. (관리자 세션만 유지됩니다.)</p>
      </div>
    </div>
    <button class="btn btn-sm" style="background: #059669; border: 1px solid #10b981;" onclick="triggerGlobalLockdown()">🟢 비상 락다운 해제 (Restore)</button>
  </div>

  <div class="tabs">
    <button class="tab-btn active" onclick="switchTab('tickets')">승인 대기 티켓 (<span id="ticket-count">0</span>)</button>
    <button class="tab-btn" onclick="switchTab('gpu')">⚡ GPU 사용량 (RTX 4090)</button>
    <button class="tab-btn" onclick="switchTab('storage')">💾 저장공간 관리</button>
    <button class="tab-btn" onclick="switchTab('containers')">🐳 도커 & 주피터</button>
    <button class="tab-btn" onclick="switchTab('vpn')">🌐 Headscale VPN (<span id="vpn-nav-count">-</span>)</button>
    <button class="tab-btn" onclick="switchTab('guide')">📖 사용가이드 & 연구법</button>
    <button class="tab-btn" onclick="switchTab('processes')">🔍 실행 프로세스 이상 검토</button>
    <button class="tab-btn" onclick="switchTab('users')">👥 사용자별 사용기록</button>
    <button class="tab-btn" onclick="switchTab('anomalies')">🚨 임의 접근 / 보안 위협</button>
    <button class="tab-btn" onclick="switchTab('cve')">🛡️ 시스템 CVE & 보안 이슈</button>
    <button class="tab-btn" onclick="switchTab('memory')">자체 메모리 & 선례 (<span id="memory-count">0</span>)</button>
    <button class="tab-btn" onclick="switchTab('ontology')">NVIDIA Auto-Ontology</button>
    <button class="tab-btn" onclick="switchTab('worklog')">업무기록 (Worklog)</button>
  </div>

  <!-- TAB: TICKETS -->
  <section id="tab-tickets" class="tab-content active">
    <div id="tickets-container">
      <p style="color: var(--text-muted);">티켓을 불러오는 중...</p>
    </div>
  </section>

  <!-- TAB: GPU USAGE -->
  <section id="tab-gpu" class="tab-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;">
      <div>
        <h3 style="font-size: 16px;">⚡ RTX 4090 GPU 자원 및 프로세스 실시간 관제</h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          10분 주기로 GPU 점유율 및 VRAM을 감시하며, 10% 이상 변동 시 학생 Discord 채널로 실시간 안내 웹훅을 자동 발송합니다.
        </p>
      </div>
      <button class="btn btn-sm btn-primary" onclick="notifyGpuDiscord()"><span>📢</span> Discord 학생 채널로 현황 알림</button>
    </div>

    <div class="grid-3" id="gpu-stats-grid">
      <div class="stat-card">
        <div class="stat-label">GPU Utilization</div>
        <div class="stat-val" id="gpu-util-val">0%</div>
        <div class="bar-wrap"><div id="gpu-util-bar" class="bar-fill" style="width: 0%;"></div></div>
        <div style="font-size: 11px; color: var(--text-muted);">Compute Core Activity</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">VRAM Allocation</div>
        <div class="stat-val" id="gpu-vram-val">0.0 / 24.0 GB</div>
        <div class="bar-wrap"><div id="gpu-vram-bar" class="bar-fill" style="width: 0%;"></div></div>
        <div style="font-size: 11px; color: var(--text-muted);">Dedicated GDDR6X Memory</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Temperature & Power</div>
        <div class="stat-val" id="gpu-temp-power">0°C • 0W</div>
        <div style="font-size: 12px; color: #a5b4fc; margin-top: 8px;">Power Limit: 450W • Fan Profile: Adaptive</div>
      </div>
    </div>

    <div class="card">
      <h3 style="font-size: 15px; margin-bottom: 12px;">사용자별 GPU 프로세스 점유 현황 (Compute Processes)</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>사용자 (User)</th>
            <th>PID</th>
            <th>실행 명령어 / 작업</th>
            <th>할당 VRAM</th>
            <th>연산 코어 점유</th>
            <th>시작 시간</th>
          </tr>
        </thead>
        <tbody id="gpu-processes-body"></tbody>
      </table>
    </div>
  </section>

  <!-- TAB: STORAGE -->
  <section id="tab-storage" class="tab-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
      <div>
        <h3 style="font-size: 16px;">서버 저장공간 및 사용자별 쿼터 관리 (Storage & Quotas)</h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          NVMe 고속 SSD(914GB) 및 8TB 연구 대용량 데이터 볼륨(/mnt/data) 실시간 점유율과 테넌트별 사용량을 감시합니다.
        </p>
      </div>
      <button class="btn btn-sm" onclick="loadStorage(true)"><span>🔄</span> 스토리지 즉시 재측정</button>
    </div>

    <!-- Storage Summary Cards -->
    <div class="grid-3" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 16px;">
      <div class="stat-card">
        <div class="stat-label">🚀 NVMe OS & 홈 (/)</div>
        <div class="stat-val" id="storage-nvme-val">554 GB / 914 GB</div>
        <div class="bar-wrap"><div id="storage-nvme-bar" class="bar-fill" style="width: 64%;"></div></div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">사용률: <span id="storage-nvme-pct" style="color: #38bdf8; font-weight: bold;">64%</span> (가용: <span id="storage-nvme-free">314 GB</span>)</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">🗄️ 8TB 연구 데이터 (/mnt/data)</div>
        <div class="stat-val" id="storage-hdd-val">2.1 TB / 7.3 TB</div>
        <div class="bar-wrap"><div id="storage-hdd-bar" class="bar-fill" style="width: 30%;"></div></div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">사용률: <span id="storage-hdd-pct" style="color: #34d399; font-weight: bold;">30%</span> (가용: <span id="storage-hdd-free">4.9 TB</span>)</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">👥 전체 사용자 점유 합계</div>
        <div class="stat-val" id="storage-users-total" style="color: #a855f7;">1.96 TB</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">최다 점유자: <strong id="storage-top-user" style="color: #38bdf8;">martin</strong></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">🛡️ 스토리지 무결성 상태</div>
        <div class="stat-val" id="storage-health-val" style="color: #10b981; font-size: 18px;">정상 (Healthy)</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 8px;">자동 쿼터 초과 모니터링 활성화</div>
      </div>
    </div>

    <!-- Partitions Breakdown Table -->
    <div class="card" style="margin-bottom: 16px;">
      <h3 style="font-size: 15px; margin-bottom: 12px;">시스템 파티션 및 마운트 현황 (Mount Points Breakdown)</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>파티션 (Filesystem)</th>
            <th>마운트 위치</th>
            <th>용도 설명</th>
            <th>전체 용량</th>
            <th>사용량</th>
            <th>가용 용량</th>
            <th>점유율</th>
            <th>상태</th>
          </tr>
        </thead>
        <tbody id="partitions-table-body"></tbody>
      </table>
    </div>

    <!-- User Storage Table -->
    <div class="card">
      <h3 style="font-size: 15px; margin-bottom: 12px;">사용자별 저장공간 사용량 및 쿼터(Quota) 모니터링</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>사용자 (User)</th>
            <th>성명</th>
            <th>역할 (Role)</th>
            <th>홈 경로 (/home)</th>
            <th>연구 데이터 (/mnt/data/users)</th>
            <th>총 사용량</th>
            <th>용량 점유율</th>
            <th>권장 한도 (Soft Quota)</th>
            <th>상태</th>
          </tr>
        </thead>
        <tbody id="storage-users-table-body"></tbody>
      </table>
    </div>
  </section>

  <!-- TAB: CONTAINERS -->
  <section id="tab-containers" class="tab-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
      <div>
        <h3 style="font-size: 16px;">🐳 도커 컨테이너 & 다중 사용자 주피터랩 관리 (Ops-Watch v2)</h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          NVIDIA Container Toolkit 기반 격리 컨테이너, 다중 사용자 JupyterLab 세션 및 NVMe SSD 발열 상태를 통합 관제합니다.
        </p>
      </div>
      <button class="btn btn-sm" onclick="loadContainers()"><span>🔄</span> 컨테이너 새로고침</button>
    </div>

    <!-- Container & Thermal Stat Cards -->
    <div class="grid-3" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-bottom: 16px;">
      <div class="stat-card">
        <div class="stat-label">🔥 NVMe SSD 실시간 온도</div>
        <div class="stat-val" id="cnt-nvme-val" style="color: #10b981;">52.9°C</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">
          서멀 스로틀링 임계치: <span style="color: #fbbf24;">65°C</span> (위험: 75°C)
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">💻 AMD Ryzen CPU 온도</div>
        <div class="stat-val" id="cnt-cpu-val" style="color: #38bdf8;">45.8°C</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">호스트 프로세서 코어 센서 (k10temp)</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">📦 활성 컨테이너 현황</div>
        <div class="stat-val" id="cnt-running-val" style="color: #a855f7;">- / -</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">Running / Total Containers</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">⚡ GPU 컨테이너 런타임</div>
        <div class="stat-val" style="color: #10b981; font-size: 18px;">NVIDIA Container Toolkit</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">DeepSpeed & CUDA 12.4 지원</div>
      </div>
    </div>

    <!-- Containers Table -->
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
        <h3 style="font-size: 15px;">서버 인스턴스 및 사용자별 주피터랩 컨테이너 목록</h3>
        <span style="font-size: 12px; color: var(--text-muted);">Docker Daemon v29.9.3</span>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>컨테이너명</th>
            <th>소유자 / 역할</th>
            <th>상태 (State)</th>
            <th>상세 가동 시간</th>
            <th>포트 바인딩</th>
            <th>베이스 이미지</th>
            <th>컨테이너 제어 (Lifecycle)</th>
          </tr>
        </thead>
        <tbody id="containers-table-body"></tbody>
      </table>
    </div>
  </section>

  <!-- TAB: VPN (Headscale) -->
  <section id="tab-vpn" class="tab-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
      <div>
        <h3 style="font-size: 16px; display: flex; align-items: center; gap: 8px;">
          🌐 Headscale VPN 메시 네트워크 & 단말 관제 (WireGuard Mesh)
          <span class="badge badge-online" id="vpn-server-badge">Headscale v0.29.6 Online</span>
        </h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          오픈소스 Headscale 서버 기반 연구실 전용 사설망(100.64.0.0/10), 연결 노드 실시간 상태 감시, 사전 인증키(Pre-Auth Key) 발급 및 세션 통제
        </p>
      </div>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-sm" onclick="openVpnKeyModal()"><span>🔑</span> 사전 인증키 발급</button>
        <button class="btn btn-secondary btn-sm" onclick="loadVpn()"><span>🔄</span> VPN 새로고침</button>
      </div>
    </div>

    <!-- VPN KPI Summary Cards -->
    <div class="grid-4" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 14px; margin-bottom: 16px;">
      <div class="stat-card">
        <div class="stat-label">📡 총 등록 노드 (Devices)</div>
        <div class="stat-val" id="vpn-total-nodes" style="color: #38bdf8;">-</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
          🟢 온라인: <strong id="vpn-online-nodes" style="color: #34d399;">-</strong> | ⚪ 오프라인: <span id="vpn-offline-nodes">-</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">🔒 VPN 사설망 IP 풀</div>
        <div class="stat-val" style="font-size: 18px; color: #a5b4fc;">100.64.0.0/10</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
          서버 IP: <strong style="color: #38bdf8;">100.64.0.2</strong> (gpu4090)
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">👥 VPN 네임스페이스 (Users)</div>
        <div class="stat-val" id="vpn-total-users" style="color: #c084fc;">-</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;" id="vpn-users-summary">
          martin, student1 외
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-label">🔑 활성 사전인증키 (Active Keys)</div>
        <div class="stat-val" id="vpn-active-keys" style="color: #fbbf24;">-</div>
        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">
          유효기간 내 미만료 키
        </div>
      </div>
    </div>

    <!-- SECTION 1: CONNECTED NODES TABLE -->
    <div class="card" style="margin-bottom: 18px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h3 style="font-size: 15px;">🌐 연결된 클라이언트 단말 및 노드 목록 (Registered Nodes)</h3>
          <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
            연구원 노트북, 관리자 PC 및 GPU 호스트의 Headscale VPN 세션 실시간 추적
          </p>
        </div>
        <input type="text" id="vpn-node-search" class="search-box" style="margin: 0; max-width: 240px; padding: 6px 12px; font-size: 12px;" placeholder="기기명, 사용자, IP 검색..." oninput="filterVpnNodes(this.value)">
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>단말명 (Hostname)</th>
            <th>소유 사용자</th>
            <th>VPN IPv4 / IPv6</th>
            <th>운영체제 (OS)</th>
            <th>연결 상태</th>
            <th>최근 통신 (Last Seen)</th>
            <th>접근 권한 (ACL Scope)</th>
            <th>키 만료일</th>
            <th>세션 및 기기 제어</th>
          </tr>
        </thead>
        <tbody id="vpn-nodes-tbody"></tbody>
      </table>
    </div>

    <!-- SECTION: ZERO-TRUST ACL POLICIES -->
    <div class="card" style="margin-bottom: 18px; border-left: 4px solid #a855f7;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h3 style="font-size: 15px; color: #c084fc;">🛡️ Headscale 제로 트러스트(Zero-Trust) ACL 격리 정책</h3>
          <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
            모든 학생 연구원은 GPU 서버(SSH: 2322 & JupyterLab: 8888-8895) 외 다른 모든 기기(관리자 PC, Mac mini, 타 학생 PC)에 대해 <strong>완전 비가시/100% 차단</strong>됩니다.
          </p>
        </div>
        <span class="badge badge-online">ACL Enforcement Active</span>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>대상 그룹 (Group)</th>
            <th>소속 사용자</th>
            <th>통신 허용 대상 (Destination Rules)</th>
            <th>단말 가시성 (Peer Visibility)</th>
            <th>보안 격리 상태 (Isolation)</th>
          </tr>
        </thead>
        <tbody id="vpn-acl-tbody"></tbody>
      </table>
    </div>

    <!-- SECTION 2: PRE-AUTH KEYS TABLE -->
    <div class="card" style="margin-bottom: 18px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 8px;">
        <div>
          <h3 style="font-size: 15px;">🔑 발급된 사전 인증키 이력 (Pre-Authentication Keys)</h3>
          <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">
            신규 연구원 온보딩 및 기기 재인증 시 발급된 Headscale 일회용/재사용 보안 키
          </p>
        </div>
        <button class="btn btn-sm" onclick="openVpnKeyModal()"><span>➕</span> 새 인증키 발급</button>
      </div>

      <table class="data-table">
        <thead>
          <tr>
            <th>Key ID</th>
            <th>대상 사용자</th>
            <th>인증키 (Auth Key)</th>
            <th>유형</th>
            <th>상태</th>
            <th>만료 일시</th>
            <th>생성 일시</th>
            <th>원클릭 작업</th>
          </tr>
        </thead>
        <tbody id="vpn-keys-tbody"></tbody>
      </table>
    </div>

    <!-- SECTION 3: ONBOARDING QUICK GUIDE -->
    <div class="card" style="border-left: 4px solid var(--primary);">
      <h3 style="font-size: 15px; margin-bottom: 10px; color: #fff;">📋 연구원 Tailscale VPN 간편 연결 가이드</h3>
      <p style="font-size: 12px; color: var(--text-muted); line-height: 1.6; margin-bottom: 14px;">
        연구원이 발급받은 인증키로 본인 PC에서 아래 명령어를 실행하면, 즉시 연구실 사설 VPN 망에 합류하여 전용 JupyterLab과 SSH에 접근할 수 있습니다.
      </p>
      <div class="grid-2" style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
        <div style="background: #080c14; padding: 12px; border-radius: 6px;">
          <div style="font-size: 12px; font-weight: 600; color: #38bdf8; margin-bottom: 6px;">🍎 macOS / 🐧 Linux (CLI)</div>
          <pre style="margin: 0; font-size: 11px; color: #f1f5f9; overflow-x: auto;">tailscale up --login-server http://100.64.0.1:8080 --authkey &lt;AUTH_KEY&gt;</pre>
        </div>
        <div style="background: #080c14; padding: 12px; border-radius: 6px;">
          <div style="font-size: 12px; font-weight: 600; color: #34d399; margin-bottom: 6px;">🪟 Windows (PowerShell 관리자)</div>
          <pre style="margin: 0; font-size: 11px; color: #f1f5f9; overflow-x: auto;">tailscale up --login-server http://100.64.0.1:8080 --authkey &lt;AUTH_KEY&gt;</pre>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB: GUIDE -->
  <section id="tab-guide" class="tab-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; flex-wrap: wrap; gap: 10px;">
      <div>
        <h3 style="font-size: 16px; display: flex; align-items: center; gap: 8px;">
          📖 연구실 인프라 사용법 & 연구 가이드 (Live Lab Guide)
          <span class="badge" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.3);">RTX 4090 24GB 맞춤 가이드</span>
        </h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          Headscale VPN 연결, 개인 전용 JupyterLab 접속, 8B LLM QLoRA 파인튜닝, DeepSpeed ZeRO-2 및 NVMe 발열 방지 수칙
        </p>
      </div>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-sm" style="background: #2563eb; border-color: #3b82f6;" onclick="copyOnboardingTemplate()">📋 학생 전달용 안내문 전체 복사</button>
        <a href="/guide" target="_blank" class="btn btn-secondary btn-sm" style="text-decoration: none;">↗ 독립 창에서 열기 / 인쇄</a>
      </div>
    </div>

    <!-- Sub-Tabs Navigation -->
    <div style="display: flex; gap: 6px; margin-bottom: 16px; border-bottom: 1px solid var(--card-border); padding-bottom: 10px; overflow-x: auto;">
      <button class="btn btn-sm sub-tab active" id="gbtn-onboarding" onclick="switchGuide('onboarding')">🚀 1. 온보딩 & VPN</button>
      <button class="btn btn-sm btn-secondary sub-tab" id="gbtn-storage" onclick="switchGuide('storage')">💾 2. 스토리지 격리</button>
      <button class="btn btn-sm btn-secondary sub-tab" id="gbtn-gpu" onclick="switchGuide('gpu')">⚡ 3. GPU 점유 & 좀비 커널</button>
      <button class="btn btn-sm btn-secondary sub-tab" id="gbtn-llm" onclick="switchGuide('llm')">🧠 4. 8B LLM 파인튜닝</button>
      <button class="btn btn-sm btn-secondary sub-tab" id="gbtn-video" onclick="switchGuide('video')">🎬 5. 비디오 & NVMe 발열</button>
      <button class="btn btn-sm btn-secondary sub-tab" id="gbtn-checklist" onclick="switchGuide('checklist')">📋 6. 체크리스트 요약</button>
    </div>

    <!-- SUB-SECTION 1: ONBOARDING -->
    <div id="guide-sec-onboarding" class="guide-content-sec">
      <div class="card" style="margin-bottom: 14px; border-left: 4px solid var(--primary);">
        <h4 style="font-size: 14px; margin-bottom: 6px; color: #fff;">🖥️ 연구실 인프라 사양 및 아키텍처 개요</h4>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.6;">
          본 서버(<code>martin-B650M-K</code>, GPU 박스 IP: <code>100.64.0.2</code>)는 연구원들의 안전한 연구를 위해 <strong>Docker 컨테이너 격리 방식</strong>으로 운영됩니다.<br>
          호스트 OS에 패키지를 직접 설치하지 않고, 각자에게 할당된 독립된 <strong>JupyterLab (PyTorch 24.04-py3, CUDA 12.4)</strong> 컨테이너 안에서 작업을 수행합니다.
        </p>
      </div>

      <div class="grid-2">
        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="color: #38bdf8; font-size: 13px;">Step 1. Headscale VPN 연결</strong>
            <span class="badge badge-online">사설망 100.64.0.0/10</span>
          </div>
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
            외부 공인 IP가 닫혀 있으므로 Tailscale 클라이언트를 통해 연구실 WireGuard VPN에 먼저 접속해야 합니다.
          </p>
          <div style="position: relative;">
            <pre style="background: #080c14; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #f1f5f9;">tailscale up --login-server http://100.64.0.1:8080 --authkey &lt;PRE_AUTH_KEY&gt;</pre>
            <button class="btn btn-secondary btn-sm" style="position: absolute; top: 6px; right: 6px; padding: 2px 8px; font-size: 10px;" onclick="copyCode(this)">복사</button>
          </div>
          <p style="font-size: 11px; color: #34d399; margin-top: 8px;">✔ 연결 완료 시 본인의 Tailnet 가상 IP가 할당됩니다.</p>
        </div>

        <div class="card">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="color: #38bdf8; font-size: 13px;">Step 2. 개인 전용 JupyterLab 접속</strong>
            <span class="badge badge-model">CUDA 12.4 • PyTorch 2.3</span>
          </div>
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 10px;">
            연구원마다 고유 포트(8888, 8889, 8890, 8891...)와 전용 보안 토큰이 부여된 컨테이너가 배정됩니다.
          </p>
          <div style="position: relative;">
            <pre style="background: #080c14; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #38bdf8;">http://100.64.0.2:&lt;PORT&gt;/?token=&lt;TOKEN&gt;</pre>
            <button class="btn btn-secondary btn-sm" style="position: absolute; top: 6px; right: 6px; padding: 2px 8px; font-size: 10px;" onclick="copyCode(this)">복사</button>
          </div>
          <p style="font-size: 11px; color: #34d399; margin-top: 8px;">✔ 브라우저에서 바로 GPU 가속 JupyterLab이 8TB 대용량 스토리지 루트로 열립니다.</p>
        </div>
      </div>

      <div class="card" style="margin-top: 14px;">
        <strong style="color: #e2e8f0; font-size: 13px;">Step 3. 터미널 SSH 접속 (선택 사항)</strong>
        <p style="font-size: 12px; color: var(--text-muted); margin: 6px 0 10px;">
          CLI 환경이나 tmux 장기 실행이 필요한 경우 비표준 포트 <code>2322</code>로 SSH 접속합니다:
        </p>
        <div style="position: relative;">
          <pre style="background: #080c14; padding: 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #f1f5f9;">ssh -p 2322 &lt;username&gt;@100.64.0.2</pre>
          <button class="btn btn-secondary btn-sm" style="position: absolute; top: 6px; right: 6px; padding: 2px 8px; font-size: 10px;" onclick="copyCode(this)">복사</button>
        </div>
      </div>

      <div class="card" style="margin-top: 14px;">
        <strong style="color: #38bdf8; font-size: 13px;">📋 연구원별 배정 주피터랩 포트 현황</strong>
        <table class="data-table" style="margin-top: 8px;">
          <thead>
            <tr>
              <th>연구원 계정</th>
              <th>컨테이너명</th>
              <th>포트</th>
              <th>기본 작업 디렉토리 (/workspace)</th>
              <th>상태</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><code>martin</code> (관리자)</td>
              <td><code>martin_jupyter</code></td>
              <td><code>8888</code></td>
              <td><code>/mnt/data/users/martin/jupyter_home</code> (8TB 스토리지)</td>
              <td><span class="badge badge-online">🟢 활성 (Running)</span></td>
            </tr>
            <tr>
              <td><code>student1</code> (연구원)</td>
              <td><code>student1_jupyter</code></td>
              <td><code>8889</code></td>
              <td><code>/mnt/data/users/student1/jupyter_home</code> (8TB 스토리지)</td>
              <td><span class="badge badge-local">⚪ 대기 (Standby)</span></td>
            </tr>
            <tr>
              <td><code>student2</code> (연구원)</td>
              <td><code>student2_jupyter</code></td>
              <td><code>8890</code></td>
              <td><code>/mnt/data/users/student2/jupyter_home</code> (8TB 스토리지)</td>
              <td><span class="badge badge-local">⚪ 대기 (Standby)</span></td>
            </tr>
            <tr>
              <td><code>student3</code> (연구원)</td>
              <td><code>student3_jupyter</code></td>
              <td><code>8891</code></td>
              <td><code>/mnt/data/users/student3/jupyter_home</code> (8TB 스토리지)</td>
              <td><span class="badge badge-local">⚪ 대기 (Standby)</span></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- SUB-SECTION 2: STORAGE -->
    <div id="guide-sec-storage" class="guide-content-sec" style="display: none;">
      <div class="card" style="margin-bottom: 14px; border-left: 4px solid #10b981;">
        <h4 style="font-size: 14px; margin-bottom: 6px; color: #34d399;">💾 기본 시작 폴더(Workspace Root) 및 스토리지 분리 구조</h4>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.6;">
          주피터랩 시작 시 <strong>기본 열리는 최상위 폴더(<code>/workspace</code>)는 8TB 대용량 스토리지 내의 독립 작업 폴더(<code>/mnt/data/users/&lt;user&gt;/jupyter_home</code>)</strong>로 설정되어 있습니다.<br>
          따라서 새로 생성하는 노트북 및 프로젝트 파일이 깔끔하게 격리되어 관리되며, 8TB HDD에 저장되므로 시스템 NVMe 루트 디스크가 꽉 차는 사고를 근본적으로 방지합니다.<br>
          상위 데이터 폴더(<code>data_root/</code>) 및 개인 홈 디렉토리(<code>home/</code>)도 탐색기 내에서 바로 접근할 수 있습니다.
        </p>
      </div>

      <table class="data-table" style="margin-bottom: 16px;">
        <thead>
          <tr>
            <th>JupyterLab 탐색기 경로</th>
            <th>호스트 실제 저장소</th>
            <th>권장 용도</th>
            <th>용량 및 특성</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>/workspace</code> <strong>(기본 시작 폴더)</strong></td>
            <td><code>/mnt/data/users/&lt;user&gt;/jupyter_home</code></td>
            <td><strong>개인 연구 노트북, 실험 코드, 프로젝트 작업공간</strong></td>
            <td><span style="color: #34d399; font-weight: bold;">8TB 대용량 스토리지</span> (전용 독립 홈 폴더)</td>
          </tr>
          <tr>
            <td><code>/workspace/data_root</code></td>
            <td><code>/mnt/data/users/&lt;user&gt;</code></td>
            <td><strong>대용량 비디오 데이터셋, HuggingFace 캐시, 8B 모델 가중치</strong></td>
            <td><span style="color: #38bdf8; font-weight: bold;">8TB 대용량 스토리지</span> (공유 및 대용량 I/O 저장소)</td>
          </tr>
          <tr>
            <td><code>/workspace/home</code></td>
            <td><code>/home/&lt;user&gt;</code></td>
            <td>개인 bash 설정, SSH 키, git repos, 가벼운 설정 파일</td>
            <td><span style="color: #f59e0b; font-weight: bold;">루트 914GB NVMe</span> (대용량 파일 저장 금지, 설정 전용)</td>
          </tr>
        </tbody>
      </table>

      <div class="grid-2">
        <div class="card">
          <strong style="color: #38bdf8; font-size: 13px;">💡 HuggingFace 캐시 디렉터리 리다이렉션 (필수 코드)</strong>
          <p style="font-size: 12px; color: var(--text-muted); margin: 6px 0 10px;">
            기본 캐시가 <code>~/.cache</code>로 지정되어 루트를 채우는 사고를 방지하기 위해 노트북 첫 셀에 선언하세요:
          </p>
          <div style="position: relative;">
            <pre style="background: #080c14; padding: 12px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #f1f5f9;">import os
os.environ["HF_HOME"] = "/workspace/cache/huggingface"
os.environ["TORCH_HOME"] = "/workspace/cache/torch"</pre>
            <button class="btn btn-secondary btn-sm" style="position: absolute; top: 6px; right: 6px; padding: 2px 8px; font-size: 10px;" onclick="copyCode(this)">복사</button>
          </div>
        </div>

        <div class="card">
          <strong style="color: #38bdf8; font-size: 13px;">⚡ JupyterLab 터미널 및 GPU 상태 즉시 확인</strong>
          <p style="font-size: 12px; color: var(--text-muted); margin: 6px 0 10px;">
            JupyterLab 상단 메뉴 <code>File ➔ New ➔ Terminal</code>을 실행하면 bash 쉘에서 GPU와 디스크를 확인할 수 있습니다:
          </p>
          <div style="position: relative;">
            <pre style="background: #080c14; padding: 12px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #34d399;"># GPU 실시간 상태 및 프로세스 점유 확인
nvidia-smi

# 작업 디렉토리 용량 확인 (/workspace 가 7.3TB로 마운트됨)
df -h /workspace</pre>
            <button class="btn btn-secondary btn-sm" style="position: absolute; top: 6px; right: 6px; padding: 2px 8px; font-size: 10px;" onclick="copyCode(this)">복사</button>
          </div>
        </div>
      </div>
    </div>

    <!-- SUB-SECTION 3: GPU ETIQUETTE -->
    <div id="guide-sec-gpu" class="guide-content-sec" style="display: none;">
      <div class="card" style="margin-bottom: 14px; border-left: 4px solid #ef4444;">
        <h4 style="font-size: 14px; margin-bottom: 6px; color: #f87171;">🚨 단일 GPU 에티켓: "브라우저 창만 닫아도 VRAM은 반납되지 않습니다"</h4>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.6;">
          RTX 4090은 단 1장(24GB VRAM)뿐이므로 여러 연구원이 공유합니다.<br>
          노트북 창을 닫아도 <strong>커널이 살아있으면 24GB VRAM 전체가 계속 점유</strong>되어 다른 연구원이 즉시 CUDA OOM 크래시를 겪게 됩니다.
        </p>
      </div>

      <div class="grid-2">
        <div class="card" style="border: 1px solid rgba(239,68,68,0.3);">
          <strong style="color: #ef4444; font-size: 13px;">❌ 자주 발생하는 잘못된 습관</strong>
          <ul style="font-size: 12px; color: #cbd5e1; margin-top: 8px; line-height: 1.8;">
            <li>노트북 웹페이지 탭/브라우저만 닫기</li>
            <li>학습 스크립트에서 에러(Exception) 발생 후 방치</li>
            <li>OOM 발생 후 커널을 재시작(Restart)하지 않고 방치</li>
          </ul>
        </div>
        <div class="card" style="border: 1px solid rgba(34,197,94,0.3);">
          <strong style="color: #22c55e; font-size: 13px;">✔ 올바른 자원 반납 절차</strong>
          <ol style="font-size: 12px; color: #cbd5e1; margin-top: 8px; line-height: 1.8;">
            <li>상단 메뉴: <strong>Kernel ➔ Shut Down All Kernels</strong> 클릭</li>
            <li>좌측 사이드바: <strong>'Running Terminals and Kernels' (정지 아이콘)</strong>에서 커널 셧다운</li>
            <li>Ops-Watch 대시보드에서 본인 컨테이너 VRAM이 0MB인지 확인</li>
          </ol>
        </div>
      </div>

      <div class="card" style="margin-top: 14px;">
        <strong style="color: #fbbf24; font-size: 13px;">🤖 ZombieKernelDetector 자동 감지 정책</strong>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 6px;">
          VRAM을 4GB 이상 점유하면서 GPU/CPU 연산률이 0%인 상태로 <strong>30분 이상 방치</strong>되는 경우, 
          Ops-Watch 온톨로지 엔진이 <code>zombie_jupyter_kernel</code> 신호를 감지하고 관리자에게 알림 티켓을 발행하여 회수합니다.
        </p>
      </div>
    </div>

    <!-- SUB-SECTION 4: 8B LLM FINETUNING -->
    <div id="guide-sec-llm" class="guide-content-sec" style="display: none;">
      <div class="card" style="margin-bottom: 14px;">
        <h4 style="font-size: 14px; margin-bottom: 6px; color: #fff;">🧠 8B LLM 파인튜닝 연구법 (RTX 4090 24GB 맞춤)</h4>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.6;">
          8B 파라미터 모델(LLaMA-3-8B, Qwen-2.5-7B)은 기본 FP16 가중치만 16GB에 달하며 일반 파인튜닝 시 40GB+가 필요합니다.<br>
          아래 <strong>4-bit QLoRA</strong> 및 <strong>FlashAttention-2</strong> 설정을 적용하면 VRAM 12~14GB 내에서 안전하게 학습할 수 있습니다.
        </p>
      </div>

      <div class="card" style="margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <strong style="color: #38bdf8; font-size: 13px;">✨ 1. 4-bit QLoRA + FlashAttention-2 파이썬 스크립트</strong>
          <span class="badge badge-success">VRAM ~13GB 소비</span>
        </div>
        <div style="position: relative;">
          <pre style="background: #080c14; padding: 12px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #f1f5f9;">import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

# 1. 4-bit 양자화 설정 (모델 가중치 ~5.5GB 압축)
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True
)

model_id = "meta-llama/Meta-Llama-3-8B-Instruct"
tokenizer = AutoTokenizer.from_pretrained(model_id, cache_dir="/workspace/data/cache")

model = AutoModelForCausalLM.from_pretrained(
    model_id,
    quantization_config=bnb_config,
    device_map="auto",
    attn_implementation="flash_attention_2", # FlashAttention-2 메모리 30% 절감 & 2.5배 가속
    cache_dir="/workspace/data/cache"
)

# 2. Gradient Checkpointing 활성화
model = prepare_model_for_kbit_training(model)
model.gradient_checkpointing_enable()

# 3. LoRA 어댑터 설정 (Rank 16, Alpha 32)
lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM"
)

model = get_peft_model(model, lora_config)
model.print_trainable_parameters()</pre>
          <button class="btn btn-secondary btn-sm" style="position: absolute; top: 6px; right: 6px; padding: 2px 8px; font-size: 10px;" onclick="copyCode(this)">복사</button>
        </div>
      </div>

      <div class="card">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <strong style="color: #38bdf8; font-size: 13px;">⚡ 2. DeepSpeed ZeRO-2 CPU-Offload 설정 (ds_config.json)</strong>
          <span class="badge badge-model">64GB 호스트 RAM 활용</span>
        </div>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">
          옵티마이저 상태(AdamW 모멘텀/분산)를 호스트의 64GB DDR5 RAM으로 오프로드하여 VRAM 8GB 이상을 확보합니다:
        </p>
        <div style="position: relative;">
          <pre style="background: #080c14; padding: 12px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #f1f5f9;">{
  "train_micro_batch_size_per_gpu": 2,
  "gradient_accumulation_steps": 4,
  "bf16": { "enabled": true },
  "zero_optimization": {
    "stage": 2,
    "offload_optimizer": { "device": "cpu", "pin_memory": true },
    "allgather_bucket_size": 200000000,
    "reduce_bucket_size": 200000000
  }
}</pre>
          <button class="btn btn-secondary btn-sm" style="position: absolute; top: 6px; right: 6px; padding: 2px 8px; font-size: 10px;" onclick="copyCode(this)">복사</button>
        </div>
      </div>
    </div>

    <!-- SUB-SECTION 5: VIDEO & NVME -->
    <div id="guide-sec-video" class="guide-content-sec" style="display: none;">
      <div class="card" style="margin-bottom: 14px; border-left: 4px solid #f59e0b;">
        <h4 style="font-size: 14px; margin-bottom: 6px; color: #fbbf24;">🎬 비디오 데이터셋 (video-multi-target) & NVMe 열보호</h4>
        <p style="font-size: 12px; color: var(--text-muted); line-height: 1.6;">
          대용량 비디오 처리 시 수만 개의 소형 mp4를 무작위 개별 디코딩하면 NVMe 온도가 75°C 이상으로 급상승하여 쓰로틀링(속도 1/10 토막)이 발생합니다.<br>
          우리 Docker 환경은 <code>--ipc=host</code> 및 <code>shm_size: 16gb</code>로 버스 에러를 차단해 두었으며, 데이터는 <strong>WebDataset (.tar)</strong> 형태로 순차 읽기를 권장합니다.
        </p>
      </div>

      <div class="card">
        <strong style="color: #38bdf8; font-size: 13px;">💡 안전한 비디오 DataLoader & NVMe 온도 감시 코드</strong>
        <div style="position: relative; margin-top: 8px;">
          <pre style="background: #080c14; padding: 12px; border-radius: 6px; font-size: 11px; overflow-x: auto; color: #f1f5f9;">import torch
from torch.utils.data import DataLoader

# 1. 고속 비디오 I/O를 위한 DataLoader 설정
train_loader = DataLoader(
    dataset,
    batch_size=4,
    shuffle=True,
    num_workers=4,            # 과도한 worker 수 지양 (4~8 권장)
    pin_memory=True,          # CPU ➔ GPU 텐서 전송 속도 가속
    persistent_workers=True,  # 에포크마다 워커를 재생성하지 않고 유지
    prefetch_factor=2
)

# 2. 비디오 학습 루프 내 NVMe 발열 방지 슬립 체크
def get_nvme_temp():
    try:
        with open("/sys/class/hwmon/hwmon1/temp1_input", "r") as f:
            return float(f.read().strip()) / 1000.0
    except Exception:
        return 50.0

for step, batch in enumerate(train_loader):
    if step % 200 == 0:
        temp = get_nvme_temp()
        if temp > 65.0:
            print(f"[NVMe Thermal Guard] 온도가 {temp:.1f}°C로 상승하여 0.5초 쿨다운합니다.")
            import time; time.sleep(0.5)
            
    loss = model(**batch).loss
    loss.backward()
    optimizer.step()
    optimizer.zero_grad()</pre>
          <button class="btn btn-secondary btn-sm" style="position: absolute; top: 6px; right: 6px; padding: 2px 8px; font-size: 10px;" onclick="copyCode(this)">복사</button>
        </div>
      </div>
    </div>

    <!-- SUB-SECTION 6: CHECKLIST -->
    <div id="guide-sec-checklist" class="guide-content-sec" style="display: none;">
      <div class="card">
        <h4 style="font-size: 14px; margin-bottom: 12px; color: #fff;">📋 연구원 일일 체크리스트 요약</h4>
        <ul style="font-size: 13px; color: #cbd5e1; line-height: 2.0; padding-left: 20px;">
          <li>✅ <strong>접속 전:</strong> 로컬 PC에서 <code>tailscale up</code> 연결 상태 확인</li>
          <li>✅ <strong>스토리지:</strong> 대용량 모델 및 비디오 데이터는 반드시 <code>/workspace/data</code>에 저장</li>
          <li>✅ <strong>파인튜닝:</strong> 8B 모델 학습 시 <code>load_in_4bit=True</code> 또는 <code>ZeRO-2 CPU-offload</code> 적용</li>
          <li>✅ <strong>종료 시:</strong> 실험이 끝나면 <strong>반드시</strong> JupyterLab 상단 <code>Kernel ➔ Shut Down All Kernels</code> 실행</li>
          <li>✅ <strong>상태 확인:</strong> Ops-Watch 상단에서 GPU VRAM 반납 및 NVMe 온도 정상(55°C 내외) 여부 확인</li>
        </ul>
        <div style="margin-top: 16px;">
          <button class="btn btn-sm" style="background: #2563eb; border-color: #3b82f6;" onclick="copyOnboardingTemplate()">📋 학생 전달용 온보딩 안내문 템플릿 복사하기</button>
        </div>
      </div>
    </div>
  </section>

  <!-- TAB: PROCESSES -->
  <section id="tab-processes" class="tab-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <div>
        <h3 style="font-size: 16px;">서버 실행 프로세스 정밀 검토 (top / ps / /proc)</h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">
          임시 디렉터리(/tmp, /dev/shm) 바이너리, 잠긴 계정 잔여 프로세스, 삭제된 바이너리 실행, 커널 스레드 위장 및 비정상 고부하 프로세스를 자동 탐지합니다.
        </p>
      </div>
      <button class="btn btn-sm" onclick="loadProcesses()"><span>🔍</span> 프로세스 즉시 재검사</button>
    </div>

    <div class="grid-3" style="margin-bottom: 16px;">
      <div class="stat-card">
        <div class="stat-label">총 실행 프로세스 수</div>
        <div class="stat-val" id="proc-total-count">-</div>
        <div style="font-size: 11px; color: var(--text-muted);">전체 사용자 및 데몬 프로세스</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">이상 징후 감지 수</div>
        <div class="stat-val" id="proc-anomaly-count" style="color: #10b981;">0</div>
        <div style="font-size: 11px; color: var(--text-muted);">미인가 바이너리 / 잠긴 계정 등</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">검사 엔진 (Engine)</div>
        <div class="stat-val" style="font-size: 18px; color: #38bdf8;">ps /proc Rules + LLM</div>
        <div style="font-size: 11px; color: var(--text-muted);">Auto-Ontology 프로세스 지표 연동</div>
      </div>
    </div>

    <div class="card" id="proc-anomalies-card" style="display: none; border-left: 4px solid #ef4444;">
      <h3 style="font-size: 15px; color: #f87171; margin-bottom: 12px;">🚨 이상 프로세스 긴급 경보 (Detected Anomalies)</h3>
      <div id="proc-anomalies-body"></div>
    </div>

    <div class="card">
      <h3 style="font-size: 15px; margin-bottom: 12px;">CPU / 메모리 상위 실행 프로세스 (Top Processes)</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>사용자 (User)</th>
            <th>PID</th>
            <th>%CPU</th>
            <th>%MEM</th>
            <th>STAT</th>
            <th>명령어 / 바이너리 경로 (Command)</th>
            <th>진단 상태</th>
          </tr>
        </thead>
        <tbody id="processes-table-body"></tbody>
      </table>
    </div>
  </section>

  <!-- TAB: USERS -->
  <section id="tab-users" class="tab-content">
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;">
        <div>
          <h3 style="font-size: 15px;">서버 등록 사용자 및 최근 활동 내역</h3>
          <p style="font-size: 12px; color: var(--text-muted); margin-top: 2px;">사용자별 접근 제어, 단말 추적 및 침해사고 긴급 격리 제어</p>
        </div>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-sm" id="global-lockdown-btn" style="background: #dc2626; border: 1px solid #b91c1c;" onclick="triggerGlobalLockdown()"><span>🚨</span> 긴급 전체 차단 (Lockdown)</button>
          <button class="btn btn-sm" onclick="openUserModal()"><span>➕</span> 신규 사용자 추가</button>
        </div>
      </div>
      <div style="background: rgba(56, 189, 248, 0.05); border: 1px solid rgba(56, 189, 248, 0.2); border-radius: 8px; padding: 12px 16px; margin-bottom: 14px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
        <div style="display: flex; gap: 18px; align-items: center; flex-wrap: wrap;">
          <div style="font-size: 13px; font-weight: 600; color: #fff;">🐳 다중 사용자 주피터랩 관리:</div>
          <div style="font-size: 12px; color: #cbd5e1;">등록 컨테이너: <strong id="u-jup-reg-count" style="color: #38bdf8;">-</strong>개</div>
          <div style="font-size: 12px; color: #cbd5e1;">실행 중 (Active): <strong id="u-jup-run-count" style="color: #34d399;">-</strong>개</div>
          <div style="font-size: 12px; color: #cbd5e1;">할당 포트 범위: <strong id="u-jup-port-range" style="color: #a5b4fc;">8888 ~ 8891+</strong></div>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="switchTab('containers')">🐳 도커 컨테이너 탭 이동 ↗</button>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>사용자명</th>
            <th>이름</th>
            <th>역할 (Role)</th>
            <th>계정 상태</th>
            <th>Headscale VPN</th>
            <th>접속 PC & OS</th>
            <th>VPN IP</th>
            <th>GPU 권한</th>
            <th>🐳 JupyterLab 컨테이너 & 상태 / 제어</th>
            <th>만료일</th>
            <th>보안 및 단말 상태</th>
            <th>긴급 대응 조치 (Emergency)</th>
          </tr>
        </thead>
        <tbody id="users-table-body"></tbody>
      </table>
    </div>
  </section>

  <!-- TAB: ANOMALIES -->
  <section id="tab-anomalies" class="tab-content">
    <div class="card">
      <h3 style="font-size: 15px; margin-bottom: 12px;">Falco eBPF & Kernel Auditd 임의 접근 감지 내역</h3>
      <table class="data-table">
        <thead>
          <tr>
            <th>시간</th>
            <th>발생 사용자</th>
            <th>접근 대상 리소스</th>
            <th>감지 카테고리</th>
            <th>상태</th>
            <th>권고/실행 작업</th>
            <th>해결/승인 메모</th>
          </tr>
        </thead>
        <tbody id="anomalies-table-body"></tbody>
      </table>
    </div>
  </section>

  <!-- TAB: CVE -->
  <section id="tab-cve" class="tab-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
      <h3 style="font-size: 16px;">시스템 취약점 및 보안 점검 결과 (CVE & Hardening Audit)</h3>
      <span class="badge badge-online" style="font-size: 13px; padding: 6px 14px;">보안 점검 점수: 88 / 100 (Hardened)</span>
    </div>
    <div id="cve-container"></div>
  </section>

  <!-- TAB: MEMORY -->
  <section id="tab-memory" class="tab-content">
    <input type="text" class="search-box" placeholder="메모리 검색 (키워드 입력)..." oninput="searchMemory(this.value)">
    <div id="memory-container"></div>
  </section>

  <!-- TAB: ONTOLOGY -->
  <section id="tab-ontology" class="tab-content">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px;">
      <div>
        <h3 style="font-size: 17px; font-weight: 700; color: #f8fafc;">NVIDIA Auto-Ontology // Operational Semantic Layer</h3>
        <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;" id="ontology-meta-desc">
          버전: v1.2.0 • 프레임워크: NVIDIA Auto-Ontology & Apache Ossie Compatible • 모델: Local Semantic Model
        </p>
      </div>
      <div style="display: flex; gap: 10px;">
        <button class="btn btn-secondary btn-sm" onclick="exportOssie()">Apache Ossie 모델 내보내기</button>
        <button class="btn btn-sm" onclick="loadOntology()"><span>🔄</span> 새로고침</button>
      </div>
    </div>
    <span id="ossie-export-status" style="font-size: 12px; color: var(--accent); margin-bottom: 12px; display: block;"></span>

    <!-- SECTION 1: WHEN & HOW -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
      <div class="card" style="border-left: 4px solid #38bdf8;">
        <h3 style="font-size: 15px; color: #38bdf8; margin-bottom: 12px;">🕒 언제 동작하는가? (Execution Triggers & Lifecycle)</h3>
        <div id="ontology-when-container"></div>
      </div>
      <div class="card" style="border-left: 4px solid #10b981;">
        <h3 style="font-size: 15px; color: #10b981; margin-bottom: 12px;">⚙️ 어떻게 동작하는가? (Architecture & Knowledge Pipeline)</h3>
        <div id="ontology-how-container"></div>
      </div>
    </div>

    <!-- SECTION 2: CHANGELOG -->
    <div class="card" style="border-left: 4px solid #a855f7; margin-bottom: 20px;">
      <h3 style="font-size: 15px; color: #c084fc; margin-bottom: 12px;">📋 온톨로지 업데이트 내역 (Changelog & Updates)</h3>
      <div id="ontology-history-container"></div>
    </div>

    <!-- SECTION 3: BASELINES & SIGNALS -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
      <div class="card">
        <h3 style="font-size: 15px; color: #34d399; margin-bottom: 8px;">🛡️ 정상 패턴 베이스라인 (Normal Baselines)</h3>
        <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 10px;">오탐(False Positive) 방지를 위해 정상으로 규정된 시스템 활동</div>
        <div id="ontology-baselines-container"></div>
      </div>
      <div class="card">
        <h3 style="font-size: 15px; color: #f87171; margin-bottom: 8px;">🚨 위협 시그널 (Incident Signals)</h3>
        <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 10px;">보안 이벤트 발생 시 분류 및 티켓 생성 기준</div>
        <div id="ontology-signals-container"></div>
      </div>
    </div>

    <!-- SECTION 4: GLOSSARY TERMS -->
    <div class="card">
      <h3 style="font-size: 15px; margin-bottom: 12px; color: #94a3b8;">📚 시맨틱 개체 사전 (7 Semantic Entities & Relationships)</h3>
      <div id="terms-container" class="term-grid"></div>
    </div>
  </section>

  <!-- TAB: WORKLOG -->
  <section id="tab-worklog" class="tab-content">
    <div style="margin-bottom: 16px; display: flex; justify-content: space-between;">
      <h3 style="font-size: 15px; color: #94a3b8;">운영 업무 기록 타임라인</h3>
      <button class="btn btn-secondary btn-sm" onclick="exportWorklog()">WORKLOG.md 동기화</button>
    </div>
    <div id="worklog-container"></div>
  </section>

  <div id="toast" class="toast"></div>

  <!-- MODAL: ADD USER -->
  <div id="user-modal" class="modal-overlay">
    <div class="modal-box">
      <div class="modal-header">
        <h3>➕ 신규 사용자 및 VPN 계정 등록</h3>
        <button onclick="closeUserModal()" style="background: none; border: none; color: #94a3b8; font-size: 18px; cursor: pointer;">✕</button>
      </div>
      <form id="new-user-form" onsubmit="submitNewUser(event)">
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">사용자 ID (Linux 계정명)*</label>
            <input type="text" id="nu-name" class="form-input" placeholder="예: chulsoo" required pattern="[a-z0-9_-]+" title="영문 소문자, 숫자, 하이픈, 언더스코어">
          </div>
          <div class="form-group">
            <label class="form-label">성명 (Full Name)*</label>
            <input type="text" id="nu-fullname" class="form-input" placeholder="예: 김철수" required>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">이메일 주소*</label>
          <input type="email" id="nu-email" class="form-input" placeholder="name@example.com" required>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">역할 (Role)</label>
            <select id="nu-role" class="form-input">
              <option value="student">학생 연구원 (student)</option>
              <option value="admin">서버 관리자 (admin)</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">계정 만료일 (YYYY-MM-DD)</label>
            <input type="date" id="nu-expires" class="form-input" value="2027-01-04">
          </div>
        </div>
        <div class="form-group" style="display: flex; gap: 20px; margin-top: 10px;">
          <label class="form-checkbox">
            <input type="checkbox" id="nu-gpu" checked> RTX 4090 GPU 접근 허용
          </label>
          <label class="form-checkbox">
            <input type="checkbox" id="nu-headscale" checked> Headscale VPN 키 생성
          </label>
        </div>
        <div class="form-group">
          <label class="form-label">연구 목적 / 메모</label>
          <input type="text" id="nu-notes" class="form-input" placeholder="예: VLA 모델 파인튜닝 연구">
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary btn-sm" onclick="closeUserModal()">취소</button>
          <button type="submit" id="nu-submit-btn" class="btn btn-sm">사용자 등록 및 VPN 키 발급</button>
        </div>
      </form>
    </div>
  </div>

  <!-- MODAL: USER PROVISIONED SUCCESS & ONBOARDING PACKAGE -->
  <div id="user-success-modal" class="modal-overlay" style="display: none;">
    <div class="modal-box" style="max-width: 620px;">
      <div class="modal-header">
        <h3>🎉 신규 연구원 인프라 프로비저닝 완료</h3>
        <button onclick="closeSuccessModal()" style="background: none; border: none; color: #94a3b8; font-size: 18px; cursor: pointer;">✕</button>
      </div>
      <div style="margin-top: 10px;">
        <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 14px;">
          신규 계정과 전용 <strong>JupyterLab 컨테이너</strong> 및 <strong>Headscale VPN 키</strong> 생성이 완료되었습니다.<br>
          아래 온보딩 안내문을 복사하여 연구원에게 전달해 주시면 됩니다.
        </p>

        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; margin-bottom: 12px;">
          <div style="font-size: 12px; font-weight: 600; color: #38bdf8; margin-bottom: 6px;">🌐 1. Headscale VPN 접속 명령어</div>
          <pre style="margin: 0; padding: 10px; background: #030712; border-radius: 6px; font-size: 11px; color: #f1f5f9; overflow-x: auto;" id="usm-vpn-cmd"></pre>
        </div>

        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; margin-bottom: 12px;">
          <div style="font-size: 12px; font-weight: 600; color: #34d399; margin-bottom: 6px;">🐳 2. 전용 JupyterLab 접속 URL (PyTorch 24.04 CUDA 12.4)</div>
          <pre style="margin: 0; padding: 10px; background: #030712; border-radius: 6px; font-size: 11px; color: #38bdf8; overflow-x: auto;" id="usm-jupyter-url"></pre>
          <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">
            할당 포트: <strong id="usm-port" style="color: #fff;"></strong> | 컨테이너: <strong id="usm-container" style="color: #fff;"></strong>
          </div>
        </div>

        <div style="background: rgba(255,255,255,0.03); border: 1px solid var(--card-border); border-radius: 8px; padding: 14px; margin-bottom: 12px;">
          <div style="font-size: 12px; font-weight: 600; color: #fbbf24; margin-bottom: 6px;">📁 3. 스토리지 볼륨 경로</div>
          <div style="font-size: 12px; color: #cbd5e1; line-height: 1.5;">
            • 소스코드/개인파일: <code>/workspace</code> (<span id="usm-workspace"></span>)<br>
            • 비디오/체크포인트(대용량): <code>/workspace/data</code> (<span id="usm-data"></span>)
          </div>
        </div>

        <div class="modal-actions" style="margin-top: 18px;">
          <button type="button" class="btn btn-secondary btn-sm" onclick="closeSuccessModal()">닫기</button>
          <button type="button" class="btn btn-sm" style="background: #2563eb; border-color: #3b82f6;" onclick="copyOnboardingTemplate()">📋 학생 전달용 안내문 전체 복사</button>
        </div>
      </div>
    </div>
  </div>

  <!-- MODAL: NEW VPN PREAUTH KEY -->
  <div id="vpn-key-modal" class="modal-overlay" style="display: none;">
    <div class="modal-box">
      <div class="modal-header">
        <h3>🔑 신규 Headscale 사전 인증키 발급</h3>
        <button onclick="closeVpnKeyModal()" style="background: none; border: none; color: #94a3b8; font-size: 18px; cursor: pointer;">✕</button>
      </div>
      <form id="new-vpn-key-form" onsubmit="submitNewVpnKey(event)">
        <div class="form-group">
          <label class="form-label">대상 사용자 (Headscale User / Namespace)</label>
          <select id="nvk-user" class="form-input" required>
            <option value="martin">martin (관리자)</option>
            <option value="student1">student1 (학생 연구원)</option>
            <option value="student2">student2 (학생 연구원)</option>
            <option value="student3">student3 (학생 연구원)</option>
          </select>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">유효 기간 (Expiration)</label>
            <select id="nvk-exp" class="form-input">
              <option value="24h">24시간 (1일, 단기 등록용)</option>
              <option value="168h">7일 (1주일)</option>
              <option value="720h" selected>30일 (1개월, 권장)</option>
              <option value="2160h">90일 (3개월)</option>
              <option value="8760h">1년 (365일)</option>
            </select>
          </div>
          <div class="form-group" style="display: flex; align-items: center; padding-top: 20px;">
            <label class="form-checkbox">
              <input type="checkbox" id="nvk-reusable">
              <span>다회용 키 (Reusable)</span>
            </label>
          </div>
        </div>

        <div id="nvk-result-box" style="display: none; background: #030712; border: 1px solid #10b981; border-radius: 6px; padding: 12px; margin-top: 10px;">
          <div style="font-size: 12px; color: #34d399; font-weight: bold; margin-bottom: 6px;">🎉 신규 인증키가 발급되었습니다!</div>
          <div style="font-size: 11px; color: #cbd5e1; word-break: break-all; font-family: monospace; background: #0b1120; padding: 8px; border-radius: 4px;" id="nvk-key-text"></div>
          <div style="margin-top: 8px; display: flex; gap: 8px;">
            <button type="button" class="btn btn-sm btn-secondary" onclick="copyVpnKeyResult()">📋 키 복사</button>
            <button type="button" class="btn btn-sm" style="background: #2563eb;" onclick="copyVpnOnboardCmd()">📋 전체 접속 명령어 복사</button>
          </div>
        </div>

        <div class="modal-actions" style="margin-top: 18px;">
          <button type="button" class="btn btn-secondary btn-sm" onclick="closeVpnKeyModal()">닫기</button>
          <button type="submit" id="nvk-submit-btn" class="btn btn-sm"><span>⚡</span> 인증키 즉시 발급</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    function showToast(msg, isError = false) {
      const t = document.getElementById('toast');
      t.innerText = msg;
      t.style.borderColor = isError ? '#ef4444' : '#10b981';
      t.style.display = 'block';
      setTimeout(() => { t.style.display = 'none'; }, 3500);
    }

    function switchTab(name) {
      document.querySelectorAll('.tab-btn').forEach(b => {
        b.classList.remove('active');
        const oc = b.getAttribute('onclick') || '';
        if (oc.includes(`'${name}'`)) {
          b.classList.add('active');
        }
      });
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      const target = document.getElementById('tab-' + name);
      if (target) target.classList.add('active');
      if (name === 'gpu') loadGpu();
      if (name === 'storage') loadStorage();
      if (name === 'containers') loadContainers();
      if (name === 'vpn') loadVpn();
      if (name === 'processes') loadProcesses();
      if (name === 'users') loadUsers();
      if (name === 'anomalies') loadAnomalies();
      if (name === 'cve') loadCve();
      if (name === 'memory') loadMemory();
      if (name === 'ontology') loadOntology();
      if (name === 'worklog') loadWorklog();
    }

    function switchGuide(sec) {
      document.querySelectorAll('.sub-tab').forEach(b => {
        b.classList.remove('active');
        b.classList.add('btn-secondary');
      });
      const activeBtn = document.getElementById('gbtn-' + sec);
      if (activeBtn) {
        activeBtn.classList.add('active');
        activeBtn.classList.remove('btn-secondary');
      }
      document.querySelectorAll('.guide-content-sec').forEach(s => s.style.display = 'none');
      const target = document.getElementById('guide-sec-' + sec);
      if (target) target.style.display = 'block';
    }

    function copyCode(btn) {
      const pre = btn.parentElement.querySelector('pre');
      if (!pre) return;
      navigator.clipboard.writeText(pre.innerText.trim()).then(() => {
        showToast('명령어/코드가 클립보드에 복사되었습니다!');
      }).catch(e => {
        alert('복사 실패: ' + e);
      });
    }

    async function fetchAPI(url, options = {}) {
      try {
        const res = await fetch(url, options);
        return await res.json();
      } catch (e) {
        console.error(e);
        return null;
      }
    }

    async function loadStatus() {
      const data = await fetchAPI('/api/status');
      if (data && data.ssh_health) {
        const ssh = data.ssh_health;
        const sshEl = document.getElementById('ssh-health-badge');
        if (sshEl) {
          const map = {
            OK: ['badge-online', 'SSH 2322: 정상'],
            DEGRADED: ['badge-warning', 'SSH 2322: 배너 없음'],
            FIREWALL_BLOCKED: ['badge-danger', 'SSH 2322: 차단(방화벽)'],
            LISTENER_DOWN: ['badge-danger', 'SSH 2322: sshd 미기동'],
            HOST_UNREACHABLE: ['badge-danger', 'SSH 2322: 도달 불가'],
            TAILNET_ONLY: ['badge-warning', 'SSH 2322: LAN만 차단']
          };
          const [cls, label] = map[ssh.state] || ['badge-warning', 'SSH 2322: ' + ssh.state];
          sshEl.className = 'badge ' + cls;
          sshEl.innerText = label;
          sshEl.title = `state=${ssh.state} · last_ok=${ssh.last_ok_str || '없음'} · 연속실패 ${ssh.fail_count}회`;
        }
      }
      if (data) {
        const el = document.getElementById('ontology-status');
        if (data.auto_ontology && data.auto_ontology.connected) {
          el.className = 'badge badge-online';
          el.innerText = 'Auto-Ontology: Connected';
        } else {
          el.className = 'badge badge-local';
          el.innerText = 'Auto-Ontology: Local Fallback';
        }
      }

      const vpnData = await fetchAPI('/api/metrics/vpn');
      const vpnNav = document.getElementById('vpn-nav-count');
      if (vpnData && vpnNav) {
        vpnNav.innerText = `${vpnData.online_nodes}/${vpnData.total_nodes}`;
      }

      const emData = await fetchAPI('/api/emergency/status');
      const lockBtn = document.getElementById('global-lockdown-btn');
      const banner = document.getElementById('global-lockdown-banner');
      if (emData && emData.global_locked) {
        if (lockBtn) {
          lockBtn.innerHTML = '<span>🟢</span> 비상 락다운 해제 (Restore)';
          lockBtn.style.background = '#059669';
          lockBtn.style.borderColor = '#10b981';
        }
        if (banner) banner.style.display = 'flex';
      } else {
        if (lockBtn) {
          lockBtn.innerHTML = '<span>🚨</span> 긴급 전체 차단 (Lockdown)';
          lockBtn.style.background = '#dc2626';
          lockBtn.style.borderColor = '#b91c1c';
        }
        if (banner) banner.style.display = 'none';
      }
    }

    async function loadTickets() {
      const data = await fetchAPI('/api/tickets');
      if (!data) return;
      const container = document.getElementById('tickets-container');
      const pendingTickets = data.filter(t => t.status === 'pending');
      document.getElementById('ticket-count').innerText = pendingTickets.length;

      if (data.length === 0) {
        container.innerHTML = '<div class="card" style="text-align: center; color: var(--text-muted); padding: 40px;">현재 감지된 티켓이 없습니다. 안전한 상태입니다.</div>';
        return;
      }

      container.innerHTML = data.map(t => {
        let triageHtml = '';
        if (t.analysis) {
          try {
            const a = JSON.parse(t.analysis);
            const sevClass = a.severity === 'critical' ? 'critical' : (a.severity === 'warning' ? 'warning' : 'info');
            triageHtml = `
              <div class="triage-box ${sevClass}">
                <div class="triage-meta">
                  <span style="color: ${a.severity === 'critical' ? '#f87171' : '#fbbf24'}; text-transform: uppercase;">● ${a.severity}</span>
                  <span>승인 필요: ${a.needs_approval ? '예 (YES)' : '아니오'}</span>
                  <span>권고 작업: ${a.recommended_action || 'none'}</span>
                  ${(() => { const m = (t.analysis_tags || '').match(/llm:([a-z]+)/); return m ? `<span style="color: #38bdf8;">LLM: ${m[1]}${(t.analysis_tags || '').includes('fallback') ? ' (fallback)' : ''}</span>` : ''; })()}
                </div>
                <div class="triage-summary"><strong>🤖 AI 진단 요약:</strong> ${a.summary}</div>
                ${a.decision_grounds ? `<div style="font-size: 13px; color: #a5f3fc; background: rgba(6,182,212,0.1); border-left: 3px solid #06b6d4; padding: 8px 12px; border-radius: 4px; margin-top: 8px; line-height: 1.5;"><strong>🔍 결정 근거 풀이:</strong> ${a.decision_grounds}</div>` : ''}
                ${a.precedent_match && a.precedent_match !== 'none' ? `<div class="triage-precedent" style="margin-top: 8px;"><strong>과거 선례 매칭:</strong> ${a.precedent_match}</div>` : ''}
              </div>
            `;
          } catch(e) {
            triageHtml = `<div class="triage-box"><div class="triage-summary">${t.analysis}</div></div>`;
          }
        }

        const isPending = t.status === 'pending';
        return `
          <div class="card">
            <div class="ticket-header">
              <div class="ticket-title">
                #${t.id}
                <span class="ticket-category ${t.category}">${t.category}</span>
                <span style="font-size: 13px; color: var(--text-muted); font-weight: normal;">${t.created_str}</span>
              </div>
              <span class="badge ${isPending ? 'badge-local' : 'badge-online'}">${t.status.toUpperCase()}</span>
            </div>
            <div class="evidence-box">${t.evidence}</div>
            ${triageHtml}
            ${t.resolution_note ? `<div style="font-size: 12px; color: #a5b4fc; background: #1e1b4b; padding: 8px 12px; border-radius: 6px; margin-bottom: 10px;"><strong>운영자 메모:</strong> ${t.resolution_note}</div>` : ''}
            <div class="card-actions">
              ${isPending ? `
                <button class="btn btn-secondary btn-sm" onclick="analyzeTicket(${t.id}, this)">🤖 AI 재분석</button>
                <button class="btn btn-secondary btn-sm" onclick="addNote(${t.id})">📝 메모 추가</button>
                <button class="btn btn-sm" onclick="approveTicket(${t.id}, this)">✅ 작업 승인 (${t.action})</button>
              ` : `
                <span style="font-size: 12px; color: #34d399;">승인 완료됨 (${t.action})</span>
              `}
            </div>
          </div>
        `;
      }).join('');
    }

    async function loadGpu() {
      const data = await fetchAPI('/api/metrics/gpu');
      if (!data) return;
      const utilPct = data.utilization_pct || 0;
      const vramUsed = data.vram_used_gb || (data.memory_used_mb ? (data.memory_used_mb / 1024).toFixed(1) : 0);
      const vramTotal = data.vram_total_gb || 24.0;
      const vramPct = Math.round((vramUsed / vramTotal) * 100);

      document.getElementById('gpu-util-val').innerText = utilPct + '%';
      const utilBar = document.getElementById('gpu-util-bar');
      utilBar.style.width = utilPct + '%';
      utilBar.className = 'bar-fill' + (utilPct > 70 ? ' high' : '');

      document.getElementById('gpu-vram-val').innerText = `${vramUsed} / ${vramTotal} GB`;
      const vramBar = document.getElementById('gpu-vram-bar');
      vramBar.style.width = vramPct + '%';
      vramBar.className = 'bar-fill' + (vramPct > 75 ? ' high' : '');

      document.getElementById('gpu-temp-power').innerText = `${data.temperature_c}°C • ${data.power_draw_w}W`;

      const tbody = document.getElementById('gpu-processes-body');
      const procs = data.active_processes || [];
      if (procs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 24px;">✨ 현재 실행 중인 GPU 연산(Compute) 프로세스가 없습니다. (유휴 상태 / 대기 중)</td></tr>';
      } else {
        tbody.innerHTML = procs.map(p => `
          <tr>
            <td><strong style="color: #38bdf8;">${p.user}</strong></td>
            <td>${p.pid}</td>
            <td><code style="font-size: 11px; background: #080c14; padding: 3px 6px; border-radius: 4px;">${p.command}</code></td>
            <td><span style="color: #34d399; font-weight: bold;">${p.vram_allocated_gb ? p.vram_allocated_gb + ' GB' : p.vram_mib + ' MiB'}</span></td>
            <td>${p.compute_util_pct !== undefined ? p.compute_util_pct + '%' : '-'}</td>
            <td style="font-size: 11px; color: var(--text-muted);">${p.started}</td>
          </tr>
        `).join('');
      }
    }

    async function notifyGpuDiscord() {
      if (!confirm('현재 RTX 4090 GPU 실시간 상태 및 이용 에티켓 안내 메시지를 학생 Discord 채널로 발송하시겠습니까?')) return;
      try {
        const res = await postAPI('/api/gpu/discord_notify', {});
        if (res.success) {
          showToast('📢 Discord 학생 채널로 GPU 현황 안내가 성공적으로 전송되었습니다.');
        } else {
          showToast('전송 실패: ' + (res.error || '알 수 없는 오류'), true);
        }
      } catch (e) {
        showToast('전송 오류 발생: ' + e, true);
      }
    }

    async function loadStorage(forceRefresh = false) {
      const url = forceRefresh ? '/api/metrics/storage?refresh=1' : '/api/metrics/storage';
      const data = await fetchAPI(url);
      if (!data) return;

      const summary = data.summary || {};
      const parts = data.partitions || [];
      const rootPart = parts.find(p => p.mount === '/') || {};
      const dataPart = parts.find(p => p.mount === '/mnt/data') || {};

      if (rootPart.mount) {
        document.getElementById('storage-nvme-val').innerText = `${rootPart.used_str} / ${rootPart.total_str}`;
        const nvmeBar = document.getElementById('storage-nvme-bar');
        nvmeBar.style.width = rootPart.percent_used + '%';
        nvmeBar.className = 'bar-fill' + (rootPart.percent_used > 80 ? ' high' : '');
        const nvmePct = document.getElementById('storage-nvme-pct');
        nvmePct.innerText = rootPart.percent_used + '%';
        nvmePct.style.color = rootPart.percent_used > 80 ? '#ef4444' : '#38bdf8';
        document.getElementById('storage-nvme-free').innerText = rootPart.avail_str;
      }

      if (dataPart.mount) {
        document.getElementById('storage-hdd-val').innerText = `${dataPart.used_str} / ${dataPart.total_str}`;
        const hddBar = document.getElementById('storage-hdd-bar');
        hddBar.style.width = dataPart.percent_used + '%';
        hddBar.className = 'bar-fill' + (dataPart.percent_used > 80 ? ' high' : '');
        const hddPct = document.getElementById('storage-hdd-pct');
        hddPct.innerText = dataPart.percent_used + '%';
        hddPct.style.color = dataPart.percent_used > 80 ? '#ef4444' : '#34d399';
        document.getElementById('storage-hdd-free').innerText = dataPart.avail_str;
      }

      document.getElementById('storage-users-total').innerText = summary.total_users_used_str || '0 B';
      document.getElementById('storage-top-user').innerText = summary.top_user || '-';
      const healthEl = document.getElementById('storage-health-val');
      if (summary.storage_health && summary.storage_health.includes('Warning')) {
        healthEl.innerText = '경고 (Warning)';
        healthEl.style.color = '#fbbf24';
      } else {
        healthEl.innerText = summary.storage_health || '정상 (Healthy)';
        healthEl.style.color = '#10b981';
      }

      // Render Partitions Table
      const partBody = document.getElementById('partitions-table-body');
      partBody.innerHTML = parts.map(p => {
        const isHigh = p.percent_used > 80;
        const badge = isHigh 
          ? '<span class="badge" style="background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444;">용량 부족 주의</span>'
          : '<span class="badge badge-online">정상</span>';
        return `
          <tr>
            <td><code style="font-size: 11px; color: #38bdf8;">${p.filesystem}</code></td>
            <td><strong style="color: #f8fafc;">${p.mount}</strong></td>
            <td style="font-size: 12px; color: var(--text-muted);">${p.name || '-'}</td>
            <td>${p.total_str}</td>
            <td><strong style="color: ${isHigh ? '#ef4444' : '#f8fafc'};">${p.used_str}</strong></td>
            <td style="color: #34d399;">${p.avail_str}</td>
            <td>
              <div style="display: flex; align-items: center; gap: 8px;">
                <div class="bar-wrap" style="width: 80px; margin: 0;"><div class="bar-fill ${isHigh ? 'high' : ''}" style="width: ${p.percent_used}%;"></div></div>
                <span style="font-size: 12px; font-weight: bold;">${p.percent_used}%</span>
              </div>
            </td>
            <td>${badge}</td>
          </tr>
        `;
      }).join('');

      // Render Users Storage Table
      const usersBody = document.getElementById('storage-users-table-body');
      const users = data.users_storage || [];
      usersBody.innerHTML = users.map(u => {
        let statusBadge = '<span class="badge badge-online">정상</span>';
        if (u.status === 'exceeded') {
          statusBadge = '<span class="badge" style="background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444;">한도 초과</span>';
        } else if (u.status === 'warning') {
          statusBadge = '<span class="badge" style="background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid #f59e0b;">주의 (80% 이상)</span>';
        }

        const roleColor = u.role === 'admin' ? '#c084fc' : '#38bdf8';
        const quotaText = u.role === 'admin' ? '무제한 (Admin)' : `Home ${u.home_soft_limit_str} / Data ${u.data_soft_limit_str}`;
        const pctWidth = Math.min(100, Math.max(2, Math.round((u.total_bytes / (2 * 1024 * 1024 * 1024 * 1024)) * 100)));

        return `
          <tr>
            <td><strong style="color: ${roleColor};">${u.username}</strong></td>
            <td>${u.full_name}</td>
            <td><span class="badge" style="background: #1e1b4b; color: ${roleColor};">${u.role}</span></td>
            <td><code style="font-size: 12px;">${u.home_str}</code></td>
            <td><code style="font-size: 12px; color: #a5f3fc;">${u.data_str}</code></td>
            <td><strong style="color: #f8fafc; font-size: 13px;">${u.total_str}</strong></td>
            <td>
              <div style="display: flex; align-items: center; gap: 8px;">
                <div class="bar-wrap" style="width: 70px; margin: 0;"><div class="bar-fill" style="width: ${pctWidth}%;"></div></div>
                <span style="font-size: 11px; color: var(--text-muted);">${u.total_str}</span>
              </div>
            </td>
            <td style="font-size: 12px; color: var(--text-muted);">${quotaText}</td>
            <td>${statusBadge}</td>
          </tr>
        `;
      }).join('');
    }

    async function loadThermals() {
      const data = await fetchAPI('/api/metrics/thermals');
      if (!data) return;
      const nvme = data.nvme || {};
      const cpu = data.cpu || {};

      const hBadge = document.getElementById('nvme-header-badge');
      if (hBadge && nvme.temp_c !== undefined) {
        hBadge.innerText = `NVMe: ${nvme.temp_c}°C`;
        if (nvme.status === 'critical') {
          hBadge.style.color = '#f87171';
          hBadge.style.borderColor = '#ef4444';
          hBadge.style.background = 'rgba(239,68,68,0.2)';
        } else if (nvme.status === 'warning') {
          hBadge.style.color = '#fbbf24';
          hBadge.style.borderColor = '#f59e0b';
          hBadge.style.background = 'rgba(245,158,11,0.2)';
        } else {
          hBadge.style.color = '#34d399';
          hBadge.style.borderColor = '#10b981';
          hBadge.style.background = 'rgba(16,185,129,0.15)';
        }
      }

      const nvmeCard = document.getElementById('cnt-nvme-val');
      if (nvmeCard && nvme.temp_c !== undefined) {
        nvmeCard.innerText = `${nvme.temp_c}°C`;
        nvmeCard.style.color = nvme.status === 'critical' ? '#ef4444' : (nvme.status === 'warning' ? '#fbbf24' : '#10b981');
      }

      const cpuCard = document.getElementById('cnt-cpu-val');
      if (cpuCard && cpu.temp_c !== undefined) {
        cpuCard.innerText = `${cpu.temp_c}°C`;
      }
    }

    async function loadContainers() {
      loadThermals();
      const conts = await fetchAPI('/api/metrics/containers');
      if (!conts) return;

      const runningCount = conts.filter(c => c.state === 'running').length;
      document.getElementById('cnt-running-val').innerText = `${runningCount} / ${conts.length}`;

      const tbody = document.getElementById('containers-table-body');
      if (conts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">등록된 컨테이너가 없습니다.</td></tr>';
        return;
      }

      tbody.innerHTML = conts.map(c => {
        const isRunning = c.state === 'running';
        const stateBadge = isRunning
          ? '<span class="badge badge-online">🟢 Running</span>'
          : '<span class="badge badge-local" style="background: rgba(148,163,184,0.15); color: #94a3b8; border: 1px solid #475569;">⚪ Exited</span>';

        const roleColor = c.tenant === 'admin' ? '#c084fc' : (c.tenant === 'shared' ? '#94a3b8' : '#38bdf8');
        const isJupyter = c.is_jupyter;

        return `
          <tr>
            <td>
              <strong style="color: ${isJupyter ? '#38bdf8' : '#f8fafc'};">${c.name}</strong>
              ${isJupyter ? '<span class="badge" style="margin-left: 6px; background: #1e1b4b; color: #a5b4fc; font-size: 10px;">JupyterLab</span>' : ''}
            </td>
            <td><span class="badge" style="background: #1e1b4b; color: ${roleColor};">${c.tenant}</span></td>
            <td>${stateBadge}</td>
            <td style="font-size: 12px; color: var(--text-muted);">${c.status}</td>
            <td><code style="font-size: 11px; background: #080c14; padding: 2px 6px; border-radius: 4px;">${c.ports || '-'}</code></td>
            <td style="font-size: 11px; color: #94a3b8; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${c.image}</td>
            <td>
              <div style="display: flex; gap: 6px;">
                ${isRunning ? `
                  <button class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 11px;" onclick="controlContainer('${c.name}', 'restart')">🔄 재시작</button>
                  <button class="btn btn-secondary btn-sm" style="color: #f87171; border-color: #ef4444; padding: 2px 8px; font-size: 11px;" onclick="controlContainer('${c.name}', 'stop')">⏹️ 중지</button>
                ` : `
                  <button class="btn btn-sm" style="background: #059669; padding: 2px 8px; font-size: 11px;" onclick="controlContainer('${c.name}', 'start')">▶️ 시작</button>
                `}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    async function controlContainer(name, action) {
      if (!confirm(`컨테이너 '${name}'에 '${action}' 명령을 실행하시겠습니까?`)) return;
      const res = await fetchAPI('/api/containers/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, action })
      });
      if (res && res.success) {
        showToast(res.message);
        loadContainers();
      } else {
        alert('제어 실패: ' + (res ? (res.error || res.message) : '오류'));
      }
    }

    let vpnNodesData = [];
    let latestGeneratedKey = null;

    async function loadVpn() {
      const data = await fetchAPI('/api/metrics/vpn');
      if (!data) return;

      document.getElementById('vpn-total-nodes').innerText = data.total_nodes;
      document.getElementById('vpn-online-nodes').innerText = data.online_nodes;
      document.getElementById('vpn-offline-nodes').innerText = data.offline_nodes;
      document.getElementById('vpn-total-users').innerText = `${data.total_users}개`;
      document.getElementById('vpn-active-keys').innerText = `${data.active_keys}개`;

      const navCount = document.getElementById('vpn-nav-count');
      if (navCount) navCount.innerText = `${data.online_nodes}/${data.total_nodes}`;

      if (data.users && data.users.length) {
        document.getElementById('vpn-users-summary').innerText = data.users.map(u => u.name).join(', ');
      }

      vpnNodesData = data.nodes || [];
      renderVpnNodes(vpnNodesData);
      renderVpnKeys(data.keys || []);
      renderVpnAcl(data.acl || {});
    }

    function renderVpnAcl(acl) {
      const tbody = document.getElementById('vpn-acl-tbody');
      if (!tbody) return;
      const rules = (acl && acl.rules) || [];
      if (!rules.length) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 14px;">설정된 ACL 규칙이 없습니다.</td></tr>';
        return;
      }
      tbody.innerHTML = rules.map(r => `
        <tr>
          <td><strong style="color: #f8fafc;">${r.group}</strong></td>
          <td><span style="color: #cbd5e1; font-size: 12px;">${r.users}</span></td>
          <td><code style="font-size: 11px; background: #080c14; padding: 3px 8px; border-radius: 4px; color: #38bdf8;">${r.dst}</code></td>
          <td style="font-size: 12px; color: #cbd5e1;">${r.visibility}</td>
          <td><span class="badge ${r.badge}" style="font-size: 11px;">${r.isolation}</span></td>
        </tr>
      `).join('');
    }

    function renderVpnNodes(nodes) {
      const tbody = document.getElementById('vpn-nodes-tbody');
      if (!tbody) return;
      if (!nodes.length) {
        tbody.innerHTML = '<tr><td colspan="10" style="text-align: center; color: var(--text-muted); padding: 20px;">등록된 VPN 노드가 없습니다.</td></tr>';
        return;
      }
      tbody.innerHTML = nodes.map(n => {
        const isOnline = n.online;
        const onlineBadge = isOnline
          ? '<span class="badge badge-online">🟢 온라인</span>'
          : '<span class="badge" style="background: rgba(148,163,184,0.15); color: #94a3b8; border: 1px solid #475569;">⚪ 오프라인</span>';

        return `
          <tr>
            <td style="font-weight: bold; color: var(--text-muted);">#${n.id}</td>
            <td>
              <strong style="color: #f8fafc; font-size: 13px;">${n.name}</strong>
              ${n.given_name ? `<div style="font-size: 11px; color: #a5b4fc; font-family: monospace;">(${n.given_name})</div>` : ''}
            </td>
            <td>
              <span class="badge" style="background: #1e1b4b; color: ${n.user === 'martin' ? '#c084fc' : '#38bdf8'};">${n.user}</span>
            </td>
            <td>
              <code style="font-size: 12px; color: #38bdf8;">${n.ipv4}</code>
              <button class="btn btn-secondary btn-sm" style="padding: 1px 5px; font-size: 10px; margin-left: 4px;" onclick="copyText('${n.ipv4}', 'IP 복사 완료')">📋</button>
            </td>
            <td>
              <span class="badge" style="color: ${n.os_color}; border: 1px solid rgba(255,255,255,0.15);">
                ${n.os_icon} ${n.os}
              </span>
              ${n.os_detail ? `<div style="font-size: 10px; color: #94a3b8; margin-top: 3px;">${n.os_detail}</div>` : ''}
              ${n.client_version ? `<div style="font-size: 9px; color: #64748b; font-family: monospace;">ts ${n.client_version.split('-')[0]}</div>` : ''}
            </td>
            <td>${onlineBadge}</td>
            <td style="font-size: 12px; color: #cbd5e1;">
              <div>${n.last_seen_rel}</div>
              <div style="font-size: 10px; color: var(--text-muted);">${n.last_seen}</div>
            </td>
            <td style="font-size: 11px;">
              <span class="badge" style="${n.acl_type === 'admin' ? 'background: rgba(168,85,247,0.15); color: #c084fc; border: 1px solid #a855f7;' : 'background: rgba(56,189,248,0.15); color: #38bdf8; border: 1px solid #0284c7;'}">
                ${n.acl_scope || '미지정'}
              </span>
              <div style="font-size: 10px; color: ${n.acl_type === 'admin' ? '#94a3b8' : '#34d399'}; margin-top: 2px;">
                ${n.acl_note || ''}
              </div>
            </td>
            <td style="font-size: 11px; color: ${n.is_expired ? '#f87171' : 'var(--text-muted)'};">
              ${n.is_expired ? '⏰ 만료됨' : (n.expiry !== '-' ? n.expiry : '영구/무제한')}
            </td>
            <td>
              <div style="display: flex; gap: 4px;">
                <button class="btn btn-secondary btn-sm" style="padding: 2px 7px; font-size: 11px; color: #fbbf24; border-color: #d97706;" onclick="expireVpnNode(${n.id}, '${n.name}')" title="세션을 강제 만료하여 연결을 즉시 차단합니다.">
                  🚫 만료
                </button>
                <button class="btn btn-secondary btn-sm" style="padding: 2px 7px; font-size: 11px; color: #f87171; border-color: #ef4444;" onclick="deleteVpnNode(${n.id}, '${n.name}')" title="Headscale 레지스트리에서 완전히 삭제합니다.">
                  🗑 삭제
                </button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    function renderVpnKeys(keys) {
      const tbody = document.getElementById('vpn-keys-tbody');
      if (!tbody) return;
      if (!keys.length) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">발급된 사전 인증키가 없습니다.</td></tr>';
        return;
      }
      tbody.innerHTML = keys.map(k => {
        const isAct = k.status === 'active';
        const typeBadge = k.reusable
          ? '<span class="badge" style="background: rgba(56,189,248,0.15); color: #38bdf8; border: 1px solid #0284c7;">다회용 (Reusable)</span>'
          : '<span class="badge" style="background: rgba(148,163,184,0.15); color: #94a3b8; border: 1px solid #475569;">1회용 (One-off)</span>';

        let statusBadge = `<span class="badge badge-online">${k.status_label}</span>`;
        if (k.status === 'expired') {
          statusBadge = `<span class="badge" style="background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid #ef4444;">${k.status_label}</span>`;
        } else if (k.status === 'used') {
          statusBadge = `<span class="badge" style="background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid #f59e0b;">${k.status_label}</span>`;
        }

        const cmd = `tailscale up --login-server http://100.64.0.1:8080 --authkey ${k.key}`;

        return `
          <tr>
            <td style="font-weight: bold; color: var(--text-muted);">#${k.id}</td>
            <td><strong style="color: #c084fc;">${k.user}</strong></td>
            <td>
              <code style="font-size: 11px; background: #080c14; padding: 2px 6px; border-radius: 4px; color: #a5f3fc;">${k.key}</code>
            </td>
            <td>${typeBadge}</td>
            <td>${statusBadge}</td>
            <td style="font-size: 11px; color: #cbd5e1;">${k.expiration}</td>
            <td style="font-size: 11px; color: var(--text-muted);">${k.created_at}</td>
            <td>
              <div style="display: flex; gap: 4px;">
                <button class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 11px;" onclick="copyText('${cmd}', 'Tailscale 접속 명령어가 복사되었습니다!')" title="접속 커맨드 복사">
                  📋 온보딩 복사
                </button>
                ${isAct ? `
                  <button class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 11px; color: #f87171; border-color: #ef4444;" onclick="expireVpnKey('${k.key}')" title="이 키를 즉시 만료시킵니다">
                    ⏹ 만료
                  </button>
                ` : ''}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    function filterVpnNodes(query) {
      const q = (query || '').toLowerCase().trim();
      if (!q) {
        renderVpnNodes(vpnNodesData);
        return;
      }
      const filtered = vpnNodesData.filter(n =>
        (n.name && n.name.toLowerCase().includes(q)) ||
        (n.given_name && n.given_name.toLowerCase().includes(q)) ||
        (n.user && n.user.toLowerCase().includes(q)) ||
        (n.ipv4 && n.ipv4.includes(q)) ||
        (n.os && n.os.toLowerCase().includes(q))
      );
      renderVpnNodes(filtered);
    }

    function openVpnKeyModal() {
      document.getElementById('vpn-key-modal').style.display = 'flex';
      document.getElementById('nvk-result-box').style.display = 'none';
      latestGeneratedKey = null;
    }

    function closeVpnKeyModal() {
      document.getElementById('vpn-key-modal').style.display = 'none';
      document.getElementById('new-vpn-key-form').reset();
      document.getElementById('nvk-exp').value = '720h';
      document.getElementById('nvk-result-box').style.display = 'none';
      latestGeneratedKey = null;
    }

    async function submitNewVpnKey(e) {
      e.preventDefault();
      const btn = document.getElementById('nvk-submit-btn');
      btn.disabled = true;
      const orig = btn.innerHTML;
      btn.innerHTML = '<span class="spinner"></span> 발급 중...';

      const payload = {
        username: document.getElementById('nvk-user').value,
        expiration: document.getElementById('nvk-exp').value,
        reusable: document.getElementById('nvk-reusable').checked
      };

      const res = await fetchAPI('/api/vpn/key/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      btn.disabled = false;
      btn.innerHTML = orig;

      if (res && res.success) {
        latestGeneratedKey = res;
        document.getElementById('nvk-key-text').innerText = res.key;
        document.getElementById('nvk-result-box').style.display = 'block';
        showToast(`'${payload.username}' 사전 인증키 발급 성공!`);
        loadVpn();
      } else {
        alert('인증키 발급 실패: ' + (res ? res.error : '알 수 없는 오류'));
      }
    }

    function copyVpnKeyResult() {
      if (!latestGeneratedKey) return;
      copyText(latestGeneratedKey.key, '인증키가 복사되었습니다!');
    }

    function copyVpnOnboardCmd() {
      if (!latestGeneratedKey) return;
      copyText(latestGeneratedKey.onboard_cmd, 'Tailscale 접속 명령어가 복사되었습니다!');
    }

    async function expireVpnNode(id, name) {
      if (!confirm(`노드 #${id} ('${name}')의 VPN 세션을 강제 만료(접속 차단)하시겠습니까?`)) return;
      const res = await fetchAPI('/api/vpn/node/expire', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_id: id })
      });
      if (res && res.success) {
        showToast(res.message);
        loadVpn();
      } else {
        alert('만료 실패: ' + (res ? res.error : '오류'));
      }
    }

    async function deleteVpnNode(id, name) {
      if (!confirm(`🚨 노드 #${id} ('${name}')를 Headscale 레지스트리에서 완전히 삭제하시겠습니까?\n이 기기는 재등록할 때까지 통신이 불가능합니다.`)) return;
      const res = await fetchAPI('/api/vpn/node/delete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ node_id: id })
      });
      if (res && res.success) {
        showToast(res.message);
        loadVpn();
      } else {
        alert('삭제 실패: ' + (res ? res.error : '오류'));
      }
    }

    async function expireVpnKey(key) {
      if (!confirm(`이 사전 인증키를 즉시 만료하시겠습니까?\n이 키로는 더 이상 신규 기기를 등록할 수 없습니다.`)) return;
      const res = await fetchAPI('/api/vpn/key/expire', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: key })
      });
      if (res && res.success) {
        showToast(res.message);
        loadVpn();
      } else {
        alert('만료 실패: ' + (res ? res.error : '오류'));
      }
    }

    async function loadProcesses() {
      const data = await fetchAPI('/api/metrics/processes');
      if (!data) return;
      document.getElementById('proc-total-count').innerText = data.total_count || 0;
      const anomCount = data.anomalies_count || 0;
      const anomBadge = document.getElementById('proc-anomaly-count');
      anomBadge.innerText = anomCount;
      anomBadge.style.color = anomCount > 0 ? '#ef4444' : '#10b981';

      const anomCard = document.getElementById('proc-anomalies-card');
      const anomBody = document.getElementById('proc-anomalies-body');
      if (anomCount > 0) {
        anomCard.style.display = 'block';
        anomBody.innerHTML = (data.anomalies || []).map(a => `
          <div style="background: rgba(239,68,68,0.12); border: 1px solid #ef4444; border-radius: 8px; padding: 12px; margin-bottom: 10px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
              <strong style="color: #f87171;">🚨 PID ${a.pid} (사용자: ${a.user}) — ${a.severity.toUpperCase()}</strong>
              <span class="badge" style="background: #450a0a; color: #fca5a5;">${a.type}</span>
            </div>
            <div style="font-size: 13px; color: #fecaca; margin-bottom: 6px;">${a.description}</div>
            <code style="font-size: 11px; background: #080c14; padding: 4px 8px; border-radius: 4px; color: #cbd5e1; display: block; word-break: break-all;">${a.command}</code>
          </div>
        `).join('');
      } else {
        anomCard.style.display = 'none';
      }

      const tbody = document.getElementById('processes-table-body');
      tbody.innerHTML = (data.top_processes || []).map(p => {
        let badge = '<span class="badge badge-online">정상</span>';
        if (p.severity === 'critical') {
          badge = `<span class="badge" style="background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444;">🚨 이상 감지</span>`;
        } else if (p.severity === 'warning') {
          badge = `<span class="badge" style="background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid #f59e0b;">⚠️ 주의</span>`;
        }
        return `
          <tr>
            <td><strong style="color: ${p.user === 'root' ? '#94a3b8' : '#38bdf8'};">${p.user}</strong></td>
            <td>${p.pid}</td>
            <td><strong style="color: ${p.cpu > 50 ? '#ef4444' : '#34d399'};">${p.cpu}%</strong></td>
            <td>${p.mem}%</td>
            <td><code style="font-size: 11px;">${p.stat}</code></td>
            <td>
              <code style="font-size: 11px; background: #080c14; padding: 3px 6px; border-radius: 4px; display: inline-block; max-width: 480px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${p.full_command}</code>
              ${p.anomaly_reasons && p.anomaly_reasons.length ? `<div style="font-size: 11px; color: #f87171; margin-top: 4px;">⚠️ ${p.anomaly_reasons.join(', ')}</div>` : ''}
            </td>
            <td>${badge}</td>
          </tr>
        `;
      }).join('');
    }

    async function loadUsers() {
      const data = await fetchAPI('/api/metrics/users');
      if (!data) return;

      let regCount = 0;
      let runCount = 0;
      let minPort = 99999, maxPort = 0;
      data.forEach(u => {
        if (u.jupyter_registered) {
          regCount++;
          if (u.jupyter_state === 'running') runCount++;
          if (u.jupyter_port) {
            if (u.jupyter_port < minPort) minPort = u.jupyter_port;
            if (u.jupyter_port > maxPort) maxPort = u.jupyter_port;
          }
        }
      });
      const regEl = document.getElementById('u-jup-reg-count');
      if (regEl) regEl.innerText = regCount;
      const runEl = document.getElementById('u-jup-run-count');
      if (runEl) runEl.innerText = runCount;
      const portRangeEl = document.getElementById('u-jup-port-range');
      if (portRangeEl && maxPort > 0) {
        portRangeEl.innerText = `${minPort} ~ ${maxPort}`;
      }

      const tbody = document.getElementById('users-table-body');
      tbody.innerHTML = data.map(u => {
        const isLocked = u.state === 'locked';
        const hasFindings = u.security_findings_count > 0;
        const isChangedEndpoint = u.endpoint_is_baseline === false;

        let hsBadge = '';
        if (u.headscale_status === 'registered') {
          hsBadge = `<span class="badge badge-online">${u.headscale_label || '✅ 등록됨'}</span>`;
        } else if (u.headscale_status === 'pending') {
          hsBadge = `<span class="badge" style="background: rgba(14,165,233,0.18); color: #38bdf8; border: 1px solid #0284c7;">${u.headscale_label || '🔑 키 발급 (대기)'}</span>`;
        } else {
          hsBadge = `<span class="badge" style="background: rgba(239,68,68,0.18); color: #f87171; border: 1px solid #ef4444;">${u.headscale_label || '❌ 미등록'}</span>`;
        }

        let emergencyActions = '';
        if (u.role === 'admin') {
          emergencyActions = '<span style="color: #94a3b8; font-size: 11px;">관리자 계정 보호</span>';
        } else if (isLocked) {
          emergencyActions = `
            <button class="btn btn-secondary btn-sm" style="color: #34d399; border-color: #059669; padding: 3px 8px; font-size: 11px;" onclick="unblockUser('${u.name}')">🟢 차단 해제</button>
          `;
        } else {
          emergencyActions = `
            <div style="display: flex; gap: 4px;">
              <button class="btn btn-sm" style="background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; padding: 3px 8px; font-size: 11px;" onclick="emergencyBlockUser('${u.name}')" title="계정 잠금 + 세션 강제종료 + VPN 차단">🚫 긴급 차단</button>
              <button class="btn btn-secondary btn-sm" style="color: #fbbf24; border-color: #d97706; padding: 3px 8px; font-size: 11px;" onclick="emergencyNetworkBlock('${u.name}')" title="VPN 네트워크 접근만 격리 (파일 보존)">🔌 VPN 격리</button>
            </div>
          `;
        }

        let jupyterCell = '';
        if (u.jupyter_registered) {
          const isRunning = u.jupyter_state === 'running';
          const isExited = u.jupyter_state === 'exited';
          let stateBadge = '';
          if (isRunning) {
            stateBadge = `<span class="badge badge-online" style="font-size: 10px; padding: 2px 6px;">🟢 실행 중 (:${u.jupyter_port})</span>`;
          } else if (isExited) {
            stateBadge = `<span class="badge" style="background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid #f59e0b; font-size: 10px; padding: 2px 6px;">⏸️ 중지됨 (:${u.jupyter_port})</span>`;
          } else {
            stateBadge = `<span class="badge" style="background: rgba(148,163,184,0.15); color: #94a3b8; border: 1px solid #475569; font-size: 10px; padding: 2px 6px;">⚪ 등록됨 (:${u.jupyter_port})</span>`;
          }

          jupyterCell = `
            <div style="display: flex; flex-direction: column; gap: 4px; min-width: 175px;">
              <div style="display: flex; align-items: center; justify-content: space-between; gap: 6px;">
                <span style="font-family: monospace; font-size: 11px; color: #38bdf8; font-weight: 600;">${u.jupyter_container_name}</span>
                ${stateBadge}
              </div>
              <div style="display: flex; gap: 4px; align-items: center; flex-wrap: wrap; margin-top: 2px;">
                ${u.jupyter_url ? `
                  <a href="${u.jupyter_url}" target="_blank" class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 10px; text-decoration: none; color: #38bdf8; border-color: #0284c7;" title="VPN 가상 IP(100.64.0.1) 주피터랩 브라우저 접속">
                    🔗 열기 ↗
                  </a>
                  <button class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 10px;" onclick="copyJupyterLink('${u.jupyter_url}', '${u.name}')" title="접속 URL 및 토큰 클립보드 복사">
                    📋 복사
                  </button>
                ` : ''}
                ${isRunning ? `
                  <button class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 10px; color: #f87171; border-color: #ef4444;" onclick="controlUserJupyter('${u.jupyter_container_name}', 'stop', this)" title="컨테이너 일시 중지 (VRAM 반납)">
                    ⏹ 정지
                  </button>
                ` : `
                  <button class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 10px; color: #34d399; border-color: #059669;" onclick="controlUserJupyter('${u.jupyter_container_name}', 'start', this)" title="컨테이너 즉시 시작">
                    ▶ 기동
                  </button>
                `}
              </div>
            </div>
          `;
        } else {
          jupyterCell = `
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; min-width: 150px;">
              <span class="badge" style="background: rgba(239,68,68,0.12); color: #f87171; border: 1px solid #ef4444; font-size: 10px; padding: 2px 6px;">❌ 미등록</span>
              <button class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 10px; color: #38bdf8; border-color: #0284c7;" onclick="provisionUserJupyter('${u.name}', this)" title="해당 연구원 전용 도커 컨테이너 및 포트 즉시 등록">
                ➕ 프로비저닝
              </button>
            </div>
          `;
        }

        return `
          <tr>
            <td><strong>${u.name}</strong></td>
            <td>${u.full_name}</td>
            <td><span class="badge ${u.role === 'admin' ? 'badge-model' : 'badge-local'}">${u.role}</span></td>
            <td><span class="badge ${isLocked ? 'badge-local' : 'badge-online'}">${u.state}</span></td>
            <td>${hsBadge}</td>
            <td>
              <strong>${u.endpoint_machine}</strong>
              <div style="font-size: 11px; color: #a5b4fc;">OS: ${u.endpoint_os}</div>
              ${u.endpoint_os_detail && u.endpoint_os_detail !== '-' ? `<div style="font-size: 10px; color: #94a3b8;">${u.endpoint_os_detail}</div>` : ''}
            </td>
            <td style="font-size: 12px; font-family: monospace;">${u.endpoint_ip}</td>
            <td>${u.gpu_allowed ? '✅ 허용' : '❌ 제한'}</td>
            <td>${jupyterCell}</td>
            <td style="font-size: 11px; color: var(--text-muted);">${u.expires || '영구/미지정'}</td>
            <td>
              ${isChangedEndpoint ? `<span class="badge" style="background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444; margin-bottom: 4px;">⚠️ PC 변경 감지</span><br>` : ''}
              ${hasFindings ? `<span style="color: #ef4444; font-weight: bold; font-size: 11px;">⚠️ 이상징후 ${u.security_findings_count}건</span>` : '<span style="color: #10b981; font-size: 11px;">정상 (0)</span>'}
            </td>
            <td>${emergencyActions}</td>
          </tr>
        `;
      }).join('');
    }

    function openUserModal() {
      document.getElementById('user-modal').style.display = 'flex';
      document.getElementById('nu-name').focus();
    }

    function closeUserModal() {
      document.getElementById('user-modal').style.display = 'none';
      document.getElementById('new-user-form').reset();
      document.getElementById('nu-expires').value = '2027-01-04';
      document.getElementById('nu-gpu').checked = true;
      document.getElementById('nu-headscale').checked = true;
    }

    let currentOnboardingInfo = null;

    function closeSuccessModal() {
      document.getElementById('user-success-modal').style.display = 'none';
      currentOnboardingInfo = null;
    }

    function copyOnboardingTemplate() {
      const info = currentOnboardingInfo || {
        full_name: '신규',
        name: '<username>',
        headscale_key: '<PRE_AUTH_KEY>',
        jupyter_url: 'http://100.64.0.2:<PORT>/?token=<TOKEN>',
        container_name: '<username>_jupyter',
        jupyter_port: '<PORT>'
      };
      const text = `[martin-B650M-K] 연구실 GPU 인프라 온보딩 안내
--------------------------------------------------
안녕하세요, ${info.full_name} 연구원님!
연구실 공유 RTX 4090 서버에 접속할 수 있는 계정 정보입니다.

1. Headscale VPN 연결 (사설망 100.64.0.0/10):
   tailscale up --login-server http://100.64.0.1:8080 --authkey ${info.headscale_key || '(관리자 문의)'}

2. 본인 전용 JupyterLab (PyTorch 24.04 CUDA 12.4):
   - 접속 URL: ${info.jupyter_url || 'http://100.64.0.2:' + (info.jupyter_port || '8888')}
   - 컨테이너: ${info.container_name || info.name + '_jupyter'} (포트: ${info.jupyter_port || '8888+'})

3. 기본 시작 폴더 및 스토리지 안내:
   - 기본 작업공간 (JupyterLab 루트): /workspace (대용량 8TB 스토리지 /mnt/data/users/${info.name})
     * 모든 연구 노트북, 대용량 비디오/LLM 데이터셋 및 체크포인트는 여기에 자동 저장됩니다.
   - 개인 홈 디렉토리: /workspace/home (호스트 /home/${info.name})
     * 개인 dotfiles, git repo 등 설정 파일 접근 시 사용합니다.

4. 필수 연구 에티켓:
   - 실험 종료 시 반드시 'Kernel -> Shut Down All Kernels'로 VRAM(24GB)을 반납해 주세요.
   - 8B LLM 학습 시 4-bit QLoRA 또는 DeepSpeed ZeRO-2 CPU-offload를 적용하세요.
--------------------------------------------------`;
      navigator.clipboard.writeText(text).then(() => {
        showToast('온보딩 안내문이 클립보드에 복사되었습니다!');
      }).catch(e => {
        alert('복사 실패: ' + e);
      });
    }

    async function submitNewUser(e) {
      e.preventDefault();
      const btn = document.getElementById('nu-submit-btn');
      btn.disabled = true;
      const orig = btn.innerText;
      btn.innerHTML = '<span class="spinner"></span> 등록 및 컨테이너 프로비저닝 중...';

      const payload = {
        name: document.getElementById('nu-name').value.trim(),
        full_name: document.getElementById('nu-fullname').value.trim(),
        email: document.getElementById('nu-email').value.trim(),
        role: document.getElementById('nu-role').value,
        expires: document.getElementById('nu-expires').value,
        gpu: document.getElementById('nu-gpu').checked,
        headscale: document.getElementById('nu-headscale').checked,
        notes: document.getElementById('nu-notes').value.trim()
      };

      const res = await fetchAPI('/api/users/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      btn.disabled = false;
      btn.innerText = orig;

      if (res && res.success) {
        closeUserModal();
        currentOnboardingInfo = res;

        // Populate success modal fields
        document.getElementById('usm-vpn-cmd').innerText = res.vpn_command || `tailscale up --login-server http://100.64.0.1:8080 --authkey ${res.headscale_key}`;
        document.getElementById('usm-jupyter-url').innerText = res.jupyter_url || `http://100.64.0.1:${res.jupyter_port || '8888'}`;
        document.getElementById('usm-port').innerText = res.jupyter_port ? `:${res.jupyter_port}` : 'N/A';
        document.getElementById('usm-container').innerText = res.container_name || `${res.name}_jupyter`;
        document.getElementById('usm-workspace').innerText = res.workspace || `/home/${res.name}`;
        document.getElementById('usm-data').innerText = res.data_dir || `/mnt/data/users/${res.name}`;

        document.getElementById('user-success-modal').style.display = 'flex';
        showToast(`사용자 '${payload.name}' (${payload.full_name}) 등록 및 프로비저닝 완료!`);
        loadUsers();
      } else {
        alert('사용자 등록 실패: ' + (res ? res.error : '알 수 없는 오류'));
      }
    }

    async function emergencyBlockUser(name) {
      const reason = prompt(`🚨 [긴급 차단] 사용자 '${name}'의 계정, 실행 프로세스, Headscale VPN을 전면 차단하시겠습니까?\n차단 사유를 입력하세요:`, '보안 침해사고 의심에 따른 긴급 격리');
      if (!reason) return;
      const res = await fetchAPI('/api/emergency/user-block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: name, reason: reason })
      });
      if (res && res.success) {
        showToast(`사용자 '${name}' 긴급 차단 완료!`);
        loadUsers();
      } else {
        alert('차단 실패: ' + (res ? (res.error || res.message) : '알 수 없는 오류'));
      }
    }

    async function emergencyNetworkBlock(name) {
      if (!confirm(`🔌 사용자 '${name}'의 Headscale VPN 및 SSH 네트워크 접근을 즉시 격리하시겠습니까?\n(로컬 계정 및 데이터는 보존됩니다.)`)) return;
      const res = await fetchAPI('/api/emergency/network-block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: name, reason: '비정상 접속에 따른 네트워크 접근 격리' })
      });
      if (res && res.success) {
        showToast(`사용자 '${name}' VPN 네트워크 격리 완료!`);
        loadUsers();
      } else {
        alert('격리 실패: ' + (res ? (res.error || res.message) : '알 수 없는 오류'));
      }
    }

    async function unblockUser(name) {
      if (!confirm(`🟢 사용자 '${name}'의 차단을 해제하고 계정 및 VPN을 복구하시겠습니까?`)) return;
      const res = await fetchAPI('/api/emergency/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: name })
      });
      if (res && res.success) {
        showToast(`사용자 '${name}' 차단 해제 및 정상 복구 완료!`);
        loadUsers();
      } else {
        alert('해제 실패: ' + (res ? (res.error || res.message) : '알 수 없는 오류'));
      }
    }

    async function triggerGlobalLockdown() {
      const btn = document.getElementById('global-lockdown-btn');
      const isLocked = btn && btn.innerText.includes('해제');
      if (isLocked) {
        if (!confirm('🟢 전체 학생 비상 락다운을 해제하고 정상 복구하시겠습니까?')) return;
        const res = await fetchAPI('/api/emergency/global-lockdown', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'restore' })
        });
        if (res && res.success) {
          showToast('비상 락다운이 정상 해제되었습니다.');
          loadStatus();
          loadUsers();
        }
      } else {
        const reason = prompt(`🚨 [긴급 경고] 서버 전체 비상 락다운(Global Panic Lockdown)을 실행하시겠습니까?
모든 학생의 VPN 통신이 전면 차단되고 활성 세션이 강제 종료됩니다.
(관리자 접속만 유지됩니다.)

발령 사유를 입력하세요:`, '긴급 침해사고 의심에 따른 전사 비상 격리');
        if (!reason) return;
        const res = await fetchAPI('/api/emergency/global-lockdown', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'lock', reason: reason })
        });
        if (res && res.success) {
          alert(`🚨 전체 학생 비상 락다운이 발령되었습니다.
모든 비인가 통신이 차단되었습니다.`);
          loadStatus();
          loadUsers();
        }
      }
    }

    async function controlUserJupyter(cname, action, btn) {
      if (btn) btn.disabled = true;
      const res = await fetchAPI('/api/containers/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: cname, action: action })
      });
      if (btn) btn.disabled = false;
      if (res && res.success) {
        showToast(res.message || `'${cname}' ${action} 완료`);
        loadUsers();
      } else {
        alert('주피터 제어 실패: ' + (res ? (res.error || res.message) : '오류'));
      }
    }

    function copyJupyterLink(url, username) {
      navigator.clipboard.writeText(url).then(() => {
        showToast(`'${username}' 주피터랩 접속 URL이 클립보드에 복사되었습니다!`);
      }).catch(e => {
        prompt('아래 URL을 복사하세요:', url);
      });
    }

    async function provisionUserJupyter(username, btn) {
      if (!confirm(`사용자 '${username}' 전용 주피터랩 컨테이너를 프로비저닝(포트 자동할당 + docker-compose 등록)하시겠습니까?`)) return;
      if (btn) {
        btn.disabled = true;
        btn.innerText = '등록 중...';
      }
      const res = await fetchAPI('/api/users/provision-jupyter', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username })
      });
      if (btn) {
        btn.disabled = false;
        btn.innerText = '➕ 프로비저닝';
      }
      if (res && res.success) {
        showToast(`'${username}' 주피터랩 컨테이너(${res.container_name}, 포트 :${res.port}) 프로비저닝 완료!`);
        loadUsers();
      } else {
        alert('프로비저닝 실패: ' + (res ? (res.error || '알 수 없는 오류') : '오류'));
      }
    }

    async function loadAnomalies() {
      const data = await fetchAPI('/api/metrics/access-anomalies');
      if (!data) return;
      const tbody = document.getElementById('anomalies-table-body');
      if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">감지된 임의 접근 이력이 없습니다.</td></tr>';
        return;
      }
      tbody.innerHTML = data.map(a => `
        <tr>
          <td style="font-size: 11px; color: var(--text-muted);">${a.timestamp}</td>
          <td><strong style="color: #f87171;">${a.user}</strong></td>
          <td><code style="color: #fbbf24; font-size: 12px;">${a.target_resource}</code></td>
          <td><span class="ticket-category ${a.category}">${a.category}</span></td>
          <td><span class="badge ${a.status === 'pending' ? 'badge-local' : 'badge-online'}">${a.status}</span></td>
          <td>${a.action}</td>
          <td style="font-size: 12px; color: #a5b4fc;">${a.resolution_note || '-'}</td>
        </tr>
      `).join('');
    }

    async function loadCve() {
      const data = await fetchAPI('/api/metrics/cve');
      if (!data || !data.cves) return;
      const container = document.getElementById('cve-container');
      container.innerHTML = data.cves.map(c => {
        const isCrit = c.severity === 'CRITICAL';
        const isHigh = c.severity === 'HIGH';
        const sevColor = isCrit ? '#ef4444' : (isHigh ? '#f97316' : '#fbbf24');
        return `
          <div class="card" style="border-left: 4px solid ${sevColor}; margin-bottom: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
              <div>
                <strong style="font-size: 16px; color: white;">${c.id}</strong> — <span style="font-size: 14px; color: #cbd5e1;">${c.title}</span>
              </div>
              <div style="display: flex; gap: 8px;">
                <span class="badge" style="background: rgba(239,68,68,0.2); color: ${sevColor}; border: 1px solid ${sevColor};">CVSS ${c.cvss} (${c.severity})</span>
                <span class="badge badge-online">${c.status}</span>
              </div>
            </div>
            <p style="font-size: 13px; color: #94a3b8; margin-bottom: 8px;">${c.description}</p>
            <div style="font-size: 12px; background: #080c14; padding: 8px 12px; border-radius: 6px; color: #34d399;">
              <strong>조치 및 완화 상태:</strong> ${c.mitigation}
            </div>
          </div>
        `;
      }).join('');
    }

    async function triggerScan(btn) {
      btn.disabled = true;
      const orig = btn.innerHTML;
      btn.innerHTML = '<span class="spinner"></span> 스캔 중...';
      const res = await fetchAPI('/api/scan', { method: 'POST' });
      btn.disabled = false;
      btn.innerHTML = orig;
      if (res && res.success) {
        showToast(res.message);
        loadTickets();
        loadUsers();
      } else {
        showToast('스캔 실패: ' + (res ? (res.error || '서버 응답 오류') : '네트워크 오류'), true);
      }
    }

    async function analyzeTicket(id, btn) {
      btn.disabled = true;
      const orig = btn.innerHTML;
      btn.innerHTML = '<span class="spinner"></span> 분석 중...';
      const res = await fetchAPI(`/api/analyze?id=${id}`, { method: 'POST' });
      btn.disabled = false;
      btn.innerHTML = orig;
      if (res && res.success) {
        showToast(`티켓 #${id} AI 분석 완료`);
        loadTickets();
      } else {
        showToast('분석 실패: ' + (res ? res.error : ''), true);
      }
    }

    async function approveTicket(id, btn) {
      if (!confirm(`티켓 #${id}의 작업을 승인하시겠습니까?`)) return;
      btn.disabled = true;
      const orig = btn.innerHTML;
      btn.innerHTML = '<span class="spinner"></span> 실행 중...';
      const res = await fetchAPI(`/api/approve?id=${id}`, { method: 'POST' });
      btn.disabled = false;
      btn.innerHTML = orig;
      if (res && res.success) {
        showToast(`티켓 #${id} 승인 및 실행 완료!`);
        loadTickets();
      } else {
        showToast('승인 실패: ' + (res ? res.error : ''), true);
      }
    }

    async function addNote(id) {
      const text = prompt(`티켓 #${id}에 남길 운영자 메모를 입력하세요 (선례 메모리에 저장됩니다):`);
      if (!text) return;
      const res = await fetchAPI('/api/note', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, text })
      });
      if (res && res.success) {
        showToast('메모가 저장되었습니다.');
        loadTickets();
      }
    }

    async function loadMemory(query = '') {
      const data = await fetchAPI(`/api/memory?q=${encodeURIComponent(query)}`);
      if (!data) return;
      document.getElementById('memory-count').innerText = data.length;
      const container = document.getElementById('memory-container');
      if (data.length === 0) {
        container.innerHTML = '<p style="color: var(--text-muted);">검색된 메모리 기록이 없습니다.</p>';
        return;
      }
      container.innerHTML = data.map(m => `
        <div class="card">
          <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
            <span style="font-weight: bold; color: #38bdf8;">${m.kind.toUpperCase()} ${m.ticket_id ? `(Ticket #${m.ticket_id})` : ''}</span>
            <span style="font-size: 12px; color: var(--text-muted);">${m.created_str}</span>
          </div>
          <div style="font-size: 13px; color: #cbd5e1; white-space: pre-wrap; font-family: monospace;">${m.body}</div>
        </div>
      `).join('');
    }

    let searchTimer = null;
    function searchMemory(q) {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { loadMemory(q); }, 300);
    }

    async function loadOntology() {
      const data = await fetchAPI('/api/ontology');
      if (!data) return;

      const meta = data.metadata || {};
      const descEl = document.getElementById('ontology-meta-desc');
      if (descEl) {
        descEl.innerText = `버전: ${meta.version || 'v1.2.0'} • 프레임워크: ${meta.framework || 'NVIDIA Auto-Ontology & Apache Ossie'} • 최근 갱신: ${meta.last_updated || '2026-11-06'}`;
      }

      // 1. When it runs
      const whenCont = document.getElementById('ontology-when-container');
      if (whenCont && data.operational_lifecycle && data.operational_lifecycle.when_it_runs) {
        whenCont.innerHTML = data.operational_lifecycle.when_it_runs.map(w => `
          <div style="background: rgba(56,189,248,0.06); border: 1px solid #1e293b; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
            <div style="font-weight: bold; color: #38bdf8; font-size: 13px; margin-bottom: 4px;">▶ ${w.trigger}</div>
            <div style="font-size: 12px; color: #94a3b8; margin-bottom: 4px;"><strong>동작 시점:</strong> ${w.timing}</div>
            <div style="font-size: 12px; color: #cbd5e1;">${w.action}</div>
          </div>
        `).join('');
      }

      // 2. How it runs
      const howCont = document.getElementById('ontology-how-container');
      if (howCont && data.operational_lifecycle && data.operational_lifecycle.how_it_runs) {
        howCont.innerHTML = data.operational_lifecycle.how_it_runs.map(h => `
          <div style="background: rgba(16,185,129,0.06); border: 1px solid #1e293b; border-radius: 6px; padding: 10px; margin-bottom: 8px;">
            <div style="font-weight: bold; color: #34d399; font-size: 13px; margin-bottom: 4px;">✔ ${h.component}</div>
            <div style="font-size: 12px; color: #cbd5e1;">${h.mechanism}</div>
          </div>
        `).join('');
      }

      // 3. Changelog / Updates
      const histCont = document.getElementById('ontology-history-container');
      if (histCont && data.operational_lifecycle && data.operational_lifecycle.update_history) {
        histCont.innerHTML = data.operational_lifecycle.update_history.map(u => `
          <div style="display: flex; gap: 14px; align-items: flex-start; padding: 10px; border-bottom: 1px solid #1e293b;">
            <span class=\"badge\" style=\"background: #2e1065; color: #c084fc; border: 1px solid #7c3aed; white-space: nowrap;\">${u.version}</span>
            <div style=\"flex: 1;\">
              <div style=\"display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;\">
                <strong style=\"color: #f8fafc; font-size: 13px;\">${u.category}</strong>
                <span style=\"font-size: 11px; color: var(--text-muted);\">${u.timestamp}</span>
              </div>
              <div style=\"font-size: 12px; color: #94a3b8;\">${u.details}</div>
            </div>
          </div>
        `).join('');
      }

      // 4. Normal Baselines
      const baseCont = document.getElementById('ontology-baselines-container');
      if (baseCont && data.normal_patterns) {
        baseCont.innerHTML = data.normal_patterns.map(p => `
          <div style=\"font-size: 12px; color: #cbd5e1; background: #080c14; padding: 8px 12px; border-radius: 6px; margin-bottom: 6px; border-left: 3px solid #10b981;\">
            ✅ ${p}
          </div>
        `).join('');
      }

      // 5. Threat Signals
      const sigCont = document.getElementById('ontology-signals-container');
      if (sigCont && data.incident_signals) {
        sigCont.innerHTML = data.incident_signals.map(s => {
          const isCrit = s.severity === 'critical';
          const sevBadge = isCrit 
            ? '<span class="badge" style="background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid #ef4444;">CRITICAL</span>'
            : '<span class="badge" style="background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid #f59e0b;">WARNING</span>';
          return `
            <div style="background: #080c14; padding: 8px 12px; border-radius: 6px; margin-bottom: 8px; border-left: 3px solid ${isCrit ? '#ef4444' : '#f59e0b'};">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                <strong style="color: #f8fafc; font-size: 13px;">${s.signal}</strong>
                ${sevBadge}
              </div>
              <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px;"><strong>지표:</strong> ${(s.indicators || []).join(', ')}</div>
              <div style="font-size: 12px; color: #cbd5e1;">${s.description}</div>
            </div>
          `;
        }).join('');
      }

      // 6. Terms
      const container = document.getElementById('terms-container');
      if (container && data.terms) {
        container.innerHTML = data.terms.map(t => `
          <div class="term-card">
            <div class="term-name">${t.name}</div>
            <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 6px;">동의어: ${(t.synonyms || []).join(', ')}</div>
            <div class="term-desc">${t.description}</div>
          </div>
        `).join('');
      }
    }

    async function exportOssie() {
      const res = await fetchAPI('/api/ontology/export-ossie');
      if (res && res.success) {
        document.getElementById('ossie-export-status').innerText = 'Apache Ossie 포맷 모델 생성 완료';
        setTimeout(() => { document.getElementById('ossie-export-status').innerText = ''; }, 3000);
      }
    }

    async function loadWorklog() {
      const data = await fetchAPI('/api/worklog');
      if (!data) return;
      const container = document.getElementById('worklog-container');
      container.innerHTML = data.map(w => `
        <div class="timeline-item">
          <div class="timeline-date">${w.created_str} • ${w.kind} (Ticket #${w.ticket_id})</div>
          <div class="timeline-body">${w.body}</div>
        </div>
      `).join('');
    }

    async function exportWorklog() {
      const res = await fetchAPI('/api/worklog/export', { method: 'POST' });
      if (res && res.success) {
        showToast('WORKLOG.md 에 성공적으로 동기화되었습니다.');
      }
    }

    // Initialize
    loadStatus();
    loadTickets();
    loadThermals();
    setInterval(loadTickets, 10000);
    setInterval(loadThermals, 15000);
  </script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html: str, status: int = 200) -> None:
        raw = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._send_html(HTML_PAGE)
            return

        if path in ("/guide", "/docs/guide", "/docs/LAB_RESEARCH_GUIDE.html"):
            guide_file = BASE_DIR / "docs" / "LAB_RESEARCH_GUIDE.html"
            if guide_file.exists():
                self._send_html(guide_file.read_text(encoding="utf-8"))
            else:
                self.send_error(404, "Guide file not found")
            return

        if path == "/api/status":
            bridge = AutoOntologyBridge()
            conn = bridge.check_connection()
            self._send_json({
                "system": "martin-B650M-K",
                "auto_ontology": conn,
                "llm": analysis_llm.chain_info(),
                "ssh_health": health_check.get_ssh_health(),
                "auto_scan": {
                    "interval_seconds": SCAN_INTERVAL,
                    "last_run": (_last_scan["ts"] or None),
                    "last_run_str": (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(_last_scan["ts"]))
                                     if _last_scan["ts"] else None),
                    "last_new_tickets": _last_scan["made"],
                    "last_error": _last_scan["error"],
                },
                "model": os.environ.get("OPS_WATCH_MODEL", "gemini-3.8-flash-medium")
            })
            return

        if path == "/api/health/ssh":
            force = query.get("refresh", ["0"])[0] == "1"
            self._send_json(health_check.get_ssh_health(force=force))
            return

        if path == "/api/emergency/status":
            import emergency_controls
            self._send_json({"global_locked": emergency_controls.is_global_locked()})
            return

        if path == "/api/metrics/users":
            self._send_json(system_metrics.get_user_records())
            return

        if path == "/api/metrics/access-anomalies":
            self._send_json(system_metrics.get_access_anomalies())
            return

        if path == "/api/metrics/cve":
            self._send_json(system_metrics.get_cve_issues())
            return

        if path == "/api/metrics/gpu":
            self._send_json(system_metrics.get_gpu_metrics())
            return

        if path == "/api/metrics/storage":
            import storage_monitor
            force = query.get("refresh", ["0"])[0] == "1"
            self._send_json(storage_monitor.get_storage_metrics(force_refresh=force))
            return

        if path == "/api/metrics/thermals":
            import hardware_thermals
            self._send_json(hardware_thermals.get_thermal_metrics())
            return

        if path == "/api/metrics/containers":
            import docker_monitor
            self._send_json(docker_monitor.get_containers_list())
            return

        if path == "/api/metrics/vpn":
            import headscale_monitor
            self._send_json(headscale_monitor.get_vpn_overview())
            return

        if path == "/api/gpu/discord_status":
            import gpu_discord_notifier
            st = gpu_discord_notifier.load_previous_state()
            self._send_json(st)
            return

        if path == "/api/metrics/processes":
            import process_inspector
            procs = process_inspector.fetch_process_list()
            anomalies = process_inspector.inspect_anomalies()
            self._send_json({
                "total_count": len(procs),
                "anomalies_count": len(anomalies),
                "anomalies": anomalies,
                "top_processes": procs[:40]
            })
            return

        if path == "/api/tickets":
            c = ops_watch.db()
            rows = c.execute(
                """SELECT t.id, datetime(t.created,'unixepoch','localtime'), t.category, t.evidence, t.action, t.status, t.resolution_note,
                          (SELECT body FROM worklog WHERE ticket_id = t.id AND kind = 'llm-analysis' ORDER BY id DESC LIMIT 1) as analysis,
                          (SELECT tags FROM worklog WHERE ticket_id = t.id AND kind = 'llm-analysis' ORDER BY id DESC LIMIT 1) as analysis_tags
                   FROM tickets t ORDER BY t.id DESC"""
            ).fetchall()
            tickets = []
            for r in rows:
                tickets.append({
                    "id": r[0],
                    "created_str": r[1],
                    "category": r[2],
                    "evidence": r[3],
                    "action": r[4],
                    "status": r[5],
                    "resolution_note": r[6],
                    "analysis": r[7],
                    "analysis_tags": r[8]
                })
            self._send_json(tickets)
            return

        if path == "/api/memory":
            q = query.get("q", [""])[0]
            c = ops_watch.db()
            sql = "SELECT id, datetime(created,'unixepoch','localtime'), ticket_id, kind, body, tags FROM worklog"
            params = []
            if q:
                sql += " WHERE body LIKE ? OR tags LIKE ? OR kind LIKE ?"
                like_q = f"%{q}%"
                params = [like_q, like_q, like_q]
            sql += " ORDER BY id DESC LIMIT 25"
            rows = c.execute(sql, params).fetchall()
            items = []
            for r in rows:
                items.append({
                    "id": r[0],
                    "created_str": r[1],
                    "ticket_id": r[2],
                    "kind": r[3],
                    "body": r[4],
                    "tags": r[5]
                })
            self._send_json(items)
            return

        if path == "/api/ontology":
            bridge = AutoOntologyBridge()
            data = bridge.load_local_ontology()
            self._send_json(data)
            return

        if path == "/api/ontology/export-ossie":
            bridge = AutoOntologyBridge()
            model = bridge.export_ossie_model()
            self._send_json({"success": True, "model": model})
            return

        if path == "/api/worklog":
            c = ops_watch.db()
            rows = c.execute(
                "SELECT id, datetime(created,'unixepoch','localtime'), ticket_id, kind, body FROM worklog ORDER BY id DESC LIMIT 25"
            ).fetchall()
            items = [{"id": r[0], "created_str": r[1], "ticket_id": r[2], "kind": r[3], "body": r[4]} for r in rows]
            self._send_json(items)
            return

        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""

        if path == "/api/scan":
            try:
                made = ops_watch.scan()
                self._send_json({"success": True, "message": f"스캔 완료: {made}건의 신규 티켓/단말 변경 감지"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/analyze":
            ticket_id = int(query.get("id", [0])[0])
            if not ticket_id:
                self._send_json({"success": False, "error": "missing id"}, status=400)
                return
            try:
                ops_watch.analyze(ticket_id)
                self._send_json({"success": True, "message": f"티켓 #{ticket_id} 분석 완료"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/approve":
            ticket_id = int(query.get("id", [0])[0])
            if not ticket_id:
                self._send_json({"success": False, "error": "missing id"}, status=400)
                return
            try:
                ops_watch.approve(ticket_id)
                self._send_json({"success": True, "message": f"티켓 #{ticket_id} 승인 완료"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/note":
            try:
                payload = json.loads(body)
                ticket_id = int(payload.get("id", 0))
                note_text = payload.get("text", "")
                ops_watch.note(ticket_id, note_text)
                self._send_json({"success": True, "message": "메모 기록 완료"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/worklog/export":
            try:
                ops_watch.worklog(export_md=True)
                self._send_json({"success": True, "message": "WORKLOG.md 동기화 완료"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/gpu/discord_notify":
            try:
                import gpu_discord_notifier
                res = gpu_discord_notifier.check_and_notify(threshold=10.0, force=True)
                self._send_json({"success": True, "result": res, "message": "디스코드 학생 안내 메시지 전송 완료"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/users/add":
            try:
                payload = json.loads(body)
                res = system_metrics.add_user(
                    name=payload.get("name", ""),
                    full_name=payload.get("full_name", ""),
                    email=payload.get("email", ""),
                    role=payload.get("role", "student"),
                    expires=payload.get("expires", "2027-01-04"),
                    gpu=payload.get("gpu", True),
                    headscale=payload.get("headscale", True),
                    notes=payload.get("notes", "")
                )
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=400)
            return

        if path == "/api/emergency/user-block":
            try:
                import emergency_controls
                req = json.loads(body) if body else {}
                res = emergency_controls.emergency_block_user(
                    req.get("username", ""),
                    req.get("reason", "운영자 긴급 차단")
                )
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/emergency/network-block":
            try:
                import emergency_controls
                req = json.loads(body) if body else {}
                res = emergency_controls.emergency_network_block(
                    req.get("username", ""),
                    req.get("reason", "VPN 네트워크 긴급 격리")
                )
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/emergency/unblock":
            try:
                import emergency_controls
                req = json.loads(body) if body else {}
                res = emergency_controls.unblock_user(req.get("username", ""))
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/emergency/global-lockdown":
            try:
                import emergency_controls
                req = json.loads(body) if body else {}
                action = req.get("action", "lock")
                if action == "restore":
                    res = emergency_controls.restore_global_lockdown()
                else:
                    res = emergency_controls.emergency_global_lockdown(
                        req.get("reason", "관리자 비상 락다운 발령")
                    )
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/containers/control":
            try:
                import docker_monitor
                req = json.loads(body) if body else {}
                res = docker_monitor.control_container(req.get("name", ""), req.get("action", ""))
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/users/provision-jupyter":
            try:
                import docker_monitor
                req = json.loads(body) if body else {}
                res = docker_monitor.provision_jupyter_container(req.get("username", ""))
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/vpn/key/create":
            try:
                import headscale_monitor
                req = json.loads(body) if body else {}
                res = headscale_monitor.create_preauth_key(
                    username=req.get("username", "martin"),
                    reusable=bool(req.get("reusable", False)),
                    expiration=req.get("expiration", "720h")
                )
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/vpn/node/expire":
            try:
                import headscale_monitor
                req = json.loads(body) if body else {}
                res = headscale_monitor.expire_node(int(req.get("node_id", 0)))
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/vpn/node/delete":
            try:
                import headscale_monitor
                req = json.loads(body) if body else {}
                res = headscale_monitor.delete_node(int(req.get("node_id", 0)))
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        if path == "/api/vpn/key/expire":
            try:
                import headscale_monitor
                req = json.loads(body) if body else {}
                res = headscale_monitor.expire_key(req.get("key", ""))
                self._send_json(res)
            except Exception as e:
                self._send_json({"success": False, "error": str(e)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)


def _auto_scan_loop(interval: int) -> None:
    """Background journal scanner: journalctl(5min window) -> rules -> tickets."""
    time.sleep(15)  # let the HTTP server bind first
    while True:
        started = time.time()
        try:
            made = ops_watch.scan()
            _last_scan.update(ts=int(time.time()), made=made, error=None)
            print(f"[auto-scan] {time.strftime('%H:%M:%S')} {made} new ticket(s) "
                  f"({time.time() - started:.1f}s)")
        except Exception as exc:
            _last_scan.update(ts=int(time.time()), error=str(exc))
            print(f"[auto-scan] error: {exc}", file=sys.stderr)
        time.sleep(max(60, interval))


def run_server(port: int = PORT) -> None:
    server = ThreadingHTTPServer((BIND, port), DashboardHandler)
    print(f"=== OPS-WATCH Web Dashboard running at http://localhost:{port} (bind {BIND}) ===")
    health_check.start_watchdog()  # tailscale ping이 아니라 TCP 2322를 감시
    if SCAN_INTERVAL > 0:
        threading.Thread(target=_auto_scan_loop, args=(SCAN_INTERVAL,),
                         name="auto-scan", daemon=True).start()
        print(f"=== Auto journal scan every {SCAN_INTERVAL}s (journalctl via linux-builder) ===")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping dashboard server.")
        server.server_close()


if __name__ == "__main__":
    run_server()
