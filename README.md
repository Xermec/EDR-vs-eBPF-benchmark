# EDR vs eBPF vs ClamAV — Detection Benchmark

> Linux орчинд **3 төрлийн security detection системийн** илрүүлэх чадварыг 10 malware sample дээр real-time харьцуулах веб дашбоард

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Ubuntu 22.04](https://img.shields.io/badge/Ubuntu-22.04-E95420.svg)](https://ubuntu.com)

---

<img width="2027" height="1164" alt="image" src="https://github.com/user-attachments/assets/51eba106-c937-4e72-b978-88de4d4b989d" />


## Ерөнхий танилцуулга

Энэхүү систем нь дараах гурван детекторыг нэгэн зэрэг ажиллуулж харьцуулдаг:

| Детектор | Технологи | Сервер |
|---|---|---|
| **eBPF Hunter** | Custom kernel-level syscall tracing | 10.52.1.57 |
| **Trellix EDR** | Commercial signature + behavior | 10.52.1.62 |
| **ClamAV** | Open-source antivirus | 10.52.1.118 |

### Туршилтын үр дүн (10/10 sample)

| Детектор | Detection rate | Avg latency | Idle CPU |
|---|:-:|:-:|:-:|
| eBPF Hunter | **7/10 (70%)** | ~1477 ms | ~0.5% |
| ClamAV | 3/10 (30%) | ~500 ms | ~3% |
| Trellix EDR | 2/10 (20%) | ~5000 ms | ~25% |

---

## Архитектур

```
Browser (HTTPS)
      │
      ▼
   Nginx  ──── /benchmark/ ──► FastAPI :8765
              ────── / ───────► Wazuh Dashboard :5601

FastAPI backend
      │
      ├── WebSocket ──► eBPF agent (10.52.1.57)
      ├── WebSocket ──► EDR agent  (10.52.1.62)
      ├── WebSocket ──► ClamAV agent (local)
      └── tail ──────► /var/ossec/logs/alerts/alerts.json
```

---

## Файлын бүтэц

```
benchmark_v4/
├── server/
│   ├── main.py                    # FastAPI backend v4.0 (3 detector)
│   └── agent.py                   # Agent (ebpf/edr/clamav mode)
├── frontend/
│   └── index.html                 # 3-panel dashboard + Chart.js
├── agent_ebpf/
│   └── ebpf_rwx_hunter.py         # eBPF Hunter v3.3 (7 vector)
├── samples/
│   ├── 01/  EICAR test file
│   ├── 02/  msfvenom static ELF
│   ├── 03/  RWX shellcode loader   (T1620)
│   ├── 04/  XOR-encoded shellcode  (T1027)
│   ├── 05/  mprotect-based loader  (T1055)
│   ├── 06/  memfd_create fileless  (T1620)
│   ├── 07/  Python ctypes LOTL     (T1059.006)
│   ├── 08/  Bash reverse shell     (T1059.004)
│   ├── 09/  Crypto miner stub      (T1496)
│   └── 10/  Cron persistence       (T1053.003)
├── scripts/
│   ├── install_clamav.sh
│   ├── add_clamav_to_wazuh.sh
│   └── deploy_wazuh_server.sh
├── systemd/
│   └── benchmark-agent-clamav.service
├── wazuh_rules/
│   └── local_rules.xml            # Custom rules 100100–100303
└── UPGRADE_TO_V4.md               # Deploy заавар
```

---

## eBPF Hunter Detection Vectors (v3.3)

| Vector | Syscall | Илрүүлэх зүйл | Sample |
|---|---|---|:-:|
| **RWX** | `mmap` | PROT_READ\|WRITE\|EXEC | 03, 04 |
| **MPROTECT** | `mprotect` | RW→RWX шилжилт | 05 |
| **MEMFD** | `memfd_create` | Fileless ELF pattern | 06 |
| **EXEC_TMP** | `execve` | /tmp /dev/shm-аас exec | 09 |
| **CONN_C2** | `psutil` | Suspicious port (4444) | 08, 10 |
| **CRON** | File watcher | Crontab modification | 10 |
| **CPU_SPIKE** | `psutil` | Sustained 80%+ CPU | 09 |

---

## Системийн шаардлага

- Ubuntu 22.04 LTS (3+ сервер)
- Linux kernel **5.15+**
- Python **3.10+**
- BCC tools **0.30+**
- Wazuh **4.14+**
- Trellix Endpoint Security 10.7 *(эсвэл өөр EDR)*

---

## Deploy хийх

### 1. Tarball татах ба тарааx

```bash
# Локалаас серверүүдэд хуулах
scp benchmark_v4.0.tar.gz root@10.52.1.118:/root/  # Wazuh
scp benchmark_v4.0.tar.gz root@10.52.1.57:/root/   # eBPF
scp benchmark_v4.0.tar.gz root@10.52.1.62:/root/   # EDR
```

### 2. Wazuh сервер (10.52.1.118)

```bash
tar xzf benchmark_v4.0.tar.gz && cd benchmark_v4
chmod +x scripts/*.sh

# ClamAV суулгах (~10 минут)
sudo bash scripts/install_clamav.sh

# Wazuh integrate
sudo bash scripts/add_clamav_to_wazuh.sh

# Backend + frontend + ClamAV agent
sudo bash scripts/deploy_wazuh_server.sh
```

### 3. eBPF сервер (10.52.1.57)

```bash
tar xzf benchmark_v4.0.tar.gz && cd benchmark_v4
sudo cp server/agent.py /opt/benchmark-agent/agent.py
sudo systemctl restart benchmark-agent

# Hunter шинэчлэх
sudo cp agent_ebpf/ebpf_rwx_hunter.py /home/ndc-user/ebpf_rwx_hunter.py
sudo systemctl restart rwx-hunter
```

### 4. EDR сервер (10.52.1.62)

```bash
tar xzf benchmark_v4.0.tar.gz && cd benchmark_v4
sudo cp server/agent.py /opt/benchmark-agent/agent.py
sudo systemctl restart benchmark-agent
```

### 5. Dashboard нээх

```
https://wazuh.datacenter.gov.mn/benchmark/
```

Ctrl+Shift+R → Header дахь 3 dot ногоон болсон байх ёстой.

---

## Dashboard-н харагдах байдал

- **3-panel layout** — eBPF / EDR / ClamAV тус бүрийн real-time CPU, RAM chart
- **Results table** — 10 sample тус бүрийн detection result
- **4 chart** — Pie (winner distribution), Detection rate, Latency bar, CPU bar
- **Dark/light theme toggle**
- **CSV export**

---

## Wazuh Custom Rules

| Rule ID | Level | Детектор | Тайлбар |
|---|:-:|---|---|
| 100100–100103 | 3–14 | eBPF Hunter | RWX Hunter alert levels |
| 100200–100220 | 3–14 | Trellix EDR | EDR threat levels |
| 100300–100303 | 3–14 | ClamAV | ClamAV malware detection |

---

## Туршилтын нотолгоо

Хамгийн тод үр дүн — **Sample 03 (RWX Shellcode Loader)**:

```
eBPF Hunter:   1585 ms  ✅ CRITICAL
Trellix EDR:  21088 ms  ✅ L3
ClamAV:           —     ❌

→ eBPF нь EDR-ээс 13 дахин хурдан ilrüülsen
```

---

## Анхааруулга

Энэхүү код нь **lab орчинд зориулагдсан** — IP хаяг, port, shellcode нь тодорхой сүлжээнд hardcode хийгдсэн.  
Өөр орчинд ашиглахдаа:

- `server/main.py` → `AGENTS` dict-д IP солих
- `samples/*/run.sh` → `LHOST` утга солих
- `wazuh_rules/local_rules.xml` → custom rule нэмэх

---

## Эх сурвалж

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [eBPF.io Documentation](https://ebpf.io/)
- [Wazuh Custom Rules](https://documentation.wazuh.com/)
- [BCC Tools](https://github.com/iovisor/bcc)
- FBI/NSA Drovorub Malware Report (2020)

---

## Лиценз

MIT License — эрдэм шинжилгээ, боловсролын зориулалтаар чөлөөтэй ашиглаж болно.

> **Дипломын ажил:** eBPF технологид суурилсан Linux хяналтын систем  
> **Огноо:** 2026 он





