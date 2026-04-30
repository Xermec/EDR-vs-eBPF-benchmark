#!/usr/bin/env python3
"""
EDR vs eBPF Detection Benchmark Server v2
Шинэ боломжууд:
  - Run All — 10 sample-ыг автомат дараалуулах
  - Results history — sample бүрийн үр дүнг хадгалж frontend-руу буцаах
  - CSV export
  - Cleanup — agent-уудаас процесс цэвэрлэх
  - Baseline CPU/RAM tracking
"""

import asyncio
import csv
import io
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
import aiofiles

# ---------- ТОХИРГОО ----------

AGENTS = {
    "ebpf": {"id": "001", "name": "ebpf-hunter", "ip": "10.52.1.57", "label": "eBPF HUNTER", "color": "#5dcaa5"},
    "edr":  {"id": "002", "name": "edr-trellix", "ip": "10.52.1.62", "label": "TRELLIX EDR",  "color": "#d4537e"},
}

WAZUH_ALERTS_LOG = "/var/ossec/logs/alerts/alerts.json"

SAMPLES = [
    {"id": "01", "name": "EICAR test file",                "tech": "Signature",       "expected_edr": True,  "expected_ebpf": False},
    {"id": "02", "name": "Static x64 ELF (msfvenom)",      "tech": "Known binary",    "expected_edr": True,  "expected_ebpf": False},
    {"id": "03", "name": "RWX shellcode loader",           "tech": "T1620",           "expected_edr": False, "expected_ebpf": True},
    {"id": "04", "name": "XOR-encoded shellcode",          "tech": "Obfuscation",     "expected_edr": False, "expected_ebpf": True},
    {"id": "05", "name": "mprotect-based loader",          "tech": "T1055",           "expected_edr": False, "expected_ebpf": True},
    {"id": "06", "name": "Reflective ELF (memfd_create)",  "tech": "T1620",           "expected_edr": False, "expected_ebpf": True},
    {"id": "07", "name": "Python ctypes injector",         "tech": "Living-off-land", "expected_edr": False, "expected_ebpf": True},
    {"id": "08", "name": "Bash reverse shell",             "tech": "Plain TTY",       "expected_edr": False, "expected_ebpf": False},
    {"id": "09", "name": "Crypto miner stub",              "tech": "Resource abuse",  "expected_edr": True,  "expected_ebpf": False},
    {"id": "10", "name": "Cron persistence + reverse shell","tech": "T1053",          "expected_edr": False, "expected_ebpf": False},
]

DETECTION_TIMEOUT_SEC = 30  # EDR-ийн delayed alert (e.g. Sample 03 ~20sec) барих хүртэл хүлээх

# ---------- STATE ----------

class State:
    def __init__(self):
        self.browsers: Set[WebSocket] = set()
        self.agents: Dict[str, WebSocket] = {}
        self.active_test: Optional[Dict] = None
        self.test_start_ts: Optional[float] = None
        self.detected: Dict[str, dict] = {}
        self.results: List[dict] = []
        self.run_all_task: Optional[asyncio.Task] = None
        self.peak_cpu: Dict[str, float] = {"ebpf": 0, "edr": 0}
        self.peak_ram: Dict[str, float] = {"ebpf": 0, "edr": 0}
        self.baseline_buffer: Dict[str, List[float]] = {"ebpf": [], "edr": []}

state = State()
app = FastAPI()


async def broadcast(msg: dict):
    if not state.browsers:
        return
    payload = json.dumps(msg)
    dead = set()
    for ws in state.browsers:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.add(ws)
    state.browsers -= dead


# ---------- WAZUH ALERT TAILER ----------

async def tail_wazuh_alerts():
    log_path = Path(WAZUH_ALERTS_LOG)
    while not log_path.exists():
        print(f"[tailer] Хүлээж байна: {log_path}")
        await asyncio.sleep(5)
    print(f"[tailer] {log_path} файлыг tail хийж эхэллээ")
    async with aiofiles.open(log_path, mode='r') as f:
        await f.seek(0, 2)
        while True:
            line = await f.readline()
            if not line:
                await asyncio.sleep(0.1)
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue
            await process_alert(event)


async def process_alert(event: dict):
    if not state.active_test:
        return

    rule = event.get("rule", {})
    agent = event.get("agent", {})
    rule_groups = rule.get("groups", [])
    rule_id = rule.get("id", "")
    rule_level = rule.get("level", 0)
    rule_desc = rule.get("description", "")
    agent_name = agent.get("name", "")

    is_ebpf_rule = "rwx_hunter" in rule_groups
    is_edr_rule = "trellix" in rule_groups
    if not (is_ebpf_rule or is_edr_rule):
        return

    source = None
    if is_ebpf_rule and ("ebpf" in agent_name or agent_name == "ebpf-hunter"):
        source = "ebpf"
    elif is_edr_rule and ("edr" in agent_name or "trellix" in agent_name):
        source = "edr"
    if not source:
        return

    latency_ms = None
    if state.test_start_ts:
        latency_ms = round((time.time() - state.test_start_ts) * 1000)

    first_detect = source not in state.detected
    if first_detect:
        state.detected[source] = {
            "latency_ms": latency_ms,
            "rule_id": rule_id,
            "rule_level": rule_level,
            "rule_desc": rule_desc,
        }

    await broadcast({
        "type": "alert",
        "source": source,
        "rule_id": rule_id,
        "rule_level": rule_level,
        "rule_desc": rule_desc,
        "latency_ms": latency_ms if first_detect else None,
        "first_detect": first_detect,
        "ts": datetime.now().strftime("%H:%M:%S"),
    })


# ---------- AGENT WEBSOCKET ----------

@app.websocket("/ws/agent/{agent_key}")
async def agent_ws(ws: WebSocket, agent_key: str):
    if agent_key not in AGENTS:
        await ws.close(code=1008)
        return
    await ws.accept()
    state.agents[agent_key] = ws
    print(f"[agent] {agent_key} холбогдлоо")
    await broadcast({"type": "agent_status", "agent": agent_key, "online": True})

    try:
        while True:
            data = await ws.receive_json()
            msg_type = data.get("type")

            if msg_type == "metrics":
                cpu = data.get("cpu", 0)
                ram_mb = data.get("ram_mb", 0)
                ram_pct = data.get("ram_pct", 0)
                net = data.get("net_conn", 0)

                if state.active_test:
                    state.peak_cpu[agent_key] = max(state.peak_cpu[agent_key], cpu)
                    state.peak_ram[agent_key] = max(state.peak_ram[agent_key], ram_mb)
                else:
                    buf = state.baseline_buffer[agent_key]
                    buf.append(cpu)
                    if len(buf) > 10:
                        buf.pop(0)

                await broadcast({
                    "type": "metrics", "source": agent_key,
                    "cpu": cpu, "ram_mb": ram_mb, "ram_pct": ram_pct,
                    "net_conn": net, "ts": time.time(),
                })

            elif msg_type == "sample_started":
                await broadcast({
                    "type": "sample_started", "source": agent_key,
                    "sample_id": data.get("sample_id"), "pid": data.get("pid"),
                })

            elif msg_type == "sample_finished":
                await broadcast({
                    "type": "sample_finished", "source": agent_key,
                    "sample_id": data.get("sample_id"),
                    "exit_code": data.get("exit_code"),
                    "stdout": data.get("stdout", "")[:500],
                })

            elif msg_type == "cleanup_done":
                await broadcast({
                    "type": "cleanup_done", "source": agent_key,
                    "killed": data.get("killed", 0),
                })

    except WebSocketDisconnect:
        print(f"[agent] {agent_key} салгагдлаа")
    except Exception as e:
        print(f"[agent] {agent_key} алдаа: {e}")
    finally:
        if state.agents.get(agent_key) is ws:
            del state.agents[agent_key]
        await broadcast({"type": "agent_status", "agent": agent_key, "online": False})


# ---------- BROWSER WEBSOCKET ----------

@app.websocket("/ws/browser")
async def browser_ws(ws: WebSocket):
    await ws.accept()
    state.browsers.add(ws)
    print(f"[browser] нэгдсэн (нийт: {len(state.browsers)})")

    await ws.send_json({
        "type": "init",
        "samples": SAMPLES,
        "agents": AGENTS,
        "agents_online": {k: (k in state.agents) for k in AGENTS},
        "results": state.results,
    })

    try:
        while True:
            data = await ws.receive_json()
            cmd = data.get("cmd")

            if cmd == "run_sample":
                asyncio.create_task(start_test(data.get("sample_id")))
            elif cmd == "run_all":
                interval = int(data.get("interval", 8))
                await start_run_all(interval)
            elif cmd == "stop_run_all":
                await stop_run_all()
            elif cmd == "reset":
                await reset_test()
            elif cmd == "cleanup":
                await trigger_cleanup()
            elif cmd == "clear_results":
                state.results = []
                await broadcast({"type": "results_cleared"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[browser] алдаа: {e}")
    finally:
        state.browsers.discard(ws)


# ---------- TEST CONTROL ----------

async def start_test(sample_id: str):
    sample = next((s for s in SAMPLES if s["id"] == sample_id), None)
    if not sample:
        await broadcast({"type": "error", "msg": f"Sample олдсонгүй: {sample_id}"})
        return

    baseline_cpu = {k: (sum(b)/len(b) if b else 0) for k, b in state.baseline_buffer.items()}

    state.active_test = sample
    state.test_start_ts = time.time()
    state.detected = {}
    state.peak_cpu = {"ebpf": 0, "edr": 0}
    state.peak_ram = {"ebpf": 0, "edr": 0}

    await broadcast({
        "type": "test_started",
        "sample": sample,
        "baseline_cpu": {k: round(v, 1) for k, v in baseline_cpu.items()},
        "ts": datetime.now().strftime("%H:%M:%S"),
    })

    for agent_key, ws in state.agents.items():
        try:
            await ws.send_json({"cmd": "run_sample", "sample_id": sample_id})
        except Exception as e:
            print(f"[test] {agent_key} рүү илгээж чадсангүй: {e}")

    # Sample script ~5 секунд run, дараа нь EDR/eBPF-д detection хийх хугацаа өгөх
    await asyncio.sleep(DETECTION_TIMEOUT_SEC)
    await finalize_test()


async def finalize_test():
    if not state.active_test:
        return

    sample = state.active_test
    result = {
        "sample_id": sample["id"],
        "sample_name": sample["name"],
        "tech": sample["tech"],
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ebpf": {
            "detected": "ebpf" in state.detected,
            "latency_ms": state.detected.get("ebpf", {}).get("latency_ms"),
            "rule_id":    state.detected.get("ebpf", {}).get("rule_id"),
            "rule_level": state.detected.get("ebpf", {}).get("rule_level", 0),
            "rule_desc":  state.detected.get("ebpf", {}).get("rule_desc", ""),
            "peak_cpu":   round(state.peak_cpu["ebpf"], 1),
            "peak_ram":   round(state.peak_ram["ebpf"]),
        },
        "edr": {
            "detected": "edr" in state.detected,
            "latency_ms": state.detected.get("edr", {}).get("latency_ms"),
            "rule_id":    state.detected.get("edr", {}).get("rule_id"),
            "rule_level": state.detected.get("edr", {}).get("rule_level", 0),
            "rule_desc":  state.detected.get("edr", {}).get("rule_desc", ""),
            "peak_cpu":   round(state.peak_cpu["edr"], 1),
            "peak_ram":   round(state.peak_ram["edr"]),
        },
        "expected_edr":  sample["expected_edr"],
        "expected_ebpf": sample["expected_ebpf"],
    }

    e_ms = result["ebpf"]["latency_ms"]
    d_ms = result["edr"]["latency_ms"]
    if e_ms is not None and d_ms is None:
        result["winner"] = "ebpf"
    elif d_ms is not None and e_ms is None:
        result["winner"] = "edr"
    elif e_ms is not None and d_ms is not None:
        result["winner"] = "ebpf" if e_ms < d_ms else ("edr" if d_ms < e_ms else "tie")
    else:
        result["winner"] = "none"

    state.results.append(result)
    state.active_test = None
    state.test_start_ts = None

    await broadcast({"type": "result", "result": result})


async def reset_test():
    state.active_test = None
    state.test_start_ts = None
    state.detected = {}
    await broadcast({"type": "test_reset"})


# ---------- RUN ALL ----------

async def start_run_all(interval: int):
    if state.run_all_task and not state.run_all_task.done():
        await broadcast({"type": "error", "msg": "Run All ажиллаж байна"})
        return
    state.run_all_task = asyncio.create_task(_run_all_loop(interval))
    await broadcast({"type": "run_all_started", "total": len(SAMPLES), "interval": interval})


async def _run_all_loop(interval: int):
    try:
        for idx, sample in enumerate(SAMPLES):
            await broadcast({
                "type": "run_all_progress",
                "current": idx + 1,
                "total": len(SAMPLES),
                "sample_id": sample["id"],
            })
            await start_test(sample["id"])
            await trigger_cleanup()
            if idx < len(SAMPLES) - 1:
                await asyncio.sleep(interval)
        await broadcast({"type": "run_all_done", "results_count": len(state.results)})
    except asyncio.CancelledError:
        await broadcast({"type": "run_all_stopped"})


async def stop_run_all():
    if state.run_all_task and not state.run_all_task.done():
        state.run_all_task.cancel()
        try:
            await state.run_all_task
        except asyncio.CancelledError:
            pass


# ---------- CLEANUP ----------

async def trigger_cleanup():
    for agent_key, ws in state.agents.items():
        try:
            await ws.send_json({"cmd": "cleanup"})
        except Exception as e:
            print(f"[cleanup] {agent_key} алдаа: {e}")
    await broadcast({"type": "cleanup_started"})


# ---------- CSV EXPORT ----------

@app.get("/api/results.csv")
async def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Timestamp", "Sample ID", "Sample Name", "Technique",
        "Expected EDR", "EDR Detected", "EDR Latency (ms)", "EDR Rule Level", "EDR Rule ID",
        "Expected eBPF", "eBPF Detected", "eBPF Latency (ms)", "eBPF Rule Level", "eBPF Rule ID",
        "EDR Peak CPU %", "EDR Peak RAM MB",
        "eBPF Peak CPU %", "eBPF Peak RAM MB",
        "Winner",
    ])
    for r in state.results:
        writer.writerow([
            r["ts"], r["sample_id"], r["sample_name"], r["tech"],
            "yes" if r["expected_edr"] else "no",
            "yes" if r["edr"]["detected"] else "no",
            r["edr"]["latency_ms"] or "",
            r["edr"]["rule_level"] or "",
            r["edr"]["rule_id"] or "",
            "yes" if r["expected_ebpf"] else "no",
            "yes" if r["ebpf"]["detected"] else "no",
            r["ebpf"]["latency_ms"] or "",
            r["ebpf"]["rule_level"] or "",
            r["ebpf"]["rule_id"] or "",
            r["edr"]["peak_cpu"], r["edr"]["peak_ram"],
            r["ebpf"]["peak_cpu"], r["ebpf"]["peak_ram"],
            r["winner"],
        ])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=benchmark_{datetime.now():%Y%m%d_%H%M%S}.csv"},
    )


# ---------- STARTUP ----------

@app.on_event("startup")
async def on_startup():
    asyncio.create_task(tail_wazuh_alerts())


FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

@app.get("/")
async def root():
    return FileResponse(FRONTEND_DIR / "index.html")

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8765)
