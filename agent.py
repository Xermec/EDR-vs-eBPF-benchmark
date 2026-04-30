#!/usr/bin/env python3
"""
Benchmark Agent v2
Шинэ боломжууд:
  - cleanup команд: малware sample-аас үлдсэн процесс цэвэрлэх
  - Sample-ийн PID-ийг хадгалж зөв kill хийх
"""

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil
import websockets

WAZUH_HOST = os.environ.get("WAZUH_HOST", "10.52.1.118")
WAZUH_PORT = int(os.environ.get("WAZUH_PORT", "8765"))
AGENT_KEY = os.environ.get("AGENT_KEY", "ebpf")
SAMPLES_DIR = Path(os.environ.get("SAMPLES_DIR", "/opt/samples"))
METRICS_INTERVAL = 1.0

WS_URL = f"ws://{WAZUH_HOST}:{WAZUH_PORT}/ws/agent/{AGENT_KEY}"

# Идэвхтэй sample процессуудын PID-уудыг track хийх
running_pids = set()


# ---------- METRICS ----------

async def metrics_loop(ws):
    psutil.cpu_percent(interval=None)
    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            net_conns = len([c for c in psutil.net_connections(kind="inet")
                             if c.status == "ESTABLISHED"])
            await ws.send(json.dumps({
                "type": "metrics",
                "cpu": round(cpu, 1),
                "ram_mb": round(mem.used / (1024 * 1024)),
                "ram_pct": round(mem.percent, 1),
                "net_conn": net_conns,
            }))
        except Exception as e:
            print(f"[metrics] алдаа: {e}")
        await asyncio.sleep(METRICS_INTERVAL)


# ---------- SAMPLE RUNNER ----------

async def run_sample(ws, sample_id: str):
    sample_dir = SAMPLES_DIR / sample_id
    run_script = sample_dir / "run.sh"

    if not run_script.exists():
        await ws.send(json.dumps({
            "type": "sample_finished",
            "sample_id": sample_id, "exit_code": -1,
            "stdout": f"run.sh олдсонгүй: {run_script}",
        }))
        return

    print(f"[runner] Sample {sample_id} эхлүүлж байна...")
    proc = await asyncio.create_subprocess_exec(
        "bash", str(run_script),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(sample_dir),
        preexec_fn=os.setsid,  # Шинэ process group — kill үед бүх child-ийг авна
    )
    running_pids.add(proc.pid)

    await ws.send(json.dumps({
        "type": "sample_started",
        "sample_id": sample_id, "pid": proc.pid,
    }))

    try:
        stdout_data, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        stdout_text = stdout_data.decode("utf-8", errors="replace")
        exit_code = proc.returncode
    except asyncio.TimeoutError:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            pass
        await proc.wait()
        stdout_text = "[timeout 30s]"
        exit_code = -2
    finally:
        running_pids.discard(proc.pid)

    print(f"[runner] Sample {sample_id} дууслаа (exit={exit_code})")
    await ws.send(json.dumps({
        "type": "sample_finished",
        "sample_id": sample_id, "exit_code": exit_code,
        "stdout": stdout_text,
    }))


# ---------- CLEANUP ----------

# Манай sample-ууд /tmp/-д үлдээдэг файлын pattern
SUSPICIOUS_PATTERNS = [
    "custom_implant", "xor_implant", "mprot_implant",
    "py_inject", "sample02", "xmrig_fake", "eicar",
]


def kill_process_tree(pid):
    """Process болон бүх child-ыг kill."""
    try:
        parent = psutil.Process(pid)
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        parent.kill()
        return True
    except psutil.NoSuchProcess:
        return False


async def cleanup_processes():
    """
    Малware sample-аас үлдсэн процессуудыг цэвэрлэх:
      1. Хадгалсан running_pids-уудыг kill
      2. /tmp/-аас сэжигтэй файл устгах
      3. Цаашлаад тэр файлуудаас гарсан процессуудыг kill
      4. 4444 порт руу холбогдсон бүх холболтыг таслах
    """
    killed = 0

    # 1. Track хийсэн sample процессууд
    for pid in list(running_pids):
        if kill_process_tree(pid):
            killed += 1
        running_pids.discard(pid)

    # 2-3. Сэжигтэй процесс ба файл
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            exe = proc.info.get("exe") or ""
            cmd = " ".join(proc.info.get("cmdline") or [])
            for pat in SUSPICIOUS_PATTERNS:
                if pat in exe or pat in cmd:
                    proc.kill()
                    killed += 1
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 4. 4444 порт руу холбогдсон процесс (reverse shell)
    for c in psutil.net_connections(kind="inet"):
        if c.raddr and c.raddr.port == 4444:
            try:
                if c.pid:
                    psutil.Process(c.pid).kill()
                    killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    # 5. /tmp/-аас сэжигтэй файлууд устгах
    try:
        for f in Path("/tmp").iterdir():
            if any(pat in f.name for pat in SUSPICIOUS_PATTERNS):
                try:
                    f.unlink()
                except Exception:
                    pass
    except Exception:
        pass

    print(f"[cleanup] {killed} процесс kill-чилсэн")
    return killed


# ---------- COMMAND HANDLER ----------

async def command_loop(ws):
    async for message in ws:
        try:
            data = json.loads(message)
        except Exception:
            continue
        cmd = data.get("cmd")

        if cmd == "run_sample":
            asyncio.create_task(run_sample(ws, data.get("sample_id")))
        elif cmd == "cleanup":
            killed = await cleanup_processes()
            await ws.send(json.dumps({
                "type": "cleanup_done",
                "killed": killed,
            }))


# ---------- MAIN ----------

async def connect_loop():
    while True:
        try:
            print(f"[conn] {WS_URL} руу холбогдож байна...")
            async with websockets.connect(WS_URL, ping_interval=20) as ws:
                print(f"[conn] Холбогдлоо ({AGENT_KEY})")
                await asyncio.gather(
                    metrics_loop(ws),
                    command_loop(ws),
                )
        except Exception as e:
            print(f"[conn] Алдаа: {e}, 5 секундийн дараа дахин оролдоно")
            await asyncio.sleep(5)


if __name__ == "__main__":
    if AGENT_KEY not in ("ebpf", "edr"):
        print("AGENT_KEY env variable нь ebpf эсвэл edr байх ёстой")
        sys.exit(1)
    print(f"=== Benchmark Agent v2 эхэллээ ({AGENT_KEY}) ===")
    print(f"Server: {WS_URL}")
    print(f"Samples: {SAMPLES_DIR}")
    try:
        asyncio.run(connect_loop())
    except KeyboardInterrupt:
        print("\nЗогслоо")
