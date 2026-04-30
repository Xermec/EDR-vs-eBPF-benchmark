#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
RWX Hunter v3 — Multi-vector eBPF detection
Шинэ боломжууд (v2-аас):
  - memfd_create syscall tracking (T1620 fileless ELF)
  - execve from /proc/self/fd/ (memfd_create-аас execute)
  - execve from /tmp, /dev/shm, /var/tmp (Sample 02, 06, 09)
  - sustained CPU monitoring (cryptominer simulation)
  - Reverse shell port connect detection (Sample 08, 10)
  - Crontab modification tracking (Sample 10)
  - Python script-аас RWX дуудаагдвал JIT bonus олгохгүй
    (Sample 07 — Python ctypes injector)
"""

from bcc import BPF
import psutil
import os
import time
import threading
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- ТОХИРГОО ---

JIT_EXE_PATTERNS = [
    '/usr/bin/python', '/usr/local/bin/python',
    '/usr/bin/java', '/usr/lib/jvm',
    '/usr/bin/node', '/usr/local/bin/node',
    '/usr/bin/ruby', '/usr/bin/perl',
    '/usr/lib/chromium', '/usr/lib/firefox',
    '/opt/google/chrome',
]

# Python script-уудыг бид JIT гэж үзэхгүй, харин malware-ийн нэг хэлбэр гэж үзнэ
# Хэрэв cmdline-д суспициус .py файл байгаа бол JIT bonus олгохгүй
SUSPICIOUS_SCRIPT_PATTERNS = [
    'inject', 'implant', 'shellcode', 'reverse', 'payload',
    '/tmp/', '/dev/shm/',
]

SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/', '/root/']

SUSPICIOUS_PORTS = {4444, 1337, 5555, 6666, 7777, 8888, 9999, 31337, 4445, 2222}

TRUSTED_SYSTEM_PROCS = {
    'networkd-dispat', 'unattended-upgr', 'systemd', 'snapd',
    'dockerd', 'containerd', 'kubelet', 'wazuh-agent',
}

# CPU sustained detection-ы хязгаар
CPU_SUSTAINED_THRESHOLD = 80.0  # %
CPU_SUSTAINED_DURATION = 3      # хэдэн удаагийн дарааллын interval

# Alert dedup — нэг л удаа alert өгөх
_alerted_pids = set()
_alerted_lock = threading.Lock()


def alert_once(key):
    """Adagdsan key-г track хийж true / false буцаана."""
    with _alerted_lock:
        if key in _alerted_pids:
            return False
        _alerted_pids.add(key)
        return True


# --- HELPERS ---

def get_process_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        return ""


def get_network_activity(pid):
    connections = []
    try:
        proc = psutil.Process(pid)
        try:
            conns = proc.net_connections(kind='inet')
        except AttributeError:
            conns = proc.connections(kind='inet')
        for conn in conns:
            if conn.status == 'ESTABLISHED' and conn.raddr:
                rip = conn.raddr.ip
                rport = conn.raddr.port
                if not rip.startswith('127.') and rip != '::1':
                    connections.append((rip, rport))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return connections


def is_jit_process(exe_path, cmdline):
    """JIT эсэхийг шалгах. Гэхдээ суспициус script ашиглаж байвал JIT гэж үзэхгүй."""
    if not exe_path:
        return False

    # Cmdline дотор сэжигтэй pattern байвал JIT bonus олгохгүй
    cmd_lower = (cmdline or "").lower()
    for pat in SUSPICIOUS_SCRIPT_PATTERNS:
        if pat in cmd_lower:
            return False

    for pattern in JIT_EXE_PATTERNS:
        if exe_path.startswith(pattern):
            return True
    return False


def is_suspicious_path(path):
    if not path:
        return False
    for sp in SUSPICIOUS_PATHS:
        if path.startswith(sp):
            return True
    return False


def is_trusted_system(comm_name, exe_path):
    if comm_name in TRUSTED_SYSTEM_PROCS:
        if exe_path and (exe_path.startswith('/usr/') or exe_path.startswith('/lib/')):
            return True
    return False


# --- THREAT ANALYSIS ---

def analyze_threat(pid, process_name, exe_path, evidence, source="SNAPSHOT", base_score=40, vector="RWX"):
    """
    evidence: тухайн илрүүлэлтийн нотолгоо (string)
    base_score: detection vector-аас хамаарч анхны оноо
    vector: RWX, MEMFD, EXEC_TMP, CONN_C2, CRON, CPU_SPIKE
    """
    cmdline = get_process_cmdline(pid)
    score = base_score
    reasons = [f"[{vector}] {evidence}"]

    net_conns = get_network_activity(pid)
    jit = is_jit_process(exe_path, cmdline)
    susp_path = is_suspicious_path(exe_path)
    trusted = is_trusted_system(process_name, exe_path)

    if trusted and not susp_path and vector == "RWX":
        return

    if jit and vector == "RWX":
        score -= 20
        reasons.append("JIT/Runtime процесс (хэвийн байж болно)")

    if susp_path:
        score += 35
        reasons.append(f"Сэжигтэй байрлалд ажиллаж байна: {exe_path}")

    try:
        real_exe = os.readlink(f"/proc/{pid}/exe")
        if "(deleted)" in real_exe:
            score += 25
            reasons.append("Executable устгагдсан байна (in-memory loader)")
    except Exception:
        pass

    suspicious_conns = []
    normal_conns = []
    for (rip, rport) in net_conns:
        if rport in SUSPICIOUS_PORTS:
            suspicious_conns.append(f"{rip}:{rport}")
            score += 40
            reasons.append(f"Сэжигтэй порт руу холбогдсон: {rip}:{rport}")
        else:
            normal_conns.append(f"{rip}:{rport}")
            score += 10
            reasons.append(f"Гадаад холболт: {rip}:{rport}")

    if score >= 80:
        threat_level = "CRITICAL"
    elif score >= 55:
        threat_level = "HIGH"
    elif score >= 35:
        threat_level = "MEDIUM"
    else:
        threat_level = "INFO"

    if threat_level == "INFO":
        return

    sep = "=" * 55
    print(f"\n{sep}")
    print(f"  [{source}] {threat_level} ALERT")
    print(f"{sep}")
    print(f"  Vector  : {vector}")
    print(f"  Process : {process_name} (PID: {pid})")
    print(f"  Path    : {exe_path or 'Unknown'}")
    print(f"  Cmdline : {cmdline[:120]}")
    print(f"  Score   : {score}/100")
    if suspicious_conns:
        print(f"  [!!!] Suspicious C2 : {suspicious_conns}")
    if normal_conns:
        print(f"  Network : {normal_conns}")
    print(f"  Reasons :")
    for r in reasons:
        print(f"    - {r}")
    print(f"{sep}", flush=True)


# --- 1. SNAPSHOT SCANNER ---

def scan_existing_rwx():
    print("[*] Одоо ажиллаж байгаа процессуудыг RWX-ийн хувьд скан хийж байна...")
    found = 0
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            if pid < 10 or pid == os.getpid():
                continue
            maps_path = f"/proc/{pid}/maps"
            if not os.path.exists(maps_path):
                continue
            with open(maps_path, 'r', errors='replace') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) > 1 and 'rwx' in parts[1]:
                        analyze_threat(
                            pid, proc.info['name'], proc.info['exe'],
                            line.strip(),
                            source="SNAPSHOT", base_score=40, vector="RWX"
                        )
                        found += 1
                        break
        except Exception:
            continue
    print(f"[*] Скан дууслаа. {found} RWX mapping олдсон.\n")


# --- 2. eBPF REAL-TIME PROBES ---

# RWX болон бусад syscall тэмдэгшил.
# Note: BPF program нь kernel-д run хийгдэх ба перс buffer-ээр userspace-руу event илгээдэг.
bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct rwx_data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8  vec;       // 1=mmap_rwx, 2=mprotect_rwx, 3=memfd_create, 4=execve_proc_fd, 5=execve_tmp
    char extra[128];
};

BPF_PERF_OUTPUT(events);

// 1. mmap RWX
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    unsigned long prot = args->prot;
    if ((prot & 7) == 7) {
        struct rwx_data_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.vec = 1;
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

// 2. mprotect WRITE+EXEC
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    unsigned long prot = args->prot;
    if ((prot & 6) == 6) {
        struct rwx_data_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.vec = 2;
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

// 3. memfd_create — fileless ELF tehnik (T1620)
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    struct rwx_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.vec = 3;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

// 4. execve from /proc/self/fd/ — memfd-аас execute
// 5. execve from /tmp /dev/shm — disk drop
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct rwx_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // Filename агуулна — string compare
    const char *filename = (const char *)args->filename;
    char fn[64] = {};
    bpf_probe_read_user_str(fn, sizeof(fn), filename);

    // /proc/self/fd/ эсвэл /proc/<n>/fd/
    if (fn[0] == '/' && fn[1] == 'p' && fn[2] == 'r' && fn[3] == 'o' && fn[4] == 'c' && fn[5] == '/') {
        // /proc/...
        // Зөвхөн /proc/self/fd эсвэл /proc/<digit>/fd замуудтай шалгах
        int has_fd = 0;
        #pragma unroll
        for (int i = 6; i < 60; i++) {
            if (fn[i] == 0) break;
            if (fn[i] == 'f' && fn[i+1] == 'd' && fn[i+2] == '/') {
                has_fd = 1;
                break;
            }
        }
        if (has_fd) {
            data.vec = 4;
            __builtin_memcpy(data.extra, fn, sizeof(data.extra) < sizeof(fn) ? sizeof(data.extra) : sizeof(fn));
            events.perf_submit(args, &data, sizeof(data));
            return 0;
        }
    }

    // /tmp/ эсвэл /dev/shm/ эсвэл /var/tmp/
    if (fn[0] == '/' && fn[1] == 't' && fn[2] == 'm' && fn[3] == 'p' && fn[4] == '/') {
        data.vec = 5;
        __builtin_memcpy(data.extra, fn, sizeof(data.extra) < sizeof(fn) ? sizeof(data.extra) : sizeof(fn));
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
    if (fn[0] == '/' && fn[1] == 'd' && fn[2] == 'e' && fn[3] == 'v' && fn[4] == '/' &&
        fn[5] == 's' && fn[6] == 'h' && fn[7] == 'm' && fn[8] == '/') {
        data.vec = 5;
        __builtin_memcpy(data.extra, fn, sizeof(data.extra) < sizeof(fn) ? sizeof(data.extra) : sizeof(fn));
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }
    if (fn[0] == '/' && fn[1] == 'v' && fn[2] == 'a' && fn[3] == 'r' && fn[4] == '/' &&
        fn[5] == 't' && fn[6] == 'm' && fn[7] == 'p' && fn[8] == '/') {
        data.vec = 5;
        __builtin_memcpy(data.extra, fn, sizeof(data.extra) < sizeof(fn) ? sizeof(data.extra) : sizeof(fn));
        events.perf_submit(args, &data, sizeof(data));
        return 0;
    }

    return 0;
}

// 6. connect() syscall — reverse shell C2 detection
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct rwx_data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.vec = 6;
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


def print_event(cpu, data, size):
    event = b["events"].event(data)
    pid = int(event.pid)
    process_name = event.comm.decode('utf-8', 'replace').strip('\x00')
    vec = int(event.vec)
    extra = event.extra.decode('utf-8', 'replace').strip('\x00') if hasattr(event, 'extra') else ""

    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
    except Exception:
        exe_path = "Unknown/Exited"

    if vec == 1:
        if not alert_once(f"rwx_{pid}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       "Dynamic mmap(RWX) via syscall",
                       source="REALTIME", base_score=40, vector="RWX")

    elif vec == 2:
        if not alert_once(f"mprot_{pid}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       "mprotect WRITE+EXEC (RW->RWX)",
                       source="REALTIME", base_score=40, vector="MPROTECT")

    elif vec == 3:
        # memfd_create — олон тооны legitimate ашиглалт байдаг (snap, systemd)
        # тиймээс зөвхөн сэжигтэй процессуудыг л track хийнэ
        if process_name in TRUSTED_SYSTEM_PROCS:
            return
        if not alert_once(f"memfd_{pid}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       "memfd_create syscall (fileless ELF technique)",
                       source="REALTIME", base_score=35, vector="MEMFD")

    elif vec == 4:
        # /proc/self/fd/N execute — энэ бол memfd-аас run хийж байгаа зорилго
        if not alert_once(f"procfd_{pid}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       f"execve /proc/.../fd/ — fileless ELF: {extra}",
                       source="REALTIME", base_score=70, vector="MEMFD_EXEC")

    elif vec == 5:
        # /tmp /dev/shm /var/tmp execute — drop & run
        if not alert_once(f"tmpexec_{pid}_{extra}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       f"execve from suspicious path: {extra}",
                       source="REALTIME", base_score=45, vector="EXEC_TMP")

    elif vec == 6:
        # connect() — нэн даруй RIP/RPORT-г шалгах (асинхрон)
        threading.Thread(target=delayed_connect_check,
                         args=(pid, process_name, exe_path),
                         daemon=True).start()


def delayed_connect_check(pid, process_name, exe_path):
    """connect() syscall эхэлсний дараа 0.5 секунд хүлээгээд ESTABLISHED state шалгана."""
    time.sleep(0.5)
    conns = get_network_activity(pid)
    for rip, rport in conns:
        if rport in SUSPICIOUS_PORTS:
            if not alert_once(f"conn_{pid}_{rip}_{rport}"):
                return
            analyze_threat(pid, process_name, exe_path,
                           f"Reverse shell port connect: {rip}:{rport}",
                           source="REALTIME", base_score=60, vector="CONN_C2")
            return


# --- 3. CRONTAB MONITOR ---

def crontab_watcher():
    """
    /var/spool/cron/* болон /etc/cron.d/-ыг 2 sec тутамд шалгана.
    Файл өөрчлөгдвөл alert.
    """
    paths_to_watch = ["/var/spool/cron/crontabs", "/etc/cron.d", "/var/spool/cron"]
    last_state = {}

    # Анхны төлөв
    for d in paths_to_watch:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            full = os.path.join(d, f)
            try:
                last_state[full] = os.path.getmtime(full)
            except Exception:
                pass

    while True:
        time.sleep(2)
        for d in paths_to_watch:
            if not os.path.isdir(d):
                continue
            try:
                for f in os.listdir(d):
                    full = os.path.join(d, f)
                    try:
                        mtime = os.path.getmtime(full)
                    except Exception:
                        continue
                    prev = last_state.get(full)
                    if prev is None or mtime > prev:
                        last_state[full] = mtime
                        # Шинэ агуулгыг шалгах (reverse shell pattern)
                        try:
                            with open(full, 'r', errors='replace') as fp:
                                content = fp.read()
                        except Exception:
                            content = ""
                        suspicious = any(p in content for p in
                                          ["/dev/tcp/", "bash -i", "nc -e", "mkfifo"])
                        if suspicious or prev is not None:
                            if not alert_once(f"cron_{full}_{mtime}"):
                                continue
                            analyze_threat(0, "crontab", full,
                                           f"Crontab modified: {full}",
                                           source="CRONTAB", base_score=55,
                                           vector="CRON")
            except Exception:
                continue


# --- 4. CPU SUSTAINED MONITOR ---

def cpu_watcher():
    """
    Системийн CPU-г 2 sec тутамд шалгана. CPU_SUSTAINED_DURATION удаа
    дараалан THRESHOLD-аас өндөр байвал alert.
    """
    consecutive = 0
    psutil.cpu_percent(interval=None)  # эхний дуудлага reset
    while True:
        time.sleep(2)
        cpu = psutil.cpu_percent(interval=None)
        if cpu > CPU_SUSTAINED_THRESHOLD:
            consecutive += 1
            if consecutive >= CPU_SUSTAINED_DURATION:
                # Хамгийн өндөр CPU-тэй процесс
                top = sorted(psutil.process_iter(["pid", "name", "exe"]),
                             key=lambda p: p.cpu_percent(interval=None) if p.is_running() else 0,
                             reverse=True)
                # Топ процессыг олох
                top_pid = None
                top_cpu = 0
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        c = proc.cpu_percent(interval=None)
                        if c > top_cpu:
                            top_cpu = c
                            top_pid = proc.info['pid']
                            top_name = proc.info['name']
                            top_exe = proc.info.get('exe') or ""
                    except Exception:
                        continue

                if top_pid and alert_once(f"cpu_spike_{top_pid}_{int(time.time()/30)}"):
                    analyze_threat(top_pid, top_name, top_exe,
                                   f"Sustained high CPU ({cpu:.0f}% for {CPU_SUSTAINED_DURATION*2}s)",
                                   source="CPU_MON", base_score=50, vector="CPU_SPIKE")
                consecutive = 0  # reset
        else:
            consecutive = 0


# --- 5. ALERT CACHE CLEANUP ---

def cleanup_alert_cache():
    """5 минут тутамд _alerted_pids-ийг цэвэрлэнэ — sample дахин ажиллахад alert өгнө."""
    while True:
        time.sleep(300)
        with _alerted_lock:
            _alerted_pids.clear()
        print("[*] Alert cache цэвэрлэгдлээ\n", flush=True)


# --- MAIN ---

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Root эрх шаардлагатай! sudo-гаар ажиллуулна уу.")
        exit(1)

    # 1. Snapshot
    scan_existing_rwx()

    # 2. Background watcher-уудыг асаах
    threading.Thread(target=crontab_watcher, daemon=True).start()
    threading.Thread(target=cpu_watcher, daemon=True).start()
    threading.Thread(target=cleanup_alert_cache, daemon=True).start()

    # 3. eBPF
    print("[*] eBPF Real-time Monitor v3 эхэллээ (Ctrl+C-гаар зогсооно)...")
    print("[*] Vectors: RWX, MPROTECT, MEMFD, EXEC_TMP, CONN_C2, CRON, CPU_SPIKE\n")
    b = BPF(text=bpf_program)
    b["events"].open_perf_buffer(print_event)

    while True:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            print("\n[*] Monitor зогссон.")
            break
