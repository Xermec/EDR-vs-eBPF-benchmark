#!/bin/bash
# Sample 01 — EICAR test file
# Хүлээж буй: EDR signature-based illrüülne
SAMPLE_DIR="$(dirname "$0")"
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar_$$.com
sleep 2
ls -la /tmp/eicar_$$.com 2>&1 || echo "EICAR ustsaan (EDR detected)"
rm -f /tmp/eicar_$$.com 2>/dev/null
