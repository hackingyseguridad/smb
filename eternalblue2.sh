#!/bin/bash
# EternalBlue Scanner 
# Detecta variantes y configuraciones vulnerables

check_eternalblue_variants() {
    local ip=$1
    local port=${2:-445}
    
    echo "[*] Probando variantes EternalBlue en $ip:$port"
    
    # Variante 1: Transacción básica (original)
    packet1="00000085ff534d427200000000185301280000000000000000000000000000000000fffe0000000000000000000000000000000000000000000000001c000000004100414141414141414141414141414141414141414141414141414141414141"
    
    # Variante 2: EternalRomance (para Windows 8/2012)
    packet2="00000090ff534d427200000000185301280000000000000000000000000000000000fffe0000000000000000000000000000000000000000000000001c000100004543424141414141414141414141414141414141414141414141414141414141"
    
    # Variante 3: EternalSynergy (Windows 10)
    packet3="00000088ff534d427200000000185301280000000000000000000000000000000000fffe0000000000000000000000000000000000000000000000001c0002000053594e4141414141414141414141414141414141414141414141414141414141"
    
    for i in {1..3}; do
        var_name="packet$i"
        packet=${!var_name}
        
        echo -n "$packet" | xxd -r -p | timeout 2 nc -w1 $ip $port > /tmp/response_$i.bin 2>/dev/null
        
        if [ -s "/tmp/response_$i.bin" ]; then
            hexdump -C "/tmp/response_$i.bin" | head -5
            echo "[!] Respuesta recibida para variante $i"
        fi
    done
    
    rm -f /tmp/response_*.bin
}
