#!/bin/bash
# SMB EASY PEEK - Encuentra shares sin password
# Requiere: smbclient (sudo apt install samba-common)

target=$1

echo "[+] Buscando shares SMB en $target"
echo "[+] Esto funciona si NULL sessions están habilitadas"

# Lista todos los shares
smbclient -L //$target -N 2>/dev/null | grep -E '^[[:space:]]+[A-Za-z]' | awk '{print $1}' > /tmp/shares.txt

if [ -s /tmp/shares.txt ]; then
    echo "[+] ¡SHARES ENCONTRADOS!"
    cat /tmp/shares.txt
    
    # Intenta acceder a cada share
    while read share; do
        echo "[*] Probando acceso a: $share"
        
        # Intenta listar archivos
        smbclient -N //$target/$share -c "ls; quit" 2>/dev/null | head -5
        
        # Si es IPC$, extrae más info
        if [ "$share" = "IPC$" ]; then
            echo "[*] IPC$ encontrado - intentando extraer info..."
            rpcclient -U "" -N $target -c "enumdomusers" 2>/dev/null | head -5
        fi
    done < /tmp/shares.txt
else
    echo "[-] No se encontraron shares accesibles"
fi

rm -f /tmp/shares.txt
