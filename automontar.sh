#!/bin/bash
# Automontaje de shares SMB encontrados

target=$1
mount_dir="/mnt/smb_scans"

mkdir -p "$mount_dir"

echo "[+] Buscando y montando shares SMB de $target"

# Encuentra todos los shares
shares=$(smbclient -L //$target -N 2>/dev/null | grep -E '^[[:space:]]+[A-Za-z0-9_]+' | awk '{print $1}')

for share in $shares; do
    if [ "$share" != "IPC$" ] && [ "$share" != "print$" ]; then
        mount_point="$mount_dir/${target}_${share}"
        mkdir -p "$mount_point"
        
        echo "[*] Intentando montar //$target/$share en $mount_point"
        
        # Intenta montar sin credenciales primero
        mount -t cifs //$target/$share "$mount_point" -o guest,ro 2>/dev/null
        
        if [ $? -eq 0 ]; then
            echo "[+] ¡MONTADO! Share: $share"
            echo "    Path: $mount_point"
            
            # Lista algunos archivos
            find "$mount_point" -type f 2>/dev/null | head -10
        else
            rmdir "$mount_point" 2>/dev/null
        fi
    fi
done

echo "[+] Montajes completados. Directorio: $mount_dir"
