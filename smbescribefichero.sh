#!/bin/bash
# Comprueba si puedes escribir en shares SMB sin credenciales

target=$1
test_file="/tmp/smb_test_$$.txt"

echo "test from $(date)" > "$test_file"

echo "[+] Probando escritura en shares SMB de $target"

shares=$(smbclient -L //$target -N 2>/dev/null | grep -E '^[[:space:]]+[A-Za-z0-9_]+' | awk '{print $1}')

for share in $shares; do
    if [ "$share" != "IPC$" ] && [ "$share" != "print$" ]; then
        echo -n "[*] Probando $share... "
        
        # Intenta subir archivo
        if smbclient -N //$target/$share -c "put $test_file test_upload_$$.txt; rm test_upload_$$.txt" 2>&1 | grep -q "putting file"; then
            echo "¡PUEDES ESCRIBIR!"
            echo "    Share $share es WRITABLE sin credenciales!"
            
            # Pregunta si quieres dejar un "mensaje"
            read -p "¿Dejar un archivo README.txt? (y/N): " choice
            if [[ $choice == "y" || $choice == "Y" ]]; then
                echo "¡Este sistema es vulnerable! Por favor, parchee SMB." > /tmp/README.txt
                smbclient -N //$target/$share -c "put /tmp/README.txt PLEASE_PATCH_SMB.txt" 2>/dev/null
                echo "    Archivo dejado: PLEASE_PATCH_SMB.txt"
            fi
        else
            echo "solo lectura"
        fi
    fi
done

rm -f "$test_file"
