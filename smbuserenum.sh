#!/bin/bash
# Enumera usuarios del dominio/systema via SMB

target=$1

echo "[+] Intentando enumerar usuarios en $target"

# Método 1: Via RPC (si IPC$ está accesible)
echo "[*] Método 1: RPC через IPC$"
rpcclient -U "" -N $target -c "enumdomusers" 2>/dev/null | grep -o '\[.*\]' | tr -d '[]' | head -20

# Método 2: Via SMB session
echo ""
echo "[*] Método 2: Probando usuarios comunes"

common_users=("administrator" "admin" "guest" "user" "test" "backup" "web" "sql" "oracle")

for user in "${common_users[@]}"; do
    echo -n "  Probando $user... "
    
    # Intenta autenticar
    if smbclient -L //$target -U "$user%invalidpass" 2>&1 | grep -q "NT_STATUS_NO_SUCH_USER"; then
        echo "NO EXISTE"
    elif smbclient -L //$target -U "$user%invalidpass" 2>&1 | grep -q "NT_STATUS_LOGON_FAILURE"; then
        echo "EXISTE (pero password incorrecta)"
    else
        echo "RESPUESTA INESPERADA"
    fi
done

# Método 3: Lookupsid si disponible
echo ""
echo "[*] Método 3: SID enumeration"
if command -v lookupsid &> /dev/null; then
    lookupsid $target 2>/dev/null | head -20
fi
