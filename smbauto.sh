#!/bin/sh
# Prueba servicio SMB Samba
# Lee IPs de ip.txt y ejecuta nxc smb
# hackingyseguridad.com 2026

while IFS= read -r IP; do
    if [ -n "$IP" ]; then
        nxc smb "$IP"
    fi
done < ip.txt
