#!/bin/bash
# Detecta versión SMB y muestra vulnerabilidades conocidas

target=$1

echo "[+] Detectando versión SMB de $target"

# Usa nmap si está disponible
if command -v nmap &> /dev/null; then
    nmap -p 445 --script smb-protocols $target
else
    # Método manual con netcat
    echo -e "\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x01\x28" > /tmp/smb_probe.bin
    echo -e "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" >> /tmp/smb_probe.bin
    echo -e "\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" >> /tmp/smb_probe.bin
    echo -e "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" >> /tmp/smb_probe.bin
    echo -e "\x00\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x02\x00\x02\x50\x43\x20" >> /tmp/smb_probe.bin
    echo -e "\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20" >> /tmp/smb_probe.bin
    echo -e "\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x00" >> /tmp/smb_probe.bin
    
    timeout 3 nc $target 445 < /tmp/smb_probe.bin | strings
fi

echo ""
echo "[+] Vulnerabilidades comunes por versión:"
echo "----------------------------------------"
echo "SMBv1: MS17-010 (EternalBlue), MS08-068"
echo "SMBv2: Algunas configuraciones malas"
echo "SMBv3: CVE-2020-0796 (SMBGhost) en Windows 10 v1903-1909"
echo ""
echo "[+] Comando para deshabilitar SMBv1 (en Windows):"
echo "    Set-ItemProperty -Path \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" SMB1 -Type DWORD -Value 0 -Force"
