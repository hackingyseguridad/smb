#!/bin/sh
# simple script para escanear el servicioSamba SMB versiñin 1, en Bash Shell 1.0.x, con nmap
# uso.:  $./escansbm.sh  IP/rango 
# (r) hackingyseguridad.com 2026
# https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html

nmap -Pn -sVC -p 139,445 --open -O  $1 $2 --script smb-vuln-ms17-010 
