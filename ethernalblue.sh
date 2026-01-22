#!/bin/sh
# Exploit para SMB versiñin 1, en Bash Shell 1.0.x, con Metaexploit
# uso.:  $./ethernalblue.sh  IP/fqdn 
# (r) hackingyseguridad.com 2026

msfconsole -q -x "use auxiliary/scanner/smb/smb_ms17_010; set RHOSTS $1; run; exit"
