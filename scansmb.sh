
# sumple script para escanear el servicioSamba SMB versiñin 1, en Bash Shell 1.0.x, con nmap
# uso.:  $./escansbm.sh  IP/rango 
# (r) hackingyseguridad.com 2026
# @antonio_taboada

nmap -Pn -sVC -p 139,445 $1 $2 --script smb-vuln-ms17-010 
