
#!/bin/bash

# Script versión 1.0.x mínima
# Lee IPs de ip.txt y ejecuta nxc smb

while IFS= read -r IP; do
    if [ -n "$IP" ]; then
        echo "Probando: $IP"
        nxc smb "$IP"
        echo "-------------------"
    fi
done < ip.txt
