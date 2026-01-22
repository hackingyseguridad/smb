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

**Detecta version**

- nxc smb 10.0.0.1
- smbclient -L //10.0.0.1/ -m NT1  
- nmap -Pn -sVC -p 139,445 10.0.0.1 --script smb-vuln-ms17-010  

***EthernalBlue*** es un exploit creado por la NSA como herramienta de ciberseguridad. El nombre oficial del exploit, proporcionado por Microsoft, es **MS17-010**. Este exploit no es específico de dispositivos Windows, sino que afecta a cualquier dispositivo compatible con el protocolo de servidor SMBv1 de Microsoft

<img style="float:left" alt="SMBv1" src="https://github.com/hackingyseguridad/smb/blob/main/smb.png">

SMBv1 en: Microsoft Windows Vista SP2; Windows Server 2008 SP2 y R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold y R2; Windows RT 8.1 y Windows 10 Gold, 1511 y 1607 y Windows Server 2016 permite a atacantes remotos ejecutar código arbitrario a través de paquetes manipulados, vulnerabilidad también conocida como "Windows SMB Remote Code Execution Vulnerability". Esta vulnerabilidad es distinta de aquellas descritas en CVE-2017-0144, CVE-2017-0145, CVE-2017-0146 y CVE-2017-0148.




#
http://www.hackingyseguridad.com/
#
