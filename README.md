```
 ███████╗ ███╗   ███╗ ██████╗
██╔════╝ ████╗ ████║ ██╔══██╗
███████╗ ██╔████╔██║ ██████╔╝
╚════██║ ██║╚██╔╝██║ ██╔══██╗
███████║ ██║ ╚═╝ ██║ ██████╔╝
╚══════╝ ╚═╝     ╚═╝ ╚═════╝
```
SMB es un protocolo de red que permite compartir archivos, impresoras y otros recursos entre maquinas. 
SMB v1 (Server Message Block versión 1) es un protocolo antiguo, inseguro y obsoleto para compartir archivos en red.

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

***EthernalBlue*** es un exploit creado por la NSA como herramienta de ciberseguridad. El nombre oficial del exploit, proporcionado por Microsoft, es MS17-010. Este exploit no es específico de dispositivos Windows, sino que afecta a cualquier dispositivo compatible con el protocolo de servidor SMBv1 de Microsoft

<img style="float:left" alt="SMBv1" src="https://github.com/hackingyseguridad/smb/blob/main/smb.png">

#
http://www.hackingyseguridad.com/
#
