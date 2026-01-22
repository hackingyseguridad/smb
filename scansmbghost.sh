#!/bin/bash
# CVE-2020-0796 (SMBGhost) Scanner
# Vulnerability in SMBv3.1.1 compression

scan_smbghost() {
    local target=$1
    local port=${2:-445}
    
    echo -e "\n${BLUE}[*]${NC} Scanning for SMBGhost (CVE-2020-0796) on $target"
    
    # Craft SMBv3.1.1 negotiate packet with compression
    create_smbghost_probe() {
        # NetBIOS header
        printf "\\x00\\x00\\x00\\x9f"
        
        # SMB2 header
        printf "\\xfe\\x53\\x4d\\x42"  # SMB2 magic
        printf "\\x40\\x00\\x00\\x00"  # Header length
        printf "\\x00\\x00\\x00\\x00"  # Credit charge
        printf "\\x01\\x00"            # Channel sequence
        printf "\\x00\\x00"            # Reserved
        printf "\\x00\\x00\\x00\\x00"  # Command (negotiate)
        printf "\\x00\\x00\\x00\\x00"  # Status
        printf "\\x01\\x00"            # Flags
        printf "\\x00\\x00"            # Next command
        printf "\\x00\\x00\\x00\\x00"  # Message ID
        printf "\\x00\\x00\\x00\\x00"  # Reserved
        printf "\\x00\\x00\\x00\\x00"  # Tree ID
        printf "\\x00\\x00\\x00\\x00"  # Session ID
        printf "\\x00\\x00\\x00\\x00"  # Signature
        
        # SMB2 Negotiate request
        printf "\\x39\\x00"            # Structure size
        printf "\\x02"                 # Dialect count
        printf "\\x00"                 # Security mode
        printf "\\x01\\x00"            # Reserved
        printf "\\x00\\x00\\x00\\x00"  # Capabilities
        printf "\\x00\\x00\\x00\\x00"  # Client GUID
        printf "\\x00\\x00\\x00\\x00"
        printf "\\x00\\x00\\x00\\x00"
        printf "\\x00\\x00\\x00\\x00"
        
        # Dialects: SMB 3.1.1 and 3.0.2
        printf "\\x02\\x00"            # SMB 2.???
        printf "\\x10\\x02"            # SMB 3.0.2
        printf "\\x02\\x00"            # SMB 2.???
        printf "\\x11\\x02"            # SMB 3.1.1 (VULNERABLE)
    }
    
    # Send probe
    probe=$(create_smbghost_probe)
    echo -n "$probe" | timeout 3 nc -w1 $target $port > /tmp/smbghost_response.bin 2>/dev/null
    
    if [ $? -eq 0 ] && [ -s "/tmp/smbghost_response.bin" ]; then
        # Check for SMB3.1.1 in response
        hexdump -C "/tmp/smbghost_response.bin" | grep -A2 -B2 "11 02" > /dev/null
        
        if [ $? -eq 0 ]; then
            echo -e "${RED}[!]${NC} SMBv3.1.1 detected - Potentially VULNERABLE to SMBGhost!"
            echo "    Windows 10 v1903-v1909 with unpatched SMBv3"
            
            # Additional check for compression support
            if hexdump -C "/tmp/smbghost_response.bin" | grep -q "03 00..00 01"; then
                echo -e "${RED}[!]${NC} Compression enabled - HIGHLY LIKELY VULNERABLE!"
                echo "CVE-2020-0796 - Remote code execution possible"
            fi
        else
            echo -e "${GREEN}[+]${NC} SMBv3.1.1 not detected or patched"
        fi
    else
        echo -e "${YELLOW}[-]${NC} No response or SMBv3 not supported"
    fi
    
    rm -f /tmp/smbghost_response.bin
}
