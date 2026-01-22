#!/bin/bash
# CVE-2021-44142 - Samba VFS Fruit Module Exploit Checker
# Affects Samba with vfs_fruit enabled

check_samba_fruit_vuln() {
    local target=$1
    local port=${2:-445}
    
    echo -e "\n${BLUE}[*]${NC} Checking for Samba CVE-2021-44142 on $target"
    
    # Method 1: Try to connect and check share list
    echo "[*] Attempting anonymous connection..."
    shares=$(timeout 5 smbclient -N -L //$target 2>/dev/null | grep -v "^\$" | grep -v "Anonymous" | awk '{print $1}')
    
    if [ -n "$shares" ]; then
        echo "[+] Shares found:"
        echo "$shares"
        
        # Test each share for vulnerability indicators
        for share in $shares; do
            echo "[*] Testing share: $share"
            
            # Check if share supports Apple extensions (vfs_fruit)
            smb_cmd="logon ./ = no; treeconnect $share; getattr altstream"
            
            echo "$smb_cmd" | timeout 5 smbclient -N //$target/$share 2>&1 | grep -i "NT_STATUS" > /dev/null
            
            if [ $? -eq 0 ]; then
                echo "[+] Share $share accepts SMB commands"
                
                # Attempt to exploit - SAFE CHECK ONLY
                # Try to list with streams (indicator of vfs_fruit)
                timeout 5 smbclient -N //$target/$share -c "allinfo ." 2>&1 | grep -i "stream" > /dev/null
                
                if [ $? -eq 0 ]; then
                    echo -e "${RED}[!]${NC} Share $share has alternate data streams (vfs_fruit可能)"
                    echo "    CVE-2021-44142可能 - 需要进一步验证"
                fi
            fi
        done
    else
        # Method 2: Direct protocol check
        echo "[*] Performing direct SMB protocol check..."
        
        # Craft SMB packet to check capabilities
        create_samba_probe() {
            # Simple negotiate request
            printf "\\x00\\x00\\x00\\x4e"
            printf "\\xff\\x53\\x4d\\x42\\x72\\x00\\x00\\x00\\x00"
            printf "\\x18\\x01\\x28\\x00\\x00\\x00\\x00\\x00\\x00"
            printf "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
            printf "\\x00\\x00\\xff\\xfe\\x00\\x00\\x00\\x00\\x00"
            printf "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
            printf "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x1c"
            printf "\\x00\\x00\\x00\\x00\\x02\\x00\\x02\\x50\\x43"
            printf "\\x20\\x4e\\x45\\x54\\x57\\x4f\\x52\\x4b\\x20"
            printf "\\x50\\x52\\x4f\\x47\\x52\\x41\\x4d\\x20\\x31"
            printf "\\x2e\\x30\\x00\\x02\\x4c\\x41\\x4e\\x4d\\x41"
            printf "\\x4e\\x31\\x2e\\x30\\x00\\x00\\x00"
        }
        
        probe=$(create_samba_probe)
        echo -n "$probe" | timeout 3 nc -w1 $target $port > /tmp/samba_response.bin 2>/dev/null
        
        if [ -s "/tmp/samba_response.bin" ]; then
            # Check for Samba in response
            strings "/tmp/samba_response.bin" | grep -i "samba" > /dev/null
            if [ $? -eq 0 ]; then
                echo -e "${YELLOW}[!]${NC} Samba detected - Check version for CVE-2021-44142"
                echo "    Vulnerable if version < 4.13.17, 4.14.12, 4.15.5"
            fi
        fi
        
        rm -f /tmp/samba_response.bin
    fi
}
