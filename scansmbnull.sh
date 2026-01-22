#!/bin/bash
# SMB NULL Session Enumeration Tool
# Exploits misconfigured SMB shares

smb_null_session_attack() {
    local target=$1
    echo -e "\n${BLUE}[*]${NC} Performing NULL session enumeration on $target"
    
    # 1. List shares anonymously
    echo "[*] Attempting to list shares..."
    shares=$(timeout 10 smbclient -N -L //$target 2>/dev/null)
    
    if echo "$shares" | grep -q "Anonymous login successful"; then
        echo -e "${RED}[!]${NC} NULL SESSION ALLOWED!"
        
        # Extract share names
        share_list=$(echo "$shares" | grep -E '^[[:space:]]+[A-Za-z0-9_]' | awk '{print $1}')
        
        echo "[*] Discovered shares:"
        for share in $share_list; do
            echo "  - $share"
            
            # Try to access each share
            echo "[*] Testing access to $share"
            
            # Check if it's IPC$ for further enumeration
            if [ "$share" = "IPC$" ]; then
                echo "[*] IPC$ found - attempting RPC enumeration..."
                
                # Try to enumerate via rpcclient
                users=$(timeout 10 rpcclient -U "" -N $target -c "enumdomusers" 2>/dev/null)
                if [ -n "$users" ]; then
                    echo -e "${RED}[!]${NC} User enumeration possible via IPC$"
                    echo "$users" | head -10
                fi
                
                # Try to get domain info
                domain=$(timeout 10 rpcclient -U "" -N $target -c "getdompwinfo" 2>/dev/null)
                if [ -n "$domain" ]; then
                    echo "[+] Domain information retrieved"
                fi
            else
                # Try to list files in regular share
                files=$(timeout 10 smbclient -N //$target/$share -c "ls" 2>/dev/null)
                if echo "$files" | grep -q "blocks available"; then
                    echo "[+] Can list files in $share"
                    
                    # Check write access
                    echo "test" > /tmp/test_smb.txt
                    upload=$(timeout 10 smbclient -N //$target/$share -c "put /tmp/test_smb.txt test_upload.txt" 2>&1)
                    
                    if echo "$upload" | grep -q "putting file"; then
                        echo -e "${RED}[!]${NC} WRITE ACCESS to $share!"
                        # Clean up
                        timeout 5 smbclient -N //$target/$share -c "del test_upload.txt" 2>/dev/null
                    fi
                    rm -f /tmp/test_smb.txt
                fi
            fi
        done
    else
        echo "[+] NULL sessions not allowed or requires authentication"
    fi
}
