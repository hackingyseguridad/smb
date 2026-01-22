#!/bin/bash
# CVE-2017-7494 (SambaCry) Checker
# Remote code execution in Samba 3.5.0 - 4.6.4

check_sambacry() {
    local target=$1
    local port=${2:-445}
    
    echo -e "\n${BLUE}[*]${NC} Checking for CVE-2017-7494 (SambaCry) on $target"
    
    # First detect if Samba is running
    echo "[*] Detecting Samba version..."
    
    # Method 1: Use smbclient to get version
    version=$(timeout 5 smbclient -N -L //$target 2>&1 | grep -i "samba \|version" | head -1)
    
    if [ -n "$version" ]; then
        echo "[+] Samba detected: $version"
        
        # Extract version number
        ver_num=$(echo "$version" | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
        
        if [ -n "$ver_num" ]; then
            echo "[*] Parsed version: $ver_num"
            
            # Check if vulnerable (3.5.0 to 4.6.4)
            vulnerable=0
            
            # Convert version to comparable format
            IFS='.' read -r major minor patch <<< "$ver_num"
            version_int=$((major * 10000 + minor * 100 + patch))
            
            # Vulnerable range: 30500 to 40604
            if [ $version_int -ge 30500 ] && [ $version_int -le 40604 ]; then
                echo -e "${RED}[!]${NC} Version $ver_num is in VULNERABLE range!"
                vulnerable=1
            fi
            
            if [ $vulnerable -eq 1 ]; then
                echo "[*] Testing for writable shares (for exploit)..."
                
                # Get writable shares
                shares=$(timeout 10 smbclient -N -L //$target 2>/dev/null | 
                         grep -E '^[[:space:]]+[A-Za-z0-9_]+' | awk '{print $1}' | 
                         grep -v '^\$' | grep -v "IPC")
                
                for share in $shares; do
                    echo "[*] Testing share: $share"
                    
                    # Create test file
                    echo "test" > /tmp/is_writable.txt
                    
                    # Try to upload
                    result=$(timeout 5 smbclient -N //$target/$share \
                             -c "put /tmp/is_writable.txt test.txt" 2>&1)
                    
                    if echo "$result" | grep -q "putting file"; then
                        echo -e "${RED}[!]${NC} Share $share is WRITABLE!"
                        echo "    CVE-2017-7494 exploit may be possible"
                        
                        # Try to delete test file
                        timeout 3 smbclient -N //$target/$share -c "del test.txt" 2>/dev/null
                    fi
                    
                    rm -f /tmp/is_writable.txt
                done
            fi
        fi
    else
        echo "[-] Could not detect Samba version"
    fi
}
