#!/bin/bash

# MS08-068 SMB Relay Vulnerability Tester
# CVE-2008-4037 - SMB Authentication Relay Vulnerability
# Permite relay de credenciales NTLM entre sesiones SMB
# Bash implementation for testing purposes

VERSION="1.0.0"
SCRIPT_NAME="ms08-068_tester.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SMB_PORT=445
TIMEOUT=3
MAX_RETRIES=2

# Global vars
TARGET_IP=""
TARGET_PORT=$SMB_PORT
VERBOSE=0
OUTPUT_FILE=""
TEST_MODE="basic"  # basic, ntlm, relay

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║         MS08-068 SMB Relay Vulnerability Tester      ║"
    echo "║                    Version $VERSION                    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --target IP        Target IP address"
    echo "  -p, --port PORT        SMB port (default: 445)"
    echo "  -m, --mode MODE        Test mode: basic, ntlm, relay"
    echo "  -o, --output FILE      Save results to file"
    echo "  -v, --verbose          Enable verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Test Modes:"
    echo "  basic    - Simple SMB connection test"
    echo "  ntlm     - Test NTLM authentication"
    echo "  relay    - Attempt SMB relay detection"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.100 -m basic"
    echo "  $0 -t 192.168.1.100 -m relay -v"
}

log_message() {
    local level=$1
    local message=$2
    
    case $level in
        "INFO") echo -e "${BLUE}[*]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[+]${NC} $message" ;;
        "WARNING") echo -e "${YELLOW}[!]${NC} $message" ;;
        "ERROR") echo -e "${RED}[-]${NC} $message" ;;
        "DEBUG") 
            if [ $VERBOSE -eq 1 ]; then
                echo -e "${BLUE}[D]${NC} $message"
            fi
            ;;
    esac
    
    if [ -n "$OUTPUT_FILE" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$OUTPUT_FILE"
    fi
}

check_dependencies() {
    local deps=("nc" "xxd" "printf" "timeout" "smbclient" "rpcclient" 2>/dev/null)
    local missing=()
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_message "WARNING" "Some tools missing: ${missing[*]}"
        log_message "INFO" "Install samba client tools: apt install smbclient"
    fi
}

# Helper functions for binary data
hex_to_bin() {
    echo -n "$1" | xxd -r -p
}

bin_to_hex() {
    echo -n "$1" | xxd -p | tr -d '\n'
}

# Create NetBIOS Session Service header
netbios_header() {
    local length=$1
    printf "\\x%02x\\x%02x\\x%02x\\x%02x" \
        $(( (length >> 24) & 0xFF )) \
        $(( (length >> 16) & 0xFF )) \
        $(( (length >> 8) & 0xFF )) \
        $(( length & 0xFF ))
}

# Create SMB header
create_smb_header() {
    local command=$1
    local status=$2
    local flags=$3
    local flags2=$4
    local pid_high=$5
    local tid=$6
    local pid_low=$7
    local uid=$8
    local mid=$9
    
    printf "\\x%02x\\x%02x\\x%02x\\x%02x" 0xff 0x53 0x4d 0x42  # SMB magic
    printf "\\x%02x" $command                                    # Command
    printf "\\x%02x\\x%02x\\x%02x\\x%02x" \
        $(( status & 0xFF )) \
        $(( (status >> 8) & 0xFF )) \
        $(( (status >> 16) & 0xFF )) \
        $(( (status >> 24) & 0xFF ))                            # Status
    printf "\\x%02x" $flags                                     # Flags
    printf "\\x%02x\\x%02x" \
        $(( flags2 & 0xFF )) \
        $(( (flags2 >> 8) & 0xFF ))                            # Flags2
    printf "\\x%02x" $pid_high                                  # PID High
    printf "\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x\\x%02x" \
        0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00                # Signature
    printf "\\x%02x" 0x00                                       # Reserved
    printf "\\x%02x\\x%02x" \
        $(( tid & 0xFF )) \
        $(( (tid >> 8) & 0xFF ))                               # TID
    printf "\\x%02x\\x%02x" \
        $(( pid_low & 0xFF )) \
        $(( (pid_low >> 8) & 0xFF ))                           # PID Low
    printf "\\x%02x\\x%02x" \
        $(( uid & 0xFF )) \
        $(( (uid >> 8) & 0xFF ))                               # UID
    printf "\\x%02x\\x%02x" \
        $(( mid & 0xFF )) \
        $(( (mid >> 8) & 0xFF ))                               # MID
}

# Check if port is open
check_port() {
    local host=$1
    local port=$2
    
    timeout $TIMEOUT nc -z -w $TIMEOUT $host $port >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "DEBUG" "Port $port is open on $host"
        return 0
    else
        log_message "DEBUG" "Port $port is closed on $host"
        return 1
    fi
}

# Send raw SMB packet
send_smb_packet() {
    local host=$1
    local port=$2
    local packet=$3
    local retry=0
    
    while [ $retry -lt $MAX_RETRIES ]; do
        local response=$(echo -n "$packet" | xxd -r -p | timeout $TIMEOUT nc -w $TIMEOUT $host $port 2>/dev/null | xxd -p | tr -d '\n')
        
        if [ -n "$response" ] && [ ${#response} -gt 0 ]; then
            echo "$response"
            return 0
        fi
        
        retry=$((retry + 1))
        sleep 1
    done
    
    echo ""
    return 1
}

# Test 1: Basic SMB connection
test_basic_smb() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Testing basic SMB connectivity to $host:$port"
    
    # Create negotiate protocol request
    local netbios_len=$(printf "\\x%02x\\x%02x\\x%02x\\x%02x" 0x00 0x00 0x00 0x4e)
    
    local smb_header=$(create_smb_header 0x72 0x00 0x18 0x2801 0x00 0xffff 0xfeff 0x00 0x00)
    
    local word_count="\\x00"
    local dialects="\\x02\\x00"
    local dialect1="\\x02\\x50\\x43\\x20\\x4e\\x45\\x54\\x57\\x4f\\x52\\x4b\\x20\\x50\\x52\\x4f\\x47\\x52\\x41\\x4d\\x20\\x31\\x2e\\x30\\x00"
    local dialect2="\\x02\\x4c\\x41\\x4e\\x4d\\x41\\x4e\\x31\\x2e\\x30\\x00"
    local byte_count="\\x00\\x00"
    
    local packet="${netbios_len}${smb_header}${word_count}${dialects}${dialect1}${dialect2}${byte_count}"
    local packet_hex=$(echo -n "$packet" | xxd -p | tr -d '\n')
    
    local response=$(send_smb_packet "$host" "$port" "$packet_hex")
    
    if [ -n "$response" ]; then
        # Check for SMB response
        if echo "$response" | grep -q "ff534d42"; then
            log_message "SUCCESS" "SMB service is accessible"
            return 0
        else
            log_message "ERROR" "Invalid SMB response"
            return 1
        fi
    else
        log_message "ERROR" "No response from SMB service"
        return 1
    fi
}

# Test 2: Check for NTLM authentication
test_ntlm_auth() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Testing NTLM authentication on $host"
    
    # Try anonymous connection to IPC$
    log_message "DEBUG" "Attempting anonymous IPC$ connection"
    
    local result=$(timeout 5 smbclient -N -L "//$host" 2>&1)
    
    if echo "$result" | grep -q "Anonymous login successful"; then
        log_message "WARNING" "Anonymous login allowed - possible misconfiguration"
        echo "ANONYMOUS_ALLOWED"
        return 0
    elif echo "$result" | grep -q "NT_STATUS_ACCESS_DENIED"; then
        log_message "INFO" "Anonymous access denied (normal)"
        echo "AUTH_REQUIRED"
        return 0
    elif echo "$result" | grep -q "NT_STATUS_LOGON_FAILURE"; then
        log_message "INFO" "Authentication required"
        echo "AUTH_REQUIRED"
        return 0
    else
        log_message "ERROR" "Unexpected response"
        echo "UNKNOWN"
        return 1
    fi
}

# Test 3: Detect SMB signing requirements
test_smb_signing() {
    local host=$1
    
    log_message "INFO" "Checking SMB signing configuration on $host"
    
    # Use rpcclient to query security settings
    local output=$(timeout 5 rpcclient -U "%" -N "$host" -c "querysecinfo" 2>&1)
    
    if echo "$output" | grep -i "signing" | grep -i "required"; then
        log_message "INFO" "SMB signing is REQUIRED (protected)"
        echo "SIGNING_REQUIRED"
        return 0
    elif echo "$output" | grep -i "signing" | grep -i "enabled"; then
        log_message "WARNING" "SMB signing is enabled but not required"
        echo "SIGNING_ENABLED"
        return 0
    else
        log_message "WARNING" "SMB signing may be disabled"
        echo "SIGNING_DISABLED"
        return 0
    fi
}

# Test 4: MS08-068 specific test - Attempt to identify vulnerable systems
test_ms08_068_vulnerability() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Testing for MS08-068 vulnerability indicators"
    
    # Indicators of vulnerability:
    # 1. SMBv1 enabled
    # 2. SMB signing disabled
    # 3. Accepts NTLM authentication
    # 4. Windows version pre-2008/Windows 7
    
    log_message "DEBUG" "Gathering system information..."
    
    # Try to get OS version via SMB
    local os_info=""
    
    # Method 1: smbclient
    local smb_output=$(timeout 5 smbclient -N -L "//$host" 2>&1 | grep -i "domain\|os\|version")
    
    # Method 2: Check for specific SMB dialects
    log_message "DEBUG" "Checking SMB protocol versions..."
    
    # Create test packets for different SMB versions
    local vulnerable=0
    local reasons=()
    
    # Check 1: Is SMBv1 enabled?
    log_message "DEBUG" "Testing SMBv1 support..."
    local test1=$(test_basic_smb "$host" "$port")
    if [ $? -eq 0 ]; then
        reasons+=("SMBv1 enabled")
        vulnerable=$((vulnerable + 1))
    fi
    
    # Check 2: SMB signing status
    log_message "DEBUG" "Testing SMB signing..."
    local signing_status=$(test_smb_signing "$host")
    if [ "$signing_status" = "SIGNING_DISABLED" ]; then
        reasons+=("SMB signing disabled")
        vulnerable=$((vulnerable + 1))
    fi
    
    # Check 3: NTLM authentication
    log_message "DEBUG" "Testing NTLM auth..."
    local ntlm_status=$(test_ntlm_auth "$host" "$port")
    
    # Try to identify Windows version
    log_message "DEBUG" "Attempting OS identification..."
    
    # Common vulnerable versions:
    # Windows XP, Windows Server 2003, Windows Vista
    # Windows Server 2008 (unpatched), Windows 7 (unpatched)
    
    # Use null session to get info (if allowed)
    local rpc_info=$(timeout 5 rpcclient -U "%" -N "$host" -c "srvinfo" 2>&1)
    
    local os_version="Unknown"
    if echo "$rpc_info" | grep -q "Windows"; then
        os_version=$(echo "$rpc_info" | grep -i "windows" | head -1)
        log_message "INFO" "Detected: $os_version"
        
        # Check if it's a vulnerable version
        if echo "$os_version" | grep -E -i "xp|2003|vista|2008|7" | grep -v -i "2008 R2\|7 SP1"; then
            reasons+=("Potentially vulnerable Windows version: $(echo "$os_version" | cut -d':' -f2-)")
            vulnerable=$((vulnerable + 1))
        fi
    fi
    
    # Evaluate results
    log_message "INFO" "Vulnerability assessment completed"
    log_message "INFO" "Indicators found: ${#reasons[@]}"
    
    for reason in "${reasons[@]}"; do
        log_message "WARNING" " - $reason"
    done
    
    if [ $vulnerable -ge 2 ]; then
        log_message "WARNING" "Host $host shows $vulnerable indicators of MS08-068 vulnerability"
        log_message "WARNING" "System may be vulnerable to SMB relay attacks"
        
        # Additional check: Test with Metasploit pattern if available
        if command -v msfconsole &> /dev/null; then
            log_message "INFO" "Note: For definitive testing, use Metasploit:"
            log_message "INFO" "  msfconsole -q -x 'use exploit/windows/smb/smb_relay
