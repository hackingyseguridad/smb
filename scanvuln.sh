#!/bin/bash

# MS17-010 SMB RCE Detection - en Bash Shell 
# Based on Metasploit module by Sean Dillon
# This script detects if a target is vulnerable to MS17-010 (EternalBlue)
# (r) hackingyseguridad.com 2026
# @antonio_taboada

############################################################################
# Escanea single host
# ./scanvuln.sh -t 192.168.1.100

# Escanea con mayor informacion
#./scanvuln.sh -t 192.168.1.100 -v

# Escan a range
# ./scanvuln.sh -r 192.168.1.0/24 -o resultado.txt

# Uso con diferente SMB puerto
# ./scanvuln.sh -t 192.168.1.100 -p 139
############################################################################

VERSION="1.0.1"
SCRIPT_NAME="scanvuln.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SMB_PORT=445
TIMEOUT=5
MAX_RETRIES=2

# Global variables
TARGET_IP=""
TARGET_PORT=$SMB_PORT
VERBOSE=0
OUTPUT_FILE=""
SCAN_RANGE=""

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║           MS17-010 SMB RCE Detection Tool           ║"
    echo "║                    Version $VERSION                    ║"
    echo "║        http://www.hackingyseguridad.com/ 2026        ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --target IP        Target IP address"
    echo "  -r, --range CIDR       IP range to scan (e.g., 192.168.1.0/24)"
    echo "  -p, --port PORT        SMB port (default: 445)"
    echo "  -o, --output FILE      Save results to file"
    echo "  -v, --verbose          Enable verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.100"
    echo "  $0 -r 192.168.1.0/24 -o results.txt"
    echo "  $0 -t 10.0.0.5 -p 139"
}

log_message() {
    local level=$1
    local message=$2
    
    case $level in
        "INFO")
            echo -e "${BLUE}[*]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[+]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[!]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[-]${NC} $message"
            ;;
        "DEBUG")
            if [ $VERBOSE -eq 1 ]; then
                echo -e "${BLUE}[D]${NC} $message"
            fi
            ;;
    esac
    
    # Write to output file if specified
    if [ -n "$OUTPUT_FILE" ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$OUTPUT_FILE"
    fi
}

check_dependencies() {
    local dependencies=("nc" "xxd" "printf" "timeout")
    local missing=()
    
    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_message "ERROR" "Missing dependencies: ${missing[*]}"
        log_message "ERROR" "Please install missing tools and try again"
        exit 1
    fi
}

# Helper function to convert hex string to binary
hex_to_bin() {
    echo -n "$1" | xxd -r -p
}

# Helper function to create SMB header
create_smb_header() {
    local command=$1
    local status=$2
    local flags=$3
    local flags2=$4
    local pid_high=$5
    local signature=$6
    local reserved=$7
    local tid=$8
    local pid_low=$9
    local uid=${10}
    local mid=${11}
    
    # SMB Header structure (32 bytes)
    printf "\\x%02x" 0xff 0x53 0x4d 0x42       # SMB magic
    printf "\\x%02x" $command                  # Command
    printf "\\x%02x" $status                   # Status (4 bytes)
    printf "\\x%02x" $(($status >> 8))
    printf "\\x%02x" $(($status >> 16))
    printf "\\x%02x" $(($status >> 24))
    printf "\\x%02x" $flags                    # Flags
    printf "\\x%02x" $flags2                   # Flags2 (2 bytes)
    printf "\\x%02x" $(($flags2 >> 8))
    printf "\\x%02x" $pid_high                 # PID High
    printf "\\x%02x" 0x00 0x00 0x00 0x00      # Signature (8 bytes)
    printf "\\x%02x" 0x00 0x00 0x00 0x00
    printf "\\x%02x" $reserved                 # Reserved
    printf "\\x%02x" $tid                      # TID (2 bytes)
    printf "\\x%02x" $(($tid >> 8))
    printf "\\x%02x" $pid_low                  # PID Low (2 bytes)
    printf "\\x%02x" $(($pid_low >> 8))
    printf "\\x%02x" $uid                      # UID (2 bytes)
    printf "\\x%02x" $(($uid >> 8))
    printf "\\x%02x" $mid                      # MID (2 bytes)
    printf "\\x%02x" $(($mid >> 8))
}

# Create SMB Negotiate Protocol Request
create_negotiate_request() {
    # NetBIOS Session Service header
    local netbios_header=$(printf "\\x%02x" 0x00 0x00 0x00 0x4e)
    
    # SMB Header
    local smb_header=$(create_smb_header 0x72 0x00 0x18 0x2801 0x00 "" 0x00 0xffff 0xfeff 0x00 0x00)
    
    # Word Count
    local word_count=$(printf "\\x%02x" 0x00)
    
    # Dialect Count and Dialects
    local dialects="\\x02\\x00"
    local dialect1="\\x02\\x50\\x43\\x20\\x4e\\x45\\x54\\x57\\x4f\\x52\\x4b\\x20\\x50\\x52\\x4f\\x47\\x52\\x41\\x4d\\x20\\x31\\x2e\\x30\\x00"
    local dialect2="\\x02\\x4c\\x41\\x4e\\x4d\\x41\\x4e\\x31\\x2e\\x30\\x00"
    
    # Byte Count
    local byte_count=$(printf "\\x%02x" 0x00 0x00)
    
    echo -n "${netbios_header}${smb_header}${word_count}${dialects}${dialect1}${dialect2}${byte_count}"
}

# Create SMB Session Setup AndX Request
create_session_setup_request() {
    # NetBIOS Session Service header
    local netbios_header=$(printf "\\x%02x" 0x00 0x00 0x00 0x63)
    
    # SMB Header
    local smb_header=$(create_smb_header 0x73 0x00 0x18 0x2801 0x00 "" 0x00 0xffff 0xfeff 0x00 0x00)
    
    # Word Count and AndX Command
    local words="\\x0d\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x07\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
    
    # Byte Count and Account Data
    local bytes="\\x3c\\x00"
    local account_data="\\x60\\x48\\x06\\x06\\x2b\\x06\\x01\\x05\\x05\\x02\\xa0\\x3e\\x30\\x3c\\xa0\\x0e\\x30\\x0c\\x06\\x0a\\x2b\\x06\\x01\\x04\\x01\\x82\\x37\\x02\\x02\\x0a\\xa2\\x2a\\x04\\x28\\x4e\\x54\\x4c\\x4d\\x53\\x53\\x50\\x00\\x01\\x00\\x00\\x00\\x07\\x82\\x08\\xa2\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x05\\x02\\xce\\x0e\\x00\\x00\\x00\\x0f\\x00\\x57\\x00\\x69\\x00\\x6e\\x00\\x64\\x00\\x6f\\x00\\x77\\x00\\x73\\x00\\x20\\x00\\x32\\x00\\x30\\x00\\x30\\x00\\x30\\x00\\x20\\x00\\x32\\x00\\x31\\x00\\x39\\x00\\x35\\x00\\x00\\x00\\x57\\x00\\x69\\x00\\x6e\\x00\\x64\\x00\\x6f\\x00\\x77\\x00\\x73\\x00\\x20\\x00\\x32\\x00\\x30\\x00\\x30\\x00\\x30\\x00\\x20\\x00\\x35\\x00\\x2e\\x00\\x30\\x00\\x00\\x00\\x00\\x00"
    
    echo -n "${netbios_header}${smb_header}${words}${bytes}${account_data}"
}

# Create Tree Connect AndX Request to IPC$
create_tree_connect_request() {
    # NetBIOS Session Service header
    local netbios_header=$(printf "\\x%02x" 0x00 0x00 0x00 0x3b)
    
    # SMB Header
    local smb_header=$(create_smb_header 0x75 0x00 0x18 0x2801 0x00 "" 0x00 0x0000 0xfeff 0x0001 0x0002)
    
    # Word Count and AndX Command
    local words="\\x04\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
    
    # Byte Count and Path
    local bytes="\\x0a\\x00"
    local path="\\\\\\x00\\\\\\x00I\\x00P\\x00C\\x00\\x24\\x00\\x00\\x00\\x3f\\x00\\x3f\\x00\\x00\\x00"
    
    echo -n "${netbios_header}${smb_header}${words}${bytes}${path}"
}

# Create MS17-010 Detection Transaction Request
create_ms17_010_probe() {
    local tree_id=$1
    
    # NetBIOS Session Service header
    local netbios_header=$(printf "\\x%02x" 0x00 0x00 0x00 0x4a)
    
    # SMB Header
    local smb_header=$(create_smb_header 0x25 0x00 0x18 0x2801 0x00 "" 0x00 $tree_id 0xfeff 0x0001 0x0003)
    
    # Word Count and Parameters
    local words="\\x10\\x00\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x23\\x00\\x00\\x00\\x00\\x00"
    
    # Byte Count and Data
    local bytes="\\x08\\x00"
    local data="\\x5c\\x50\\x49\\x50\\x45\\x5c\\x00\\x00"
    
    echo -n "${netbios_header}${smb_header}${words}${bytes}${data}"
}

# Parse SMB response
parse_smb_response() {
    local response="$1"
    local offset=0
    
    # Extract NetBIOS length
    local nb_len_hex=$(echo -n "$response" | cut -c1-8 | xxd -r -p | od -An -t u4)
    offset=$((offset + 4))
    
    # Check SMB magic
    local magic=$(echo -n "$response" | cut -c$((offset*2+1))-$((offset*2+8)) | xxd -r -p)
    if [ "$magic" != "SMB" ]; then
        echo "INVALID_RESPONSE"
        return
    fi
    offset=$((offset + 4))
    
    # Extract command
    local command=$(printf "%d" "0x$(echo -n "$response" | cut -c$((offset*2+1))-$((offset*2+2)))")
    offset=$((offset + 1))
    
    # Extract status code (4 bytes)
    local status_hex=$(echo -n "$response" | cut -c$((offset*2+1))-$((offset*2+8)) | tr '[:lower:]' '[:upper:]')
    offset=$((offset + 4))
    
    # Map status codes
    case "$status_hex" in
        "C0000205")
            echo "STATUS_INSUFF_SERVER_RESOURCES"
            ;;
        "C0000022")
            echo "STATUS_ACCESS_DENIED"
            ;;
        "C0000008")
            echo "STATUS_INVALID_HANDLE"
            ;;
        "00000000")
            echo "STATUS_SUCCESS"
            ;;
        *)
            echo "UNKNOWN_STATUS_$status_hex"
            ;;
    esac
}

# Send raw SMB packet
send_smb_packet() {
    local host=$1
    local port=$2
    local packet=$3
    local retry=0
    
    while [ $retry -lt $MAX_RETRIES ]; do
        # Convert hex string to binary and send
        local response=$(echo -n "$packet" | xxd -r -p | timeout $TIMEOUT nc -w $TIMEOUT $host $port 2>/dev/null | xxd -p | tr -d '\n')
        
        if [ -n "$response" ] && [ ${#response} -gt 0 ]; then
            echo "$response"
            return 0
        fi
        
        retry=$((retry + 1))
        if [ $retry -lt $MAX_RETRIES ]; then
            log_message "DEBUG" "Retrying connection to $host:$port (attempt $retry/$MAX_RETRIES)"
            sleep 1
        fi
    done
    
    echo ""
    return 1
}

# Check if port is open
check_port() {
    local host=$1
    local port=$2
    
    timeout $TIMEOUT nc -z -w $TIMEOUT $host $port >/dev/null 2>&1
    return $?
}

# Main vulnerability detection function
detect_ms17_010() {
    local host=$1
    local port=$2
    
    log_message "INFO" "Testing $host:$port for MS17-010 vulnerability"
    
    # Step 1: Check if port is open
    if ! check_port "$host" "$port"; then
        log_message "ERROR" "Port $port is closed on $host"
        return 1
    fi
    
    log_message "DEBUG" "Port $port is open on $host"
    
    # Step 2: Send Negotiate Protocol Request
    log_message "DEBUG" "Sending SMB Negotiate Protocol Request"
    local negotiate_packet=$(create_negotiate_request)
    local negotiate_response=$(send_smb_packet "$host" "$port" "$negotiate_packet")
    
    if [ -z "$negotiate_response" ]; then
        log_message "ERROR" "No response to Negotiate Protocol Request"
        return 1
    fi
    
    log_message "DEBUG" "Received Negotiate Protocol Response"
    
    # Step 3: Send Session Setup Request
    log_message "DEBUG" "Sending SMB Session Setup Request"
    local session_packet=$(create_session_setup_request)
    local session_response=$(send_smb_packet "$host" "$port" "$session_packet")
    
    if [ -z "$session_response" ]; then
        log_message "ERROR" "No response to Session Setup Request"
        return 1
    fi
    
    log_message "DEBUG" "Received Session Setup Response"
    
    # Step 4: Send Tree Connect to IPC$
    log_message "DEBUG" "Connecting to IPC$ share"
    local tree_packet=$(create_tree_connect_request)
    local tree_response=$(send_smb_packet "$host" "$port" "$tree_packet")
    
    if [ -z "$tree_response" ]; then
        log_message "ERROR" "No response to Tree Connect Request"
        return 1
    fi
    
    # Extract TID from response (bytes 28-29 in SMB header, after 4-byte NetBIOS header)
    local tid_hex=$(echo -n "$tree_response" | cut -c9-12)
    local tid=$((0x$tid_hex))
    log_message "DEBUG" "Connected to IPC$ with TID = $tid"
    
    # Step 5: Send MS17-010 probe
    log_message "INFO" "Sending MS17-010 detection probe"
    local probe_packet=$(create_ms17_010_probe $tid)
    local probe_response=$(send_smb_packet "$host" "$port" "$probe_packet")
    
    if [ -z "$probe_response" ]; then
        log_message "ERROR" "No response to MS17-010 probe"
        return 1
    fi
    
    # Parse the response
    local status=$(parse_smb_response "$probe_response")
    log_message "INFO" "Received status: $status"
    
    # Evaluate result
    case "$status" in
        "STATUS_INSUFF_SERVER_RESOURCES")
            log_message "WARNING" "$host is LIKELY VULNERABLE to MS17-010 (EternalBlue)!"
            echo "VULNERABLE"
            ;;
        "STATUS_ACCESS_DENIED"|"STATUS_INVALID_HANDLE")
            log_message "SUCCESS" "$host does NOT appear vulnerable to MS17-010"
            echo "NOT_VULNERABLE"
            ;;
        "STATUS_SUCCESS")
            log_message "INFO" "$host responded with SUCCESS - likely patched"
            echo "PATCHED"
            ;;
        *)
            log_message "ERROR" "Unable to determine vulnerability status: $status"
            echo "UNKNOWN"
            ;;
    esac
    
    return 0
}

# Scan a range of IPs
scan_range() {
    local range=$1
    
    log_message "INFO" "Starting scan of range: $range"
    
    # Extract network and prefix
    local network=$(echo "$range" | cut -d'/' -f1)
    local prefix=$(echo "$range" | cut -d'/' -f2)
    
    if [ -z "$network" ] || [ -z "$prefix" ]; then
        log_message "ERROR" "Invalid CIDR notation: $range"
        return 1
    fi
    
    # Convert to IP list (simplified - in production, use proper subnet calculation)
    # For simplicity, this scans first 10 hosts in the range
    IFS='.' read -r i1 i2 i3 i4 <<< "$network"
    
    for i in $(seq 1 10); do
        local target_ip="$i1.$i2.$i3.$((i4 + i))"
        log_message "INFO" "Scanning $target_ip"
        detect_ms17_010 "$target_ip" "$TARGET_PORT"
        echo ""
    done
}

# Main execution
main() {
    print_banner
    check_dependencies
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--target)
                TARGET_IP="$2"
                shift 2
                ;;
            -r|--range)
                SCAN_RANGE="$2"
                shift 2
                ;;
            -p|--port)
                TARGET_PORT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                log_message "ERROR" "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    if [ -z "$TARGET_IP" ] && [ -z "$SCAN_RANGE" ]; then
        log_message "ERROR" "Either --target or --range must be specified"
        print_usage
        exit 1
    fi
    
    if [ -n "$TARGET_IP" ] && [ -n "$SCAN_RANGE" ]; then
        log_message "WARNING" "Both target and range specified. Using target: $TARGET_IP"
    fi
    
    # Initialize output file if specified
    if [ -n "$OUTPUT_FILE" ]; then
        echo "MS17-010 Scan Results - $(date)" > "$OUTPUT_FILE"
        echo "=======================================" >> "$OUTPUT_FILE"
    fi
    
    # Perform scan
    if [ -n "$SCAN_RANGE" ]; then
        scan_range "$SCAN_RANGE"
    else
        detect_ms17_010 "$TARGET_IP" "$TARGET_PORT"
    fi
    
    log_message "INFO" "Scan completed"
}

# Run main function with all arguments
main "$@"

# VULNERABLE: Returns STATUS_INSUFF_SERVER_RESOURCES (0xC0000205)
# NOT VULNERABLE: Returns STATUS_ACCESS_DENIED (0xC0000022) or STATUS_INVALID_HANDLE (0xC0000008)
# PATCHED: Returns STATUS_SUCCESS (0x00000000)



