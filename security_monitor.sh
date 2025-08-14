#!/bin/bash

# ============================================================================
# COMPREHENSIVE SECURITY MONITORING SCRIPT
# ============================================================================
# Author: Security Monitor
# Version: 1.0
# Description: Automated security checks for malware, backdoors, and threats
# Usage: ./security_monitor.sh [--full|--quick|--report]
# ============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$HOME/security_logs"
REPORT_FILE="$LOG_DIR/security_report_$(date +%Y%m%d_%H%M%S).txt"
ALERT_FILE="$LOG_DIR/security_alerts.log"
CONFIG_FILE="$HOME/.security_monitor.conf"

# Create directories
mkdir -p "$LOG_DIR"

# Default configuration
ENABLE_EMAIL_ALERTS=false
EMAIL_ADDRESS=""
SCAN_DEPTH="normal"
AUTO_CLEAN=false

# Load configuration if exists
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

print_header() {
    echo -e "${BLUE}============================================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${BLUE}============================================================================${NC}"
}

print_section() {
    echo -e "\n${PURPLE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

log_alert() {
    local level="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$ALERT_FILE"
    
    if [[ "$level" == "CRITICAL" || "$level" == "HIGH" ]]; then
        print_error "$message"
        if [[ "$ENABLE_EMAIL_ALERTS" == "true" && -n "$EMAIL_ADDRESS" ]]; then
            echo "$message" | mail -s "Security Alert: $level" "$EMAIL_ADDRESS" 2>/dev/null
        fi
    elif [[ "$level" == "MEDIUM" ]]; then
        print_warning "$message"
    else
        print_info "$message"
    fi
}

# ============================================================================
# SECURITY CHECK FUNCTIONS
# ============================================================================

check_rootkits() {
    print_section "ROOTKIT DETECTION"
    
    if command -v chkrootkit >/dev/null 2>&1; then
        print_info "Running chkrootkit scan..."
        local infected_count=$(sudo chkrootkit 2>/dev/null | grep -c "INFECTED")
        
        if [[ $infected_count -gt 0 ]]; then
            log_alert "CRITICAL" "Rootkit detected! $infected_count infections found"
            sudo chkrootkit 2>/dev/null | grep "INFECTED" >> "$REPORT_FILE"
        else
            print_success "No rootkits detected"
        fi
    else
        print_warning "chkrootkit not installed. Installing..."
        sudo apt update && sudo apt install -y chkrootkit
    fi
    
    if command -v rkhunter >/dev/null 2>&1; then
        print_info "Running rkhunter scan..."
        sudo rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null | tee -a "$REPORT_FILE"
    fi
}

check_processes() {
    print_section "SUSPICIOUS PROCESSES"
    
    # Check for high CPU processes
    print_info "Checking high CPU processes..."
    ps aux --sort=-%cpu | head -10 | while read line; do
        cpu=$(echo "$line" | awk '{print $3}')
        if (( $(echo "$cpu > 80" | bc -l) )); then
            log_alert "MEDIUM" "High CPU process detected: $line"
        fi
    done
    
    # Check for suspicious process names
    print_info "Checking for suspicious process names..."
    suspicious_processes=("nc" "netcat" "ncat" "socat" "wget" "curl" "python -c" "perl -e" "ruby -e" "bash -i" "sh -i")
    
    for proc in "${suspicious_processes[@]}"; do
        if pgrep -f "$proc" >/dev/null; then
            log_alert "HIGH" "Suspicious process found: $proc"
            ps aux | grep "$proc" | grep -v grep >> "$REPORT_FILE"
        fi
    done
    
    print_success "Process check completed"
}

check_network() {
    print_section "NETWORK SECURITY"
    
    # Check listening ports
    print_info "Checking listening ports..."
    netstat -tulpn 2>/dev/null | grep LISTEN | while read line; do
        port=$(echo "$line" | awk '{print $4}' | cut -d: -f2)
        if [[ "$port" =~ ^[0-9]+$ ]]; then
            # Check for suspicious ports
            case $port in
                1234|4444|5555|6666|7777|8888|9999|31337|12345)
                    log_alert "HIGH" "Suspicious port listening: $line"
                    ;;
                22|80|443|3389|8080|8501|8545)
                    log_alert "INFO" "Standard service port: $line"
                    ;;
            esac
        fi
    done
    
    # Check for established connections to suspicious IPs
    print_info "Checking network connections..."
    netstat -an | grep ESTABLISHED | while read line; do
        remote_ip=$(echo "$line" | awk '{print $5}' | cut -d: -f1)
        if [[ "$remote_ip" != "127.0.0.1" && "$remote_ip" != "::1" ]]; then
            # You can add IP reputation checking here
            log_alert "INFO" "External connection: $line"
        fi
    done
    
    print_success "Network check completed"
}

check_files() {
    print_section "FILE SYSTEM SECURITY"
    
    # Check for SUID/SGID files
    print_info "Checking SUID/SGID files..."
    find /usr /bin /sbin -perm -4000 -o -perm -2000 2>/dev/null | while read file; do
        if [[ ! -f "/tmp/known_suid_files.txt" ]]; then
            # Create baseline of known SUID files
            find /usr /bin /sbin -perm -4000 -o -perm -2000 2>/dev/null > "/tmp/known_suid_files.txt"
        fi
        
        if ! grep -q "$file" "/tmp/known_suid_files.txt"; then
            log_alert "MEDIUM" "New SUID/SGID file detected: $file"
        fi
    done
    
    # Check for suspicious files in temp directories
    print_info "Checking temporary directories..."
    find /tmp /var/tmp -type f -executable 2>/dev/null | while read file; do
        log_alert "MEDIUM" "Executable file in temp directory: $file"
    done
    
    # Check for recently modified system files
    print_info "Checking recently modified system files..."
    find /etc /usr/bin /usr/sbin -type f -mtime -1 2>/dev/null | while read file; do
        log_alert "INFO" "Recently modified system file: $file"
    done
    
    # Check for hidden files in unusual locations
    print_info "Checking for suspicious hidden files..."
    find /tmp /var/tmp -name ".*" -type f 2>/dev/null | while read file; do
        if [[ ! "$file" =~ \.(X11-unix|ICE-unix|font-unix) ]]; then
            log_alert "MEDIUM" "Hidden file in temp directory: $file"
        fi
    done
    
    print_success "File system check completed"
}

check_users() {
    print_section "USER ACCOUNT SECURITY"
    
    # Check for new users
    print_info "Checking user accounts..."
    if [[ -f "/tmp/known_users.txt" ]]; then
        current_users=$(cut -d: -f1 /etc/passwd | sort)
        known_users=$(cat /tmp/known_users.txt)
        
        new_users=$(comm -13 <(echo "$known_users") <(echo "$current_users"))
        if [[ -n "$new_users" ]]; then
            log_alert "HIGH" "New user accounts detected: $new_users"
        fi
    else
        cut -d: -f1 /etc/passwd | sort > /tmp/known_users.txt
    fi
    
    # Check for users with UID 0
    print_info "Checking for root-level users..."
    awk -F: '$3 == 0 {print $1}' /etc/passwd | while read user; do
        if [[ "$user" != "root" ]]; then
            log_alert "CRITICAL" "Non-root user with UID 0: $user"
        fi
    done
    
    # Check for users without passwords
    print_info "Checking for users without passwords..."
    sudo awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null | while read user; do
        log_alert "HIGH" "User without password: $user"
    done
    
    print_success "User account check completed"
}

check_ssh() {
    print_section "SSH SECURITY"
    
    # Check SSH configuration
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        print_info "Checking SSH configuration..."
        
        # Check for root login
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
            log_alert "HIGH" "SSH root login is enabled"
        fi
        
        # Check for password authentication
        if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
            log_alert "MEDIUM" "SSH password authentication is enabled"
        fi
        
        # Check for empty passwords
        if grep -q "^PermitEmptyPasswords yes" /etc/ssh/sshd_config; then
            log_alert "CRITICAL" "SSH empty passwords are permitted"
        fi
    fi
    
    # Check authorized_keys files
    print_info "Checking SSH authorized_keys..."
    find /home -name "authorized_keys" 2>/dev/null | while read keyfile; do
        if [[ -s "$keyfile" ]]; then
            key_count=$(wc -l < "$keyfile")
            log_alert "INFO" "SSH keys found in $keyfile: $key_count keys"
            
            # Check for suspicious keys
            while read key; do
                if [[ "$key" =~ (backdoor|hack|root|admin) ]]; then
                    log_alert "HIGH" "Suspicious SSH key comment: $key"
                fi
            done < "$keyfile"
        fi
    done
    
    print_success "SSH security check completed"
}

check_cron() {
    print_section "SCHEDULED TASKS"
    
    # Check user cron jobs
    print_info "Checking cron jobs..."
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab -u "$user" -l 2>/dev/null | while read cronjob; do
            if [[ -n "$cronjob" && ! "$cronjob" =~ ^# ]]; then
                log_alert "INFO" "Cron job for $user: $cronjob"
                
                # Check for suspicious commands
                if [[ "$cronjob" =~ (wget|curl|nc|netcat|bash.*-i|sh.*-i) ]]; then
                    log_alert "HIGH" "Suspicious cron job: $cronjob"
                fi
            fi
        done
    done
    
    # Check system cron jobs
    print_info "Checking system cron jobs..."
    find /etc/cron* -type f 2>/dev/null | while read cronfile; do
        if [[ -f "$cronfile" ]]; then
            log_alert "INFO" "System cron file: $cronfile"
        fi
    done
    
    print_success "Scheduled tasks check completed"
}

check_logs() {
    print_section "LOG ANALYSIS"
    
    # Check for failed login attempts
    print_info "Checking authentication logs..."
    if [[ -f "/var/log/auth.log" ]]; then
        failed_logins=$(grep "Failed password" /var/log/auth.log | wc -l)
        if [[ $failed_logins -gt 10 ]]; then
            log_alert "MEDIUM" "High number of failed login attempts: $failed_logins"
        fi
    fi
    
    # Check system logs for errors
    print_info "Checking system logs..."
    journalctl --since "1 hour ago" --priority=err 2>/dev/null | while read logline; do
        if [[ -n "$logline" ]]; then
            log_alert "INFO" "System error: $logline"
        fi
    done
    
    print_success "Log analysis completed"
}

check_malware() {
    print_section "MALWARE DETECTION"
    
    # Check for common malware signatures
    print_info "Scanning for malware signatures..."
    
    # Common malware file names
    malware_names=("nc.exe" "netcat" "pwdump" "fgdump" "cachedump" "wce.exe" "mimikatz")
    
    for malware in "${malware_names[@]}"; do
        find / -name "*$malware*" -type f 2>/dev/null | while read file; do
            log_alert "HIGH" "Potential malware file: $file"
        done
    done
    
    # Check for suspicious scripts
    print_info "Checking for suspicious scripts..."
    find /tmp /var/tmp /home -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null | while read script; do
        if grep -l -E "(eval|exec|system|shell_exec|passthru)" "$script" 2>/dev/null; then
            log_alert "MEDIUM" "Script with potentially dangerous functions: $script"
        fi
    done
    
    print_success "Malware detection completed"
}

system_cleanup() {
    print_section "SYSTEM CLEANUP"
    
    if [[ "$AUTO_CLEAN" == "true" ]]; then
        print_info "Performing automatic cleanup..."
        
        # Clean temporary files
        find /tmp -type f -atime +7 -delete 2>/dev/null
        find /var/tmp -type f -atime +7 -delete 2>/dev/null
        
        # Clean old logs
        find /var/log -name "*.log" -size +100M -exec truncate -s 50M {} \; 2>/dev/null
        
        # Clean package cache
        sudo apt autoremove -y >/dev/null 2>&1
        sudo apt autoclean >/dev/null 2>&1
        
        print_success "System cleanup completed"
    else
        print_info "Auto-cleanup disabled. Use --clean flag to enable."
    fi
}

generate_report() {
    print_section "GENERATING REPORT"
    
    {
        echo "SECURITY MONITORING REPORT"
        echo "=========================="
        echo "Generated: $(date)"
        echo "Hostname: $(hostname)"
        echo "User: $(whoami)"
        echo "Uptime: $(uptime)"
        echo ""
        echo "SYSTEM INFORMATION:"
        echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")"
        echo "Kernel: $(uname -r)"
        echo "Architecture: $(uname -m)"
        echo ""
        echo "DISK USAGE:"
        df -h | grep -E "^/dev"
        echo ""
        echo "MEMORY USAGE:"
        free -h
        echo ""
        echo "NETWORK INTERFACES:"
        ip addr show | grep -E "(inet |UP)"
        echo ""
        echo "LISTENING SERVICES:"
        netstat -tulpn 2>/dev/null | grep LISTEN
        echo ""
        echo "RECENT ALERTS:"
        tail -20 "$ALERT_FILE" 2>/dev/null || echo "No alerts found"
        echo ""
        echo "TOP PROCESSES:"
        ps aux --sort=-%cpu | head -10
        echo ""
    } > "$REPORT_FILE"
    
    print_success "Report generated: $REPORT_FILE"
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "OPTIONS:"
    echo "  --full      Perform comprehensive security scan"
    echo "  --quick     Perform quick security scan"
    echo "  --report    Generate security report only"
    echo "  --clean     Enable automatic cleanup"
    echo "  --config    Show configuration"
    echo "  --setup     Initial setup and configuration"
    echo "  --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --full          # Full security scan"
    echo "  $0 --quick         # Quick scan"
    echo "  $0 --report        # Generate report only"
    echo ""
}

setup_config() {
    print_header "SECURITY MONITOR SETUP"
    
    echo "Setting up security monitor configuration..."
    
    read -p "Enable email alerts? (y/n): " enable_email
    if [[ "$enable_email" =~ ^[Yy] ]]; then
        ENABLE_EMAIL_ALERTS=true
        read -p "Enter email address: " EMAIL_ADDRESS
    fi
    
    read -p "Enable automatic cleanup? (y/n): " enable_clean
    if [[ "$enable_clean" =~ ^[Yy] ]]; then
        AUTO_CLEAN=true
    fi
    
    # Save configuration
    cat > "$CONFIG_FILE" << EOF
# Security Monitor Configuration
ENABLE_EMAIL_ALERTS=$ENABLE_EMAIL_ALERTS
EMAIL_ADDRESS="$EMAIL_ADDRESS"
SCAN_DEPTH="$SCAN_DEPTH"
AUTO_CLEAN=$AUTO_CLEAN
EOF
    
    print_success "Configuration saved to $CONFIG_FILE"
    
    # Setup cron job
    read -p "Setup automatic daily scan? (y/n): " setup_cron
    if [[ "$setup_cron" =~ ^[Yy] ]]; then
        (crontab -l 2>/dev/null; echo "0 2 * * * $SCRIPT_DIR/security_monitor.sh --quick") | crontab -
        print_success "Daily scan scheduled at 2:00 AM"
    fi
}

main() {
    local scan_type="quick"
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --full)
                scan_type="full"
                shift
                ;;
            --quick)
                scan_type="quick"
                shift
                ;;
            --report)
                scan_type="report"
                shift
                ;;
            --clean)
                AUTO_CLEAN=true
                shift
                ;;
            --config)
                cat "$CONFIG_FILE" 2>/dev/null || echo "No configuration file found"
                exit 0
                ;;
            --setup)
                setup_config
                exit 0
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Start security monitoring
    print_header "SECURITY MONITORING SYSTEM"
    echo -e "${CYAN}Scan Type: $scan_type${NC}"
    echo -e "${CYAN}Log Directory: $LOG_DIR${NC}"
    echo -e "${CYAN}Started: $(date)${NC}"
    
    case $scan_type in
        "full")
            check_rootkits
            check_processes
            check_network
            check_files
            check_users
            check_ssh
            check_cron
            check_logs
            check_malware
            system_cleanup
            generate_report
            ;;
        "quick")
            check_processes
            check_network
            check_users
            check_ssh
            system_cleanup
            generate_report
            ;;
        "report")
            generate_report
            ;;
    esac
    
    print_header "SECURITY SCAN COMPLETED"
    echo -e "${GREEN}✅ Security monitoring completed successfully${NC}"
    echo -e "${CYAN}📊 Report: $REPORT_FILE${NC}"
    echo -e "${CYAN}📋 Alerts: $ALERT_FILE${NC}"
    
    # Show summary
    if [[ -f "$ALERT_FILE" ]]; then
        critical_count=$(grep -c "CRITICAL" "$ALERT_FILE" 2>/dev/null || echo 0)
        high_count=$(grep -c "HIGH" "$ALERT_FILE" 2>/dev/null || echo 0)
        medium_count=$(grep -c "MEDIUM" "$ALERT_FILE" 2>/dev/null || echo 0)
        
        echo ""
        echo -e "${PURPLE}=== ALERT SUMMARY ===${NC}"
        echo -e "${RED}Critical: $critical_count${NC}"
        echo -e "${YELLOW}High: $high_count${NC}"
        echo -e "${BLUE}Medium: $medium_count${NC}"
        
        if [[ $critical_count -gt 0 || $high_count -gt 0 ]]; then
            echo -e "\n${RED}⚠️  ATTENTION: High priority security issues detected!${NC}"
            echo -e "${YELLOW}Review the alert log: $ALERT_FILE${NC}"
        fi
    fi
}

# Run main function with all arguments
main "$@"
