#!/bin/bash
# RedBadger Security Platform - Installation Script
# Supports: Ubuntu, Debian, CentOS, RHEL, Fedora, Alpine

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/redbadger"
DATA_DIR="/var/lib/redbadger"
LOG_DIR="/var/log/redbadger"
CONFIG_DIR="/etc/redbadger"
SERVICE_USER="redbadger"
PYTHON_VERSION="3.11"

print_color() {
    echo -e "${2}${1}${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_color "This script must be run as root!" "$RED"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        print_color "Cannot detect OS" "$RED"
        exit 1
    fi
}

install_dependencies_debian() {
    print_color "Installing dependencies for Debian/Ubuntu..." "$BLUE"
    apt-get update
    apt-get install -y \
        python3 python3-pip python3-dev \
        nmap traceroute whois dnsutils \
        iptables net-tools tcpdump \
        git curl wget \
        build-essential libffi-dev \
        sqlite3
}

install_dependencies_redhat() {
    print_color "Installing dependencies for RHEL/CentOS/Fedora..." "$BLUE"
    if [[ $OS == "fedora" ]]; then
        dnf install -y \
            python3 python3-pip python3-devel \
            nmap traceroute whois bind-utils \
            iptables net-tools tcpdump \
            git curl wget \
            gcc make \
            sqlite
    else
        yum install -y epel-release
        yum install -y \
            python3 python3-pip python3-devel \
            nmap traceroute whois bind-utils \
            iptables net-tools tcpdump \
            git curl wget \
            gcc make \
            sqlite
    fi
}

install_dependencies_alpine() {
    print_color "Installing dependencies for Alpine..." "$BLUE"
    apk add --no-cache \
        python3 py3-pip python3-dev \
        nmap nmap-scripts traceroute whois bind-tools \
        iptables net-tools tcpdump \
        git curl wget \
        gcc musl-dev libffi-dev \
        sqlite
}

install_dependencies() {
    case $OS in
        ubuntu|debian)
            install_dependencies_debian
            ;;
        rhel|centos|rocky|almalinux)
            install_dependencies_redhat
            ;;
        fedora)
            install_dependencies_redhat
            ;;
        alpine)
            install_dependencies_alpine
            ;;
        *)
            print_color "Unsupported OS: $OS" "$RED"
            exit 1
            ;;
    esac
}

create_user() {
    print_color "Creating service user..." "$BLUE"
    if ! id -u $SERVICE_USER > /dev/null 2>&1; then
        useradd -r -s /bin/false -d $INSTALL_DIR $SERVICE_USER
    fi
}

create_directories() {
    print_color "Creating directories..." "$BLUE"
    mkdir -p $INSTALL_DIR
    mkdir -p $DATA_DIR
    mkdir -p $LOG_DIR
    mkdir -p $CONFIG_DIR
    
    chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR $DATA_DIR $LOG_DIR
}

install_application() {
    print_color "Installing RedBadger application..." "$BLUE"
    
    # Copy main application
    cp redbadger.py $INSTALL_DIR/
    
    # Copy requirements
    cp requirements.txt $INSTALL_DIR/
    
    # Install Python packages
    pip3 install --no-cache-dir -r $INSTALL_DIR/requirements.txt
    
    # Create config file
    cat > $CONFIG_DIR/config.json << EOF
{
    "database": "$DATA_DIR/redbadger.db",
    "log_file": "$LOG_DIR/redbadger.log",
    "report_dir": "$DATA_DIR/reports",
    "web_port": 5000,
    "web_host": "0.0.0.0",
    "monitoring_enabled": true
}
EOF
    
    chown $SERVICE_USER:$SERVICE_USER $CONFIG_DIR/config.json
}

create_systemd_service() {
    print_color "Creating systemd service..." "$BLUE"
    
    cat > /etc/systemd/system/redbadger.service << EOF
[Unit]
Description=RedBadger Security Platform
After=network.target sqlite3.service
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/redbadger.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=redbadger

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR $CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable redbadger
}

create_logrotate() {
    print_color "Configuring log rotation..." "$BLUE"
    
    cat > /etc/logrotate.d/redbadger << EOF
$LOG_DIR/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $SERVICE_USER $SERVICE_USER
}
EOF
}

setup_firewall() {
    print_color "Setting up firewall rules..." "$BLUE"
    
    if command -v ufw &> /dev/null; then
        ufw allow 5000/tcp comment 'RedBadger Web Interface'
        ufw allow 8080/tcp comment 'RedBadger Phishing Simulator'
        ufw reload
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=5000/tcp
        firewall-cmd --permanent --add-port=8080/tcp
        firewall-cmd --reload
    elif command -v iptables &> /dev/null; then
        iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
        iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
        # Save rules
        if [[ $OS == "ubuntu" ]] || [[ $OS == "debian" ]]; then
            iptables-save > /etc/iptables/rules.v4
        fi
    fi
}

print_summary() {
    print_color "\n=========================================" "$GREEN"
    print_color "RedBadger Security Platform Installation Complete!" "$GREEN"
    print_color "=========================================" "$GREEN"
    echo ""
    print_color "📍 Installation Directory: $INSTALL_DIR" "$BLUE"
    print_color "📍 Data Directory: $DATA_DIR" "$BLUE"
    print_color "📍 Log Directory: $LOG_DIR" "$BLUE"
    print_color "📍 Config Directory: $CONFIG_DIR" "$BLUE"
    echo ""
    print_color "🚀 To start RedBadger:" "$YELLOW"
    print_color "   sudo systemctl start redbadger" "$YELLOW"
    echo ""
    print_color "📊 Check status:" "$YELLOW"
    print_color "   sudo systemctl status redbadger" "$YELLOW"
    echo ""
    print_color "📝 View logs:" "$YELLOW"
    print_color "   sudo journalctl -u redbadger -f" "$YELLOW"
    echo ""
    print_color "🌐 Web Interface: http://localhost:5000" "$GREEN"
    echo ""
    print_color "🔧 Manual run:" "$YELLOW"
    print_color "   cd $INSTALL_DIR && python3 redbadger.py" "$YELLOW"
    echo ""
    print_color "⚠️  IMPORTANT: Configure integrations (Discord, Telegram, Slack) on first run!" "$YELLOW"
}

# Main installation
main() {
    print_color "🐻 RedBadger Security Platform Installer" "$GREEN"
    print_color "========================================" "$GREEN"
    
    check_root
    detect_os
    install_dependencies
    create_user
    create_directories
    install_application
    create_systemd_service
    create_logrotate
    setup_firewall
    print_summary
}

# Run main function
main