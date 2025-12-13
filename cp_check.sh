#!/bin/bash
# =============================================================================
# CyberPatriot Linux Initial Checklist & Fix Script
# Run as root: sudo bash this_script.sh
# Author: Liam
# Last updated: 2025
# =============================================================================

echo "============================================================"
echo "    CyberPatriot Linux Hardening Checklist Script, hi"
echo "    This script only READS and REPORTS (and suggests fixes)"
echo "============================================================"
echo




# Temporary file for issues
SYS_REPORT="$PWD/cyberpatriot_sys_report_$(date +%Y%m%d_%H%M%S).txt"
USER_REPORT="$PWD/cyberpatriot_user_report_$(date +%Y%m%d_%H%M%S).txt"
APP_REPORT="$PWD/cyberpatriot_app_report_$(date +%Y%m%d_%H%M%S).txt"
echo "CyberPatriot Quick Hardening App Report - $(date)" > "$APP_REPORT"
echo "CyberPatriot Quick Hardening User Report - $(date)" > "$USER_REPORT"
echo "CyberPatriot Quick Hardening System Report - $(date)" > "$SYS_REPORT"
echo "Hostname: $(hostname)" >> "$APP_REPORT"
echo "Hostname: $(hostname)" >> "$USER_REPORT"
echo "Hostname: $(hostname)" >> "$SYS_REPORT"
echo "Distro: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)" >> "$APP_REPORT"
echo "Distro: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)" >> "$USER_REPORT"
echo "Distro: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)" >> "$SYS_REPORT"
echo "===========================================" >> "$APP_REPORT"
echo "===========================================" >> "$USER_REPORT"
echo "===========================================" >> "$SYS_REPORT"
echo >> "$APP_REPORT"
echo >> "$USER_REPORT"
echo >> "$SYS_REPORT"

# ------------------------------------------------------------------
# 1. Check for forbidden media files (common in CP images)
# ------------------------------------------------------------------

echo -e "[1] Searching for forbidden media files (.mp3, .mp4, .avi, .jpg, etc.)${NC}"
echo "Below files were found (if any). To remove them, cd into the directory and delete them with the rm command:" >> "$APP_REPORT"
echo >> "$APP_REPORT"

find /home /root /var/www /tmp -type f \( \
    -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" -o \
    -iname "*.jpg" -o -iname "*.png" -o -iname "*.gif" -o -iname "*.torrent" \) \
    2>/dev/null >> "$APP_REPORT"

echo

# ------------------------------------------------------------------
# 2. Users Groups & Passwords
# ------------------------------------------------------------------

echo -e "[2] Checking user accounts${NC}"

# List all users with login shell
echo "Users with login shells:" >> "$USER_REPORT"
echo "===========================================" >> "$USER_REPORT"

awk -F: '$7 ~ /(bash|sh|zsh|csh|ksh)/ {print "  " $1 " (UID:" $3 ") Home:" $6}' /etc/passwd >> "$USER_REPORT"

# Users that should almost always be removed/disabled in CP
BAD_USERS=("games" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "sys" "sync")

for user in "${BAD_USERS[@]}"; do
    if id "$user" >/dev/null 2>&1; then
        echo -e "${RED}   → Unauthorized user found: $user${NC}" >> "$USER_REPORT"
        echo "   Fix: sudo userdel -r $user   OR   sudo passwd -l $user (lock)" >> "$USER_REPORT"
    fi
done
# Check for users with UID 0 (root privileges)
echo >> "$USER_REPORT"
echo "Users with UID 0 (root privileges):" >> "$USER_REPORT"
echo "===========================================" >> "$USER_REPORT"
awk -F: '($3 == "0") {print "  " $1}' /etc/passwd >> "$USER_REPORT"
if [ $(awk -F: '($3 == "0") {print}' /etc/passwd | wc -l) -gt 1 ]; then
    echo -e "${RED}   → Extra root accounts detected! Leave only 'root'.${NC}"
fi
echo

# List current groups and users in them

echo -e "[3] Checking groups and their members${NC}"
echo >> "$USER_REPORT"
echo "Groups and their members:" >> "$USER_REPORT"
echo "===========================================" >> "$USER_REPORT"
echo >> "$USER_REPORT"
echo "To delete a group: sudo groupdel groupname" >> "$USER_REPORT"
echo "To remove a user from a group: sudo gpasswd -d username groupname" >> "$USER_REPORT"
echo "To add a user to a group: sudo usermod -aG groupname username" >> "$USER_REPORT"
echo >> "$USER_REPORT"

if [[ $UID -ne 0 ]]; then
    echo "[!] Warning: Not running as root. Some sudo privileges may not be visible."
    echo
fi

# Get all groups (skip system groups if you want only user groups, remove _SKIP_SYSTEM if not)
_SKIP_SYSTEM=1  # Set to 0 to include system groups like daemon, bin, etc.

while IFS=: read -r group _ gid members; do
    # Skip system groups (GID < 1000 typically) if desired
    if [[ $_SKIP_SYSTEM -eq 1 && $gid -lt 1000 ]]; then
        continue
    fi

    echo "Group: $group  (GID: $gid)" >> "$USER_REPORT"
    echo "Members: ${members:-none (empty)}" >> "$USER_REPORT"

    # Replace commas with spaces for easier looping
    IFS=',' read -ra USERLIST <<< "$members"

    has_sudo=false
    sudo_details=""

    # Check each member for sudo rights
    for user in "${USERLIST[@]:-}"; do
        user=$(echo "$user" | xargs)  # trim whitespace
        [[ -z "$user" ]] && continue

        if sudo -l -U "$user" 2>/dev/null; then
            has_sudo=true
            privs=$(sudo -l -U "$user" | grep -E '\(root\)|NOPASSWD' | sed 's/^/    /')
            if [[ -n "$privs" ]]; then
                sudo_details="$sudo_details\n$user can run the following as root:\n$privs"
            else
                sudo_details="$sudo_details\n$user may run some commands (but none with (root) or NOPASSWD visible)"
            fi
        fi
    done

    # Check if the group itself has sudo rights via /etc/sudoers
    if grep -E -q "^%$group" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
        has_sudo=true
        group_sudo=$(grep -E "^%$group" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/    /')
        sudo_details="$sudo_details\nGroup '$group' has direct sudoers entry:\n$group_sudo"
    fi

    if $has_sudo; then
        echo "PRIVILEGES: Elevated (sudo access detected)" >> "$USER_REPORT"
        echo -e "$sudo_details" >> "$USER_REPORT"
    else
        echo "PRIVILEGES: Standard user group (no sudo rights found)" >> "$USER_REPORT"
    fi

    # Check for sensitive group memberships (common privilege vectors)
    sensitive=false
    case "$group" in
        adm|sudo|admin|wheel|root|docker|lxd|libvirt|kvm|disk|cdrom|floppy|tape|audio|video|plugdev|netdev|systemd-journal|systemd-network|ssh|shadow)
            sensitive=true
            ;;
    esac

    if $sensitive; then
        echo "NOTE: This group grants access to sensitive resources (logs, hardware, containers, etc.)" >> "$USER_REPORT"
    fi

    echo "--------------------------------------------------" >> "$USER_REPORT"
done < <(getent group)
echo   




# ------------------------------------------------------------------
# 4. Check password policy (Ubuntu/Debian common location)
# ------------------------------------------------------------------
echo -e "[4] Password policy check${NC}"
echo >> "$USER_REPORT"
if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
    grep "^PASS_MAX_DAYS" /etc/login.defs >> "$USER_REPORT"
    if [ $(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}') -gt 90 ]; then
        echo -e "${RED}   → Passwords never expire or too long!${NC}" >> "$USER_REPORT"
        echo "   Fix: sudo sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs" >> "$USER_REPORT"
    fi
fi
echo

# ------------------------------------------------------------------
# 5. Check for empty password or no password users
# ------------------------------------------------------------------
echo -e "[5] Users with empty passwords${NC}"
echo >> "$USER_REPORT"
while IFS=: read -r username _ uid _ _ _ _; do
    [[ $uid -ge 1000 && $username != "nobody" ]] && {
        passwd -S "$username" | grep -q "Password locked\|NP" && {
            echo -e "${RED}   → $username has no password!${NC}" >> "$USER_REPORT"
            echo "   Fix: sudo passwd $username" >> "$USER_REPORT"
        }
    }
done < /etc/passwd
echo

# ------------------------------------------------------------------
# 6. Services – disable unnecessary ones
# ------------------------------------------------------------------
echo -e "[6] Checking common unnecessary services${NC}"
echo >> "$SYS_REPORT"

SERVICES=("vsftpd" "apache2" "httpd" "nginx" "smbd" "nmbd" "telnetd" "rsync" "nis" "rsh" "rexec" "rlogin" "tftp" "docker")

for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null || service "$svc" status >/dev/null 2>&1; then
        echo -e "${RED}   → $svc is RUNNING${NC}" >> "$SYS_REPORT"
        echo "   Fix: sudo systemctl stop $svc && sudo systemctl disable $svc" >> "$SYS_REPORT"
    fi
done
echo

# ------------------------------------------------------------------
# 7. Firewall status (ufw or firewalld)
# ------------------------------------------------------------------
echo -e "[7] Firewall status${NC}"
echo >> "$SYS_REPORT"
if command -v ufw >/dev/null 2>&1; then
    ufw status >> "$SYS_REPORT"
    if ufw status | grep -q "inactive"; then
        echo -e "${RED}   → UFW is inactive!${NC}" >> "$SYS_REPORT"
        echo "   Fix: sudo ufw enable && sudo ufw default deny incoming && sudo ufw allow ssh" >> "$SYS_REPORT"
    fi
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --state 2>/dev/null >> "$SYS_REPORT"
    sudo firewall-cmd --list-all >> "$SYS_REPORT"
fi
echo

# ------------------------------------------------------------------
# 8. Check for outdated packages (critical in every round)
# ------------------------------------------------------------------
echo -e "[8] Checking for outdated packages${NC}"

if command -v apt >/dev/null 2>&1; then
    echo "Running: apt update && apt list --upgradable"
    apt update >/dev/null 2>&1
    apt list --upgradable >> "$SYS_REPORT"
    echo -e "${GREEN}   → Run these commands to update:${NC}"
    echo "   sudo apt update && sudo apt upgrade -y && sudo apt autoremove -y"
elif command -v yum >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
    echo "Running: yum check-update or dnf check-update"
    yum check-update --security || dnf check-update --security
    echo -e "${GREEN}   → Run: sudo yum update -y || sudo dnf update -y${NC}"
fi
echo

# ------------------------------------------------------------------
# 9. Check SSH configuration (very common points)
# ------------------------------------------------------------------
echo -e "[9] SSH hardening check${NC}"
SSH_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSH_CONFIG" ]; then
    grep -i "PermitRootLogin" "$SSH_CONFIG" >> "$SYS_REPORT"
    grep -i "PasswordAuthentication" "$SSH_CONFIG" >> "$SYS_REPORT"
    grep -i "PermitEmptyPasswords" "$SSH_CONFIG" >> "$SYS_REPORT"

    if grep -qi "PermitRootLogin yes" "$SSH_CONFIG"; then
        echo -e "${RED}   → Root login via SSH allowed!${NC}"
        echo "   Fix: sudo sed -i 's/PermitRootLogin.*/PermitRootLogin no/' $SSH_CONFIG && sudo systemctl restart sshd"
    fi
    if grep -qi "PasswordAuthentication yes" "$SSH_CONFIG"; then
        echo -e "${YELLOW}   → Password auth enabled (OK if using key only is not required)${NC}"
    fi
fi
echo

# ------------------------------------------------------------------
# 10. Check system for any known bad packages (telnet, rcmd, etc.)
# ------------------------------------------------------------------
echo -e "[10] Checking for known bad packages${NC}"
echo >> "$APP_REPORT"
BAD_PACKAGES=("telnet" "rlogind" "rshd" "rcmd" "rexecd" "rbootd" "rquotad" "rstatd" "rusersd" "rwalld" "rexd" "fingerd" "tftpd" "john" "nmap" "vuze" "frostwire" "kismet" "freeciv" "minetest" "minetest-server" "medusa" "hydra" "truecrack" "ophcrack" "nikto" "cryptcat" "nc" "netcat" "tightvncserver" "x11vnc" "nfs" "xinetd")
for pkg in "${BAD_PACKAGES[@]}"; do
    if dpkg -l | grep -qw "$pkg" || rpm -q "$pkg" >/dev/null 2>&1; then
        echo -e "${RED}   → Bad package installed: $pkg${NC}" >> "$APP_REPORT"
        echo "   Fix: sudo apt remove $pkg -y   OR   sudo yum remove $pkg -y" >> "$APP_REPORT"
    fi
done
echo "Only known bad packages are checked, there may be others." >> "$APP_REPORT"
echo "Consider reviewing installed packages manually by running dpkg -l" >> "$APP_REPORT"
echo

echo "============================================================"
echo "               CHECKLIST COMPLETE!"
echo "============================================================"${NC}

