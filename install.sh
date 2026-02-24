#!/bin/bash
set -e

# ==========================================
# Configuration (ဒီနေရာမှာ ပြင်ဆင်ပါ)
# ==========================================
# သင်၏ database.sh ရှိမည့် GitHub Raw Link ကို ထည့်ပါ
DB_URL="https://raw.githubusercontent.com/nyeinkokoaung404/channel404-manager/main/database.sh"

# အခြား URLs
MENU_URL="https://raw.githubusercontent.com/nyeinkokoaung404/channel404-manager/main/menu.sh"
SSHD_URL="https://raw.githubusercontent.com/nyeinkokoaung404/channel404-manager/main/ssh"
# ==========================================

# Must be root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

clear
echo "------------------------------------------------"
echo "        Channel404 Manager Installer           "
echo "        Developer: @nkka404                    "
echo "------------------------------------------------"

# ၁။ VPS IP ကို စစ်ဆေးခြင်း
echo -n "Checking system IP... "
SERVER_IP=$(wget -4 -qO- http://checkip.amazonaws.com || curl -s4 icanhazip.com)
echo "[$SERVER_IP]"

# ၂။ Serial Key တောင်းခြင်း
echo -e "\nContact @nkka404 to get your Serial Key."
read -p "Enter Serial Key: " USER_KEY

if [[ -z "$USER_KEY" ]]; then
    echo "❌ Error: Serial Key is required!"
    exit 1
fi

echo "Verifying license..."

# ၃။ Database မှ အချက်အလက်ယူခြင်း
DB_DATA=$(wget -4 -qO- "$DB_URL" || { echo "❌ Server Error: Could not connect to database."; exit 1; })
KEY_INFO=$(echo "$DB_DATA" | grep "^$USER_KEY|")

if [[ -z "$KEY_INFO" ]]; then
    echo "❌ Error: Invalid Serial Key!"
    exit 1
fi

# ၄။ Data ခွဲထုတ်ခြင်း (Key|Expiry|IP)
EXPIRY_DATE=$(echo "$KEY_INFO" | cut -d'|' -f2)
ALLOWED_IP=$(echo "$KEY_INFO" | cut -d'|' -f3)
CURRENT_DATE_SEC=$(date +%s)
EXPIRY_DATE_SEC=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || echo 0)

# ၅။ သက်တမ်းကုန်/မကုန် စစ်ဆေးခြင်း
if [[ $CURRENT_DATE_SEC -gt $EXPIRY_DATE_SEC ]]; then
    echo "❌ Error: This key expired on $EXPIRY_DATE."
    exit 1
fi

# ၆။ IP Lock စစ်ဆေးခြင်း
if [[ "$ALLOWED_IP" != "ANY" ]] && [[ "$ALLOWED_IP" != "$SERVER_IP" ]]; then
    echo "❌ Access Denied: This key is locked to another IP ($ALLOWED_IP)."
    echo "Your IP: $SERVER_IP"
    exit 1
fi

echo "✅ License Verified! Expiry: $EXPIRY_DATE"
echo "------------------------------------------------"
echo "Proceeding to installation..."
sleep 2

# ၇။ Installation စတင်ခြင်း
echo "Installing dependencies..."
apt-get update -y > /dev/null 2>&1 || yum update -y > /dev/null 2>&1

echo "Downloading components..."
wget -4 -q -O /usr/local/bin/menu "$MENU_URL"
chmod +x /usr/local/bin/menu

echo "Applying SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.backup.$(date +%F-%H%M%S)"

cp "$SSHD_CONFIG" "$BACKUP"
wget -4 -q -O "$SSHD_CONFIG" "$SSHD_URL"
chmod 600 "$SSHD_CONFIG"

# Validate SSH config
if ! sshd -t 2>/dev/null; then
    echo "ERROR: SSH configuration is invalid! Restoring..."
    cp "$BACKUP" "$SSHD_CONFIG"
    exit 1
fi

# Restart SSH service
restart_ssh() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    elif command -v service >/dev/null 2>&1; then
        service sshd restart 2>/dev/null || service ssh restart 2>/dev/null
    fi
}

restart_ssh && echo "SSH service restarted." || echo "Restart failed, manual reboot may be needed."

# Run Setup from menu
if [ -f /usr/local/bin/menu ]; then
    bash /usr/local/bin/menu --install-setup
fi

echo "------------------------------------------------"
echo " Installation Complete!"
echo " Developer: @nkka404"
echo " Type 'menu' to start."
echo "------------------------------------------------"
