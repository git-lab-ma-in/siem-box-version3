#!/usr/bin/env bash
# =============================================================================
# install-agent.sh — OSSIEM Web-Agent Installer
#
# Cai dat va dang ky Wazuh Agent tren mot may chu Web Linux (nginx/apache),
# cau hinh gui log truy cap (access log) ve Wazuh Manager de dong ho AI
# (ossiem_ai.py) phan tich va tu sinh luat. Tuy chon: tu dong ap dung
# blocklist IP do AI sinh ra (chan bang ipset + iptables/nftables).
#
# Chay tren may chu Web can giam sat (KHONG chay tren may SIEM/manager).
#
# Cach dung:
#   sudo MANAGER_IP=1.2.3.4 ./install-agent.sh
#
# Bien moi truong (co the export truoc hoac dat inline):
#   MANAGER_IP        (bat buoc) IP/hostname cua Wazuh Manager (may SIEM)
#   AGENT_NAME         Ten agent hien thi tren Wazuh (mac dinh: hostname)
#   MANAGER_PORT       Cong enrollment cua manager (mac dinh: 1515)
#   AUTHD_PASSWORD     Mat khau dang ky agent qua authd, neu manager yeu cau
#   WEBSERVER           nginx | apache | auto (mac dinh: auto - tu do)
#   AI_URL             URL toi OSSIEM-AI tren manager, vd: http://1.2.3.4:8088
#   AI_RULES_TOKEN     Bearer token de tai blocklist/suricata rules tu AI_URL
#   AI_RULES_HMAC_KEY  (tuy chon) Khoa xac thuc chu ky HMAC cua AI_URL
#   ENABLE_BLOCKLIST   yes|no - tu dong chan IP theo blocklist AI (mac dinh: no)
#   BLOCKLIST_INTERVAL Chu ky (giay) tai lai blocklist (mac dinh: 60)
#   WAZUH_VERSION      Phien ban goi wazuh-agent (mac dinh: 4.9.0-1)
#   AGENT_PACKAGE      (offline) Duong dan toi goi wazuh-agent .deb/.rpm da tai san tu
#                      https://packages.wazuh.com tren mot may co Internet. Khi dat bien
#                      nay, script se dpkg -i/rpm -i truc tiep, KHONG them repo online,
#                      KHONG can Internet tren may chu Web nay.
#
# CHAY OFFLINE: tren mot may CO Internet, tai san goi tuong ung:
#   Debian/Ubuntu: https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/ (chon .deb dung kien truc)
#   RHEL/CentOS  : https://packages.wazuh.com/4.x/yum/wazuh-agent-<ver>.rpm
# roi chep sang may chu Web (USB/mang noi bo) va chay:
#   sudo MANAGER_IP=1.2.3.4 AGENT_PACKAGE=/tmp/wazuh-agent_4.9.0-1_amd64.deb ./install-agent.sh
#
# Idempotent: chay lai nhieu lan an toan, se ghi de cau hinh cu.
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------ tham so
MANAGER_IP="${MANAGER_IP:-}"
AGENT_NAME="${AGENT_NAME:-$(hostname -f 2>/dev/null || hostname)}"
MANAGER_PORT="${MANAGER_PORT:-1515}"
AUTHD_PASSWORD="${AUTHD_PASSWORD:-}"
WEBSERVER="${WEBSERVER:-auto}"
AI_URL="${AI_URL:-}"
AI_RULES_TOKEN="${AI_RULES_TOKEN:-}"
AI_RULES_HMAC_KEY="${AI_RULES_HMAC_KEY:-}"
ENABLE_BLOCKLIST="${ENABLE_BLOCKLIST:-no}"
BLOCKLIST_INTERVAL="${BLOCKLIST_INTERVAL:-60}"
WAZUH_VERSION="${WAZUH_VERSION:-4.9.0-1}"
AGENT_PACKAGE="${AGENT_PACKAGE:-}"

log()  { printf '\033[1;36m[install-agent]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install-agent][CANH BAO]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[install-agent][LOI]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Script nay phai chay bang root (sudo)."
[ -n "$MANAGER_IP" ] || die "Thieu MANAGER_IP. Vi du: sudo MANAGER_IP=1.2.3.4 ./install-agent.sh"

# ------------------------------------------------------------ nhan dien OS
PKG=""
if command -v apt-get >/dev/null 2>&1; then PKG="apt"
elif command -v yum >/dev/null 2>&1; then PKG="yum"
elif command -v dnf >/dev/null 2>&1; then PKG="dnf"
else die "Khong nhan dien duoc trinh quan ly goi (can apt-get/yum/dnf)."
fi
log "He quan tri goi: $PKG | Manager: $MANAGER_IP:$MANAGER_PORT | Ten agent: $AGENT_NAME"

# ------------------------------------------------------- cai dat wazuh-agent
install_wazuh_agent() {
    if [ -x /var/ossec/bin/wazuh-control ]; then
        log "wazuh-agent da duoc cai dat, bo qua buoc cai moi."
        return
    fi
    if [ -n "$AGENT_PACKAGE" ]; then
        log "Che do offline: cai wazuh-agent tu goi da tai san $AGENT_PACKAGE ..."
        [ -f "$AGENT_PACKAGE" ] || die "Khong tim thay tep AGENT_PACKAGE=$AGENT_PACKAGE"
        case "$PKG" in
            apt)
                command -v dpkg >/dev/null 2>&1 || die "Thieu dpkg."
                WAZUH_MANAGER="$MANAGER_IP" dpkg -i "$AGENT_PACKAGE" \
                    || die "Cai dat that bai (dpkg -i $AGENT_PACKAGE). Kiem tra kien truc/goi phu thuoc."
                ;;
            yum|dnf)
                WAZUH_MANAGER="$MANAGER_IP" rpm -ivh "$AGENT_PACKAGE" \
                    || die "Cai dat that bai (rpm -ivh $AGENT_PACKAGE). Kiem tra kien truc/goi phu thuoc."
                ;;
        esac
        [ -x /var/ossec/bin/wazuh-control ] || die "Cai dat wazuh-agent that bai."
        log "Cai dat wazuh-agent (offline) xong."
        return
    fi
    log "Dang cai dat wazuh-agent ${WAZUH_VERSION} (can Internet - dung AGENT_PACKAGE=... neu may nay offline) ..."
    case "$PKG" in
        apt)
            apt-get update -y
            apt-get install -y curl gnupg apt-transport-https lsb-release ipset iptables
            curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
                > /etc/apt/sources.list.d/wazuh.list
            apt-get update -y
            WAZUH_MANAGER="$MANAGER_IP" apt-get install -y "wazuh-agent=${WAZUH_VERSION}" \
                || WAZUH_MANAGER="$MANAGER_IP" apt-get install -y wazuh-agent
            ;;
        yum|dnf)
            $PKG install -y curl ipset iptables-services || $PKG install -y curl ipset
            cat >/etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
            WAZUH_MANAGER="$MANAGER_IP" $PKG install -y "wazuh-agent-${WAZUH_VERSION}" \
                || WAZUH_MANAGER="$MANAGER_IP" $PKG install -y wazuh-agent
            ;;
    esac
    [ -x /var/ossec/bin/wazuh-control ] || die "Cai dat wazuh-agent that bai."
    log "Cai dat wazuh-agent xong."
}

# --------------------------------------------------------- dang ky voi manager
enroll_agent() {
    log "Dang ky agent voi manager qua agent-auth (cong ${MANAGER_PORT}) ..."
    systemctl stop wazuh-agent 2>/dev/null || true
    AUTH_ARGS=(-m "$MANAGER_IP" -p "$MANAGER_PORT" -A "$AGENT_NAME")
    if [ -n "$AUTHD_PASSWORD" ]; then
        AUTH_ARGS+=(-P "$AUTHD_PASSWORD")
    fi
    if ! /var/ossec/bin/agent-auth "${AUTH_ARGS[@]}"; then
        warn "agent-auth that bai (co the manager yeu cau mat khau authd, dat AUTHD_PASSWORD)."
        warn "Se van tiep tuc cau hinh - ban co the chay lai enrollment sau: /var/ossec/bin/agent-auth -m $MANAGER_IP"
    else
        log "Dang ky thanh cong, da nhan client.keys."
    fi
}

# ------------------------------------------------------------- cau hinh ossec.conf
detect_webserver() {
    local w="$WEBSERVER"
    if [ "$w" = "auto" ]; then
        w=""
        [ -d /var/log/nginx ] && w="${w}nginx "
        { [ -d /var/log/apache2 ] || [ -d /var/log/httpd ]; } && w="${w}apache"
        [ -z "$w" ] && w="none"
    fi
    echo "$w"
}

configure_ossec() {
    local wsvc; wsvc="$(detect_webserver)"
    log "Web server phat hien: ${wsvc:-none}"

    local conf=/var/ossec/etc/ossec.conf
    [ -f "$conf" ] || die "Khong tim thay $conf - cai dat wazuh-agent that bai?"
    cp -a "$conf" "${conf}.bak.$(date +%s)"

    # Dat dia chi manager
    python3 - "$conf" "$MANAGER_IP" <<'PYEOF' 2>/dev/null || \
    sed -i "s#<address>.*</address>#<address>${MANAGER_IP}</address>#" "$conf"
import sys, re
p, ip = sys.argv[1], sys.argv[2]
s = open(p).read()
s2 = re.sub(r"<address>.*?</address>", f"<address>{ip}</address>", s, count=1)
open(p, "w").write(s2)
PYEOF

    # Chen cac khoi <localfile> cho access log truoc the dong </ossec_config> dau tien
    LOCALFILE_BLOCK=""
    if echo "$wsvc" | grep -q nginx; then
        LOCALFILE_BLOCK+=$'  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/nginx/access.log</location>\n  </localfile>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/nginx/error.log</location>\n  </localfile>\n'
    fi
    if echo "$wsvc" | grep -q apache; then
        for p in /var/log/apache2/access.log /var/log/apache2/error.log /var/log/httpd/access_log /var/log/httpd/error_log; do
            [ -f "$p" ] || continue
            LOCALFILE_BLOCK+="  <localfile>\n    <log_format>syslog</log_format>\n    <location>${p}</location>\n  </localfile>\n"
        done
    fi

    if [ -n "$LOCALFILE_BLOCK" ] && ! grep -q "OSSIEM-AI localfile block" "$conf"; then
        TMP="$(mktemp)"
        awk -v block="$LOCALFILE_BLOCK" '
            /<\/ossec_config>/ && !done {
                print "  <!-- OSSIEM-AI localfile block (added by install-agent.sh) -->"
                printf "%s", block
                done=1
            }
            { print }
        ' "$conf" > "$TMP"
        mv "$TMP" "$conf"
        log "Da them cau hinh gui log web server (${wsvc}) ve manager."
    elif [ -z "$LOCALFILE_BLOCK" ]; then
        warn "Khong tim thay nginx/apache dang chay - chua them localfile nao. Chay lai voi WEBSERVER=nginx|apache neu can."
    fi

    chown wazuh:wazuh "$conf" 2>/dev/null || true
}

# -------------------------------------------------------- khoi dong agent
start_agent() {
    systemctl enable wazuh-agent >/dev/null 2>&1 || true
    systemctl restart wazuh-agent
    sleep 2
    systemctl is-active --quiet wazuh-agent && log "wazuh-agent dang chay." \
        || warn "wazuh-agent khong o trang thai active, kiem tra: journalctl -u wazuh-agent -n 50"
}

# ------------------------------------------------ tu dong chan IP theo AI
setup_blocklist_enforcement() {
    [ "$ENABLE_BLOCKLIST" = "yes" ] || { log "ENABLE_BLOCKLIST=no -> bo qua thiet lap tu dong chan IP."; return; }
    [ -n "$AI_URL" ] && [ -n "$AI_RULES_TOKEN" ] || { warn "Thieu AI_URL/AI_RULES_TOKEN -> bo qua tu dong chan IP."; return; }

    command -v ipset >/dev/null 2>&1 || { warn "Khong co ipset -> bo qua tu dong chan IP."; return; }
    ipset list ossiem-ai-block >/dev/null 2>&1 || ipset create ossiem-ai-block hash:ip timeout 3600
    if command -v iptables >/dev/null 2>&1; then
        iptables -C INPUT -m set --match-set ossiem-ai-block src -j DROP 2>/dev/null \
            || iptables -I INPUT -m set --match-set ossiem-ai-block src -j DROP
    fi

    install -d -m 755 /usr/local/lib/ossiem-ai
    cat > /usr/local/bin/ossiem-ai-block-sync.sh <<EOF
#!/usr/bin/env bash
# Tu dong sinh boi install-agent.sh - tai va ap dung blocklist IP tu OSSIEM-AI
set -euo pipefail
AI_URL="${AI_URL}"
TOKEN="${AI_RULES_TOKEN}"
HMAC_KEY="${AI_RULES_HMAC_KEY}"
TMP="\$(mktemp)"
HDR="\$(mktemp)"
trap 'rm -f "\$TMP" "\$HDR"' EXIT

if ! curl -fsS -D "\$HDR" -H "Authorization: Bearer \$TOKEN" "\$AI_URL/rules/blocklist.txt" -o "\$TMP"; then
    echo "\$(date -Is) loi tai blocklist tu \$AI_URL" >&2
    exit 1
fi

if [ -n "\$HMAC_KEY" ]; then
    SIG="\$(grep -i '^X-OSSIEM-Signature:' "\$HDR" | tr -d '\r' | cut -d' ' -f2- || true)"
    CALC="\$(openssl dgst -sha256 -hmac "\$HMAC_KEY" "\$TMP" | awk '{print \$2}')"
    if [ -z "\$SIG" ] || [ "\$SIG" != "\$CALC" ]; then
        echo "\$(date -Is) CANH BAO: chu ky HMAC blocklist khong hop le, bo qua lan cap nhat nay" >&2
        exit 1
    fi
fi

ipset create ossiem-ai-block hash:ip timeout 3600 -exist
while read -r ip ttl _; do
    [ -n "\${ip:-}" ] || continue
    case "\$ip" in \#*) continue;; esac
    ipset add ossiem-ai-block "\$ip" timeout "\${ttl:-3600}" -exist 2>/dev/null || true
done < "\$TMP"
EOF
    chmod 700 /usr/local/bin/ossiem-ai-block-sync.sh

    cat > /etc/systemd/system/ossiem-ai-block.service <<EOF
[Unit]
Description=OSSIEM-AI blocklist sync (mot lan)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ossiem-ai-block-sync.sh
EOF
    cat > /etc/systemd/system/ossiem-ai-block.timer <<EOF
[Unit]
Description=OSSIEM-AI blocklist sync moi ${BLOCKLIST_INTERVAL}s
[Timer]
OnBootSec=15
OnUnitActiveSec=${BLOCKLIST_INTERVAL}
AccuracySec=5
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now ossiem-ai-block.timer
    log "Da bat tu dong dong bo blocklist AI moi ${BLOCKLIST_INTERVAL}s (ipset: ossiem-ai-block, DROP qua iptables INPUT)."
}

# --------------------------------------------------------------------- main
install_wazuh_agent
enroll_agent
configure_ossec
start_agent
setup_blocklist_enforcement

cat <<EOF

================================================================
 OSSIEM Web-Agent da cai dat xong tren: $(hostname)
   Ten agent      : $AGENT_NAME
   Manager         : $MANAGER_IP:$MANAGER_PORT
   Web server log  : $(detect_webserver)
   Tu dong chan IP : $ENABLE_BLOCKLIST
 Kiem tra ket noi tren manager: /var/ossec/bin/manage_agents -l
================================================================
EOF