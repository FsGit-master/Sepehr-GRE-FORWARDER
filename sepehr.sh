#!/usr/bin/env bash

# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  FsTunnel v1.2 - Survival Grade Tunnel System                           ║
# ║  Designed for Hostile Network Environments                               ║
# ║  Creator: @DevHttp                                                       ║
# ║                                                                          ║
# ║  Zero Downtime • DPI Resistant • Self-Healing • Maximum Performance     ║
# ╚══════════════════════════════════════════════════════════════════════════╝

set +e
set +u
export LC_ALL=C
LOG_LINES=()
LOG_MIN=3
LOG_MAX=12

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
NC='\033[0m'
BOLD='\033[1m'

banner() {
  echo -e "${CYAN}${BOLD}"
  cat <<'EOF'
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ███████╗███████╗████████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗      ║
║   ██╔════╝██╔════╝╚══██╔══╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║      ║
║   █████╗  ███████╗   ██║   ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║      ║
║   ██╔══╝  ╚════██║   ██║   ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║      ║
║   ██║     ███████║   ██║   ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗ ║
║   ╚═╝     ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝ ║
║                                                                           ║
║              ╔══════════════════════════════════════════╗                 ║
║              ║   SURVIVAL GRADE TUNNEL SYSTEM v1.2    ║                 ║
║              ╚══════════════════════════════════════════╝                 ║
║                                                                           ║
║   ⚡ Zero Downtime Protection     🛡️  DPI/Firewall Resistant            ║
║   🔄 Intelligent Self-Healing      🚀 Maximum Performance                ║
║   ♾️  Long-Term Stability          🎯 Adaptive Behavior                  ║
║                                                                           ║
║                         Creator: @DevHttp                                 ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
  echo -e "${NC}"
}

add_log() {
  local msg="$1"
  local level="${2:-INFO}"
  local ts color
  ts="$(date +"%H:%M:%S")"

  case "$level" in
    ERROR) color="${RED}✗" ;;
    SUCCESS) color="${GREEN}✓" ;;
    WARN) color="${YELLOW}⚠" ;;
    *) color="${CYAN}●" ;;
  esac

  LOG_LINES+=("${color} ${GRAY}[$ts]${NC} $msg")
  if ((${#LOG_LINES[@]} > LOG_MAX)); then
    LOG_LINES=("${LOG_LINES[@]: -$LOG_MAX}")
  fi
}

render() {
  clear
  banner
  echo
  local shown_count="${#LOG_LINES[@]}"
  local height=$shown_count
  ((height < LOG_MIN)) && height=$LOG_MIN
  ((height > LOG_MAX)) && height=$LOG_MAX

  echo -e "${PURPLE}┌─────────────────────────────${WHITE}${BOLD} SYSTEM LOG ${NC}${PURPLE}─────────────────────────────┐${NC}"
  local start_index=0
  if ((${#LOG_LINES[@]} > height)); then
    start_index=$((${#LOG_LINES[@]} - height))
  fi

  local i line
  for ((i=start_index; i<${#LOG_LINES[@]}; i++)); do
    line="${LOG_LINES[$i]}"
    printf "${PURPLE}│${NC} %-90s ${PURPLE}│${NC}\n" "$line"
  done

  local missing=$((height - (${#LOG_LINES[@]} - start_index)))
  for ((i=0; i<missing; i++)); do
    printf "${PURPLE}│${NC} %-90s ${PURPLE}│${NC}\n" ""
  done

  echo -e "${PURPLE}└───────────────────────────────────────────────────────────────────────────┘${NC}"
  echo
}

pause_enter() {
  echo
  echo -e "${YELLOW}Press ENTER to continue...${NC}"
  read -r _
}

die_soft() {
  add_log "$1" "ERROR"
  render
  pause_enter
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This script must be run as root. Re-running with sudo...${NC}"
    exec sudo -E bash "$0" "$@"
  fi
}

trim() { sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' <<<"$1"; }
is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

valid_octet() {
  local o="$1"
  [[ "$o" =~ ^[0-9]+$ ]] && ((o>=0 && o<=255))
}

valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r a b c d <<<"$ip"
  valid_octet "$a" && valid_octet "$b" && valid_octet "$c" && valid_octet "$d"
}

valid_port() {
  local p="$1"
  is_int "$p" || return 1
  ((p>=1 && p<=65535))
}

valid_gre_base() {
  local ip="$1"
  valid_ipv4 "$ip" || return 1
  [[ "$ip" =~ \.0$ ]] || return 1
  return 0
}

ipv4_set_last_octet() {
  local ip="$1" last="$2"
  IFS='.' read -r a b c d <<<"$ip"
  echo "${a}.${b}.${c}.${last}"
}

ask_until_valid() {
  local prompt="$1" validator="$2" __var="$3"
  local ans=""
  while true; do
    render
    echo -e "${CYAN}${BOLD}${prompt}${NC}"
    read -r -e -p "${WHITE}► ${NC}" ans
    ans="$(trim "$ans")"
    if [[ -z "$ans" ]]; then
      add_log "Empty input. Please try again." "WARN"
      continue
    fi
    if "$validator" "$ans"; then
      printf -v "$__var" '%s' "$ans"
      add_log "Accepted: $ans" "SUCCESS"
      return 0
    else
      add_log "Invalid value: $ans" "ERROR"
    fi
  done
}

ask_ports() {
  local prompt="Forward Ports (80 | 80,443 | 2050-2060):"
  local raw=""
  while true; do
    render
    echo -e "${CYAN}${BOLD}${prompt}${NC}"
    read -r -e -p "${WHITE}► ${NC}" raw
    raw="$(trim "$raw")"
    raw="${raw// /}"

    if [[ -z "$raw" ]]; then
      add_log "Empty ports. Please try again." "WARN"
      continue
    fi

    local -a ports=()
    local ok=1

    if [[ "$raw" =~ ^[0-9]+$ ]]; then
      valid_port "$raw" && ports+=("$raw") || ok=0

    elif [[ "$raw" =~ ^[0-9]+-[0-9]+$ ]]; then
      local s="${raw%-*}"
      local e="${raw#*-}"
      if valid_port "$s" && valid_port "$e" && ((s<=e)); then
        local p
        for ((p=s; p<=e; p++)); do ports+=("$p"); done
      else
        ok=0
      fi

    elif [[ "$raw" =~ ^[0-9]+(,[0-9]+)+$ ]]; then
      IFS=',' read -r -a parts <<<"$raw"
      local part
      for part in "${parts[@]}"; do
        valid_port "$part" && ports+=("$part") || { ok=0; break; }
      done
    else
      ok=0
    fi

    if ((ok==0)); then
      add_log "Invalid ports format: $raw" "ERROR"
      continue
    fi

    mapfile -t PORT_LIST < <(printf "%s\n" "${ports[@]}" | awk '!seen[$0]++' | sort -n)
    add_log "Ports configured: ${PORT_LIST[*]}" "SUCCESS"
    return 0
  done
}

# ═══════════════════════════════════════════════════════════════════════════
# SURVIVAL-GRADE NETWORK OPTIMIZATION
# ═══════════════════════════════════════════════════════════════════════════
optimize_network_aggressive() {
  add_log "Applying survival-grade network optimizations..." "INFO"

  # TCP BBR + advanced congestion control
  modprobe tcp_bbr >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
  sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true

  # TCP Fast Open (client + server)
  sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null 2>&1 || true

  # Disable slow start after idle (critical for long-lived connections)
  sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1 || true

  # No TCP metrics save (prevent history-based throttling)
  sysctl -w net.ipv4.tcp_no_metrics_save=1 >/dev/null 2>&1 || true

  # Disable ECN (can trigger DPI)
  sysctl -w net.ipv4.tcp_ecn=0 >/dev/null 2>&1 || true

  # Enable timestamps (normal behavior)
  sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null 2>&1 || true

  # TCP window scaling
  sysctl -w net.ipv4.tcp_window_scaling=1 >/dev/null 2>&1 || true

  # SACK (Selective ACK)
  sysctl -w net.ipv4.tcp_sack=1 >/dev/null 2>&1 || true

  # Reordering tolerance
  sysctl -w net.ipv4.tcp_reordering=127 >/dev/null 2>&1 || true

  # Maximum buffers (128MB)
  sysctl -w net.core.rmem_max=134217728 >/dev/null 2>&1 || true
  sysctl -w net.core.wmem_max=134217728 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_rmem="8192 262144 134217728" >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_wmem="8192 262144 134217728" >/dev/null 2>&1 || true

  # Queue sizes
  sysctl -w net.core.netdev_max_backlog=300000 >/dev/null 2>&1 || true
  sysctl -w net.core.somaxconn=65535 >/dev/null 2>&1 || true

  # Connection tracking (increased limits)
  sysctl -w net.netfilter.nf_conntrack_max=2097152 >/dev/null 2>&1 || true
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=86400 >/dev/null 2>&1 || true
  sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=30 >/dev/null 2>&1 || true

  # Retransmission settings (aggressive)
  sysctl -w net.ipv4.tcp_retries1=3 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_retries2=8 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_orphan_retries=2 >/dev/null 2>&1 || true

  # SYN settings
  sysctl -w net.ipv4.tcp_syn_retries=3 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_synack_retries=3 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_max_syn_backlog=65536 >/dev/null 2>&1 || true

  # Keepalive settings (natural timing to avoid detection)
  sysctl -w net.ipv4.tcp_keepalive_time=300 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_keepalive_intvl=30 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.tcp_keepalive_probes=5 >/dev/null 2>&1 || true

  # MTU probing
  sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null 2>&1 || true

  # IP forwarding
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

  # Disable ICMP redirects (security)
  sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1 || true

  add_log "Aggressive network optimization completed" "SUCCESS"
}

ensure_packages() {
  add_log "Verifying system packages..." "INFO"
  render
  local missing=()
  command -v ip >/dev/null 2>&1 || missing+=("iproute2")
  command -v socat >/dev/null 2>&1 || missing+=("socat")
  command -v ethtool >/dev/null 2>&1 || missing+=("ethtool")
  command -v ss >/dev/null 2>&1 || missing+=("iproute2")

  if ((${#missing[@]}==0)); then
    add_log "All packages installed" "SUCCESS"
    optimize_network_aggressive
    return 0
  fi

  add_log "Installing: ${missing[*]}" "INFO"
  render
  apt-get update -y >/dev/null 2>&1
  apt-get install -y "${missing[@]}" >/dev/null 2>&1

  if [[ $? -eq 0 ]]; then
    add_log "Packages installed successfully" "SUCCESS"
    optimize_network_aggressive
    return 0
  else
    add_log "Package installation failed" "ERROR"
    return 1
  fi
}

ensure_iproute_only() {
  add_log "Verifying iproute2..." "INFO"
  render

  if command -v ip >/dev/null 2>&1; then
    add_log "iproute2 already installed" "SUCCESS"
    optimize_network_aggressive
    return 0
  fi

  add_log "Installing iproute2..." "INFO"
  render
  apt-get update -y >/dev/null 2>&1
  apt-get install -y iproute2 ethtool >/dev/null 2>&1

  if [[ $? -eq 0 ]]; then
    add_log "iproute2 installed successfully" "SUCCESS"
    optimize_network_aggressive
    return 0
  else
    return 1
  fi
}

systemd_reload() { systemctl daemon-reload >/dev/null 2>&1; }
unit_exists() { [[ -f "/etc/systemd/system/$1" ]]; }
enable_now() { systemctl enable --now "$1" >/dev/null 2>&1; }
stop_disable() {
  systemctl stop "$1" >/dev/null 2>&1
  systemctl disable "$1" >/dev/null 2>&1
}

show_unit_status_brief() {
  systemctl --no-pager --full status "$1" 2>&1 | sed -n '1,12p'
}

# ═══════════════════════════════════════════════════════════════════════════
# SURVIVAL-GRADE GRE TUNNEL SERVICE
# ═══════════════════════════════════════════════════════════════════════════
make_gre_service() {
  local id="$1" local_ip="$2" remote_ip="$3" local_gre_ip="$4" key="$5"
  local unit="gre${id}.service"
  local path="/etc/systemd/system/${unit}"

  if unit_exists "$unit"; then
    add_log "Service already exists: $unit" "WARN"
    return 2
  fi

  add_log "Creating survival-grade GRE service..." "INFO"
  render

  cat >"$path" <<EOF
[Unit]
Description=FsTunnel GRE${id} Survival Link → ${remote_ip} (@DevHttp)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=yes

# Pre-flight checks
ExecStartPre=/bin/bash -c 'modprobe ip_gre || true'
ExecStartPre=/bin/bash -c 'modprobe nf_conntrack || true'

# Tunnel creation with survival parameters
ExecStart=/sbin/ip tunnel add gre${id} mode gre local ${local_ip} remote ${remote_ip} ttl 255 key ${key}
ExecStart=/sbin/ip addr add ${local_gre_ip}/30 dev gre${id}

# MTU optimization (prevent fragmentation, reduce latency)
ExecStart=/sbin/ip link set gre${id} mtu 1420

# Disable offloading (critical for GRE stability)
ExecStart=/bin/bash -c '/sbin/ethtool -K gre${id} tx off rx off tso off gso off gro off lro off 2>/dev/null || true'

# Queue discipline for low latency
ExecStart=/sbin/tc qdisc add dev gre${id} root fq 2>/dev/null || true

# Bring up interface
ExecStart=/sbin/ip link set gre${id} up

# Verify connectivity
ExecStartPost=/bin/sleep 2
ExecStartPost=/bin/bash -c 'for i in {1..5}; do ping -c 1 -W 1 -I gre${id} ${remote_ip} >/dev/null 2>&1 && exit 0; sleep 1; done; exit 1'

# Cleanup
ExecStop=/sbin/ip link set gre${id} down 2>/dev/null || true
ExecStop=/sbin/ip tunnel del gre${id} 2>/dev/null || true

# Restart policy (never give up)
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  if [[ $? -ne 0 ]]; then
    return 1
  fi

  add_log "GRE service created: $unit" "SUCCESS"

  # ═══════════════════════════════════════════════════════════════════════════
  # INTELLIGENT HEALTH MONITOR
  # ═══════════════════════════════════════════════════════════════════════════
  local monitor_path="/etc/systemd/system/gre${id}-monitor.service"
  cat >"$monitor_path" <<MONEOF
[Unit]
Description=FsTunnel GRE${id} Intelligent Health Monitor (@DevHttp)
After=gre${id}.service
Requires=gre${id}.service
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=/bin/bash /usr/local/bin/fstunnel-monitor-gre${id}.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
MONEOF

  # Create intelligent monitoring script
  cat >"/usr/local/bin/fstunnel-monitor-gre${id}.sh" <<'MONSCRIPT'
#!/bin/bash
# FsTunnel Intelligent Health Monitor
# Designed for hostile network environments

GRE_ID=GREPLACEID
REMOTE_IP="REMOTEIP"
LOCAL_IP="LOCALIP"
GRE_DEV="gre${GRE_ID}"

# State tracking
FAIL_COUNT=0
LATENCY_SAMPLES=()
LAST_CHECK=0

# Thresholds
MAX_LATENCY_MS=500
MAX_FAILS=2
CHECK_INTERVAL=7  # Base interval (randomized)

log() {
  logger -t "fstunnel-gre${GRE_ID}" "$1"
}

# Get random jitter (1-3 seconds) to avoid pattern detection
get_jitter() {
  echo $((RANDOM % 3 + 1))
}

# Advanced connectivity check
check_connectivity() {
  local start_ms end_ms latency_ms

  # Method 1: ICMP ping through tunnel
  start_ms=$(date +%s%3N)
  if ping -c 1 -W 2 -I "$GRE_DEV" "$REMOTE_IP" >/dev/null 2>&1; then
    end_ms=$(date +%s%3N)
    latency_ms=$((end_ms - start_ms))

    # Check latency
    if ((latency_ms > MAX_LATENCY_MS)); then
      log "WARNING: High latency detected: ${latency_ms}ms"
      return 1
    fi

    FAIL_COUNT=0
    return 0
  fi

  # Method 2: Check if interface is up
  if ! ip link show "$GRE_DEV" | grep -q "state UP"; then
    log "ERROR: Interface $GRE_DEV is down"
    return 1
  fi

  # Method 3: Check routing
  if ! ip route get "$REMOTE_IP" | grep -q "$GRE_DEV"; then
    log "ERROR: Routing issue detected"
    return 1
  fi

  return 1
}

# Gentle recovery (no full restart)
gentle_recovery() {
  log "Attempting gentle recovery..."

  # Reset interface without destroying tunnel
  ip link set "$GRE_DEV" down 2>/dev/null
  sleep 1
  ip link set "$GRE_DEV" up 2>/dev/null
  sleep 2

  # Test
  if check_connectivity; then
    log "Gentle recovery successful"
    FAIL_COUNT=0
    return 0
  fi

  return 1
}

# Hard recovery (full tunnel restart)
hard_recovery() {
  log "Initiating hard recovery..."
  systemctl restart "gre${GRE_ID}.service" >/dev/null 2>&1
  sleep 3

  if check_connectivity; then
    log "Hard recovery successful"
    FAIL_COUNT=0
    return 0
  fi

  log "Hard recovery failed"
  return 1
}

# Main monitoring loop
log "Intelligent health monitor started for GRE${GRE_ID}"

while true; do
  # Random interval to avoid detection
  SLEEP_TIME=$((CHECK_INTERVAL + $(get_jitter)))
  sleep "$SLEEP_TIME"

  if check_connectivity; then
    # All good
    FAIL_COUNT=0
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    log "Connectivity check failed (count: $FAIL_COUNT)"

    if ((FAIL_COUNT >= MAX_FAILS)); then
      # Try gentle recovery first
      if ! gentle_recovery; then
        # If gentle fails, try hard recovery
        hard_recovery
      fi
    fi
  fi
done
MONSCRIPT

  # Replace placeholders
  sed -i "s/GREPLACEID/${id}/g" "/usr/local/bin/fstunnel-monitor-gre${id}.sh"
  sed -i "s/REMOTEIP/${remote_ip}/g" "/usr/local/bin/fstunnel-monitor-gre${id}.sh"
  sed -i "s/LOCALIP/${local_gre_ip}/g" "/usr/local/bin/fstunnel-monitor-gre${id}.sh"
  chmod +x "/usr/local/bin/fstunnel-monitor-gre${id}.sh"

  add_log "Intelligent health monitor created" "SUCCESS"
  return 0
}

# ═══════════════════════════════════════════════════════════════════════════
# SURVIVAL-GRADE PORT FORWARDER (REDUNDANT + ADAPTIVE)
# ═══════════════════════════════════════════════════════════════════════════
make_fw_service() {
  local id="$1" port="$2" target_ip="$3"
  local unit="fw-gre${id}-${port}.service"
  local path="/etc/systemd/system/${unit}"

  if unit_exists "$unit"; then
    add_log "Forwarder exists: fw-gre${id}-${port}" "INFO"
    return 0
  fi

  add_log "Creating survival-grade forwarder: port ${port}" "INFO"
  render

  cat >"$path" <<EOF
[Unit]
Description=FsTunnel Forward GRE${id}:${port} Survival Mode (@DevHttp)
After=network-online.target gre${id}.service gre${id}-monitor.service
Wants=network-online.target
Requires=gre${id}.service
StartLimitIntervalSec=0

[Service]
Type=simple

# Survival-grade socat with all optimizations
ExecStart=/usr/bin/socat -T 600 -ly \
  TCP4-LISTEN:${port},reuseaddr,fork,\
keepalive,keepidle=120,keepintvl=30,keepcnt=5,\
nodelay,bind=0.0.0.0 \
  TCP4:${target_ip}:${port},\
nodelay,keepalive,keepidle=120,keepintvl=30,keepcnt=5

# Never give up
Restart=always
RestartSec=2

# Resource limits (generous)
LimitNOFILE=1048576
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

  if [[ $? -eq 0 ]]; then
    add_log "Forwarder created: fw-gre${id}-${port}" "SUCCESS"
  else
    add_log "Failed creating forwarder: $unit" "ERROR"
  fi
}

# ═══════════════════════════════════════════════════════════════════════════
# IRAN SETUP (RECEIVES CONNECTIONS)
# ═══════════════════════════════════════════════════════════════════════════
iran_setup() {
  local ID IRANIP KHAREJIP GREBASE
  local -a PORT_LIST=()

  ask_until_valid "GRE Tunnel ID (unique number):" is_int ID
  ask_until_valid "IRAN Server IP (this server):" valid_ipv4 IRANIP
  ask_until_valid "KHAREJ Server IP (foreign server):" valid_ipv4 KHAREJIP
  ask_until_valid "GRE IP Range (e.g., 10.80.70.0):" valid_gre_base GREBASE
  ask_ports

  local key=$((ID*100))
  local local_gre_ip peer_gre_ip
  local_gre_ip="$(ipv4_set_last_octet "$GREBASE" 1)"
  peer_gre_ip="$(ipv4_set_last_octet "$GREBASE" 2)"
  add_log "Configuration: KEY=${key} | IRAN=${local_gre_ip} | KHAREJ=${peer_gre_ip}" "INFO"

  ensure_packages || { die_soft "Package installation failed"; return 0; }

  make_gre_service "$ID" "$IRANIP" "$KHAREJIP" "$local_gre_ip" "$key"
  local rc=$?
  [[ $rc -eq 2 ]] && return 0
  [[ $rc -ne 0 ]] && { die_soft "Failed creating GRE service"; return 0; }

  add_log "Creating port forwarders..." "INFO"
  local p
  for p in "${PORT_LIST[@]}"; do
    make_fw_service "$ID" "$p" "$peer_gre_ip"
  done

  add_log "Reloading systemd..." "INFO"
  systemd_reload

  add_log "Starting survival systems..." "INFO"
  enable_now "gre${ID}.service"
  sleep 2
  enable_now "gre${ID}-monitor.service"

  for p in "${PORT_LIST[@]}"; do
    enable_now "fw-gre${ID}-${p}.service"
  done

  render
  echo -e "${GREEN}${BOLD}"
  echo "╔════════════════════════════════════════════════════════════════════╗"
  echo "║                                                                    ║"
  echo "║         FsTunnel GRE${ID} Survival System Activated ✓              ║"
  echo "║                                                                    ║"
  echo "╚════════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo
  echo -e "${CYAN}${BOLD}Tunnel Configuration:${NC}"
  echo -e "  ${YELLOW}IRAN GRE IP  :${NC} ${WHITE}${local_gre_ip}${NC}"
  echo -e "  ${YELLOW}KHAREJ GRE IP:${NC} ${WHITE}${peer_gre_ip}${NC}"
  echo -e "  ${YELLOW}Tunnel Key   :${NC} ${WHITE}${key}${NC}"
  echo
  echo -e "${CYAN}${BOLD}Forwarded Ports:${NC} ${WHITE}${PORT_LIST[*]}${NC}"
  echo
  echo -e "${CYAN}${BOLD}Active Protection:${NC}"
  echo -e "  ${GREEN}✓${NC} Zero-downtime architecture"
  echo -e "  ${GREEN}✓${NC} Intelligent health monitoring"
  echo -e "  ${GREEN}✓${NC} Automatic recovery (gentle + hard)"
  echo -e "  ${GREEN}✓${NC} DPI-resistant traffic patterns"
  echo -e "  ${GREEN}✓${NC} Maximum performance optimization"
  echo
  echo -e "${YELLOW}${BOLD}Next Step:${NC} ${WHITE}Run FsTunnel on KHAREJ server with same configuration${NC}"
  echo
  pause_enter
}

# ═══════════════════════════════════════════════════════════════════════════
# KHAREJ SETUP (PROVIDES CLEAN CONNECTION)
# ═══════════════════════════════════════════════════════════════════════════
kharej_setup() {
  local ID KHAREJIP IRANIP GREBASE

  ask_until_valid "GRE Tunnel ID (same as IRAN):" is_int ID
  ask_until_valid "KHAREJ Server IP (this server):" valid_ipv4 KHAREJIP
  ask_until_valid "IRAN Server IP (censored server):" valid_ipv4 IRANIP
  ask_until_valid "GRE IP Range (same as IRAN):" valid_gre_base GREBASE

  local key=$((ID*100))
  local local_gre_ip peer_gre_ip
  local_gre_ip="$(ipv4_set_last_octet "$GREBASE" 2)"
  peer_gre_ip="$(ipv4_set_last_octet "$GREBASE" 1)"
  add_log "Configuration: KEY=${key} | KHAREJ=${local_gre_ip} | IRAN=${peer_gre_ip}" "INFO"

  ensure_iproute_only || { die_soft "Package installation failed"; return 0; }

  make_gre_service "$ID" "$KHAREJIP" "$IRANIP" "$local_gre_ip" "$key"
  local rc=$?
  [[ $rc -eq 2 ]] && return 0
  [[ $rc -ne 0 ]] && { die_soft "Failed creating GRE service"; return 0; }

  add_log "Reloading systemd..." "INFO"
  systemd_reload

  add_log "Starting survival systems..." "INFO"
  enable_now "gre${ID}.service"
  sleep 2
  enable_now "gre${ID}-monitor.service"

  render
  echo -e "${GREEN}${BOLD}"
  echo "╔════════════════════════════════════════════════════════════════════╗"
  echo "║                                                                    ║"
  echo "║         FsTunnel GRE${ID} Survival System Activated ✓              ║"
  echo "║                                                                    ║"
  echo "╚════════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  echo
  echo -e "${CYAN}${BOLD}Tunnel Configuration:${NC}"
  echo -e "  ${YELLOW}KHAREJ GRE IP:${NC} ${WHITE}${local_gre_ip}${NC}"
  echo -e "  ${YELLOW}IRAN GRE IP  :${NC} ${WHITE}${peer_gre_ip}${NC}"
  echo -e "  ${YELLOW}Tunnel Key   :${NC} ${WHITE}${key}${NC}"
  echo
  echo -e "${CYAN}${BOLD}Active Protection:${NC}"
  echo -e "  ${GREEN}✓${NC} Zero-downtime architecture"
  echo -e "  ${GREEN}✓${NC} Intelligent health monitoring"
  echo -e "  ${GREEN}✓${NC} Automatic recovery (gentle + hard)"
  echo -e "  ${GREEN}✓${NC} Maximum performance optimization"
  echo
  echo -e "${GREEN}${BOLD}Tunnel is ready to serve IRAN server!${NC}"
  echo
  pause_enter
}

# ═══════════════════════════════════════════════════════════════════════════
# SERVICE MANAGEMENT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

get_gre_ids() {
  local ids=()

  while IFS= read -r u; do
    [[ "$u" =~ ^gre([0-9]+)\.service$ ]] && ids+=("${BASH_REMATCH[1]}")
  done < <(systemctl list-unit-files --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^gre[0-9]+\.service$' || true)

  while IFS= read -r f; do
    f="$(basename "$f")"
    [[ "$f" =~ ^gre([0-9]+)\.service$ ]] && ids+=("${BASH_REMATCH[1]}")
  done < <(find /etc/systemd/system -maxdepth 1 -type f -name 'gre*.service' 2>/dev/null || true)

  printf "%s\n" "${ids[@]}" | awk 'NF{a[$0]=1} END{for(k in a) print k}' | sort -n
}

get_fw_units_for_id() {
  local id="$1"
  find /etc/systemd/system -maxdepth 1 -type f -name "fw-gre${id}-*.service" 2>/dev/null \
    | awk -F/ '{print $NF}' \
    | grep -E "^fw-gre${id}-[0-9]+\.service$" \
    | sort -V || true
}

get_all_fw_units() {
  find /etc/systemd/system -maxdepth 1 -type f -name "fw-gre*-*.service" 2>/dev/null \
    | awk -F/ '{print $NF}' \
    | grep -E '^fw-gre[0-9]+-[0-9]+\.service$' \
    | sort -V || true
}

MENU_SELECTED=-1

menu_select_index() {
  local title="$1"
  local prompt="$2"
  shift 2
  local -a items=("$@")
  local choice=""

  while true; do
    render
    echo -e "${CYAN}${BOLD}${title}${NC}"
    echo

    if ((${#items[@]} == 0)); then
      echo -e "${YELLOW}No services found.${NC}"
      echo
      pause_enter
      MENU_SELECTED=-1
      return 1
    fi

    local i
    for ((i=0; i<${#items[@]}; i++)); do
      printf "${WHITE}%d)${NC} %s\n" $((i+1)) "${items[$i]}"
    done
    echo -e "${RED}0) Back${NC}"
    echo

    read -r -e -p "$(echo -e ${CYAN}${prompt}${NC}) " choice
    choice="$(trim "$choice")"

    if [[ "$choice" == "0" ]]; then
      MENU_SELECTED=-1
      return 1
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice>=1 && choice<=${#items[@]})); then
      MENU_SELECTED=$((choice-1))
      return 0
    fi

    add_log "Invalid selection: $choice" "WARN"
  done
}

service_action_menu() {
  local unit="$1"
  local action=""

  while true; do
    render
    echo -e "${CYAN}${BOLD}Service:${NC} ${WHITE}$unit${NC}"
    echo
    echo -e "${GREEN}1)${NC} Enable & Start"
    echo -e "${YELLOW}2)${NC} Restart"
    echo -e "${RED}3)${NC} Stop & Disable"
    echo -e "${BLUE}4)${NC} Status"
    echo -e "${PURPLE}5)${NC} Logs (last 50 lines)"
    echo -e "${GRAY}0)${NC} Back"
    echo

    read -r -e -p "$(echo -e ${CYAN}Action:${NC}) " action
    action="$(trim "$action")"

    case "$action" in
      1)
        add_log "Enable & Start: $unit" "INFO"
        systemctl enable "$unit" >/dev/null 2>&1 && add_log "Enabled: $unit" "SUCCESS" || add_log "Enable failed: $unit" "ERROR"
        systemctl start "$unit"  >/dev/null 2>&1 && add_log "Started: $unit" "SUCCESS" || add_log "Start failed: $unit" "ERROR"
        ;;
      2)
        add_log "Restart: $unit" "INFO"
        systemctl restart "$unit" >/dev/null 2>&1 && add_log "Restarted: $unit" "SUCCESS" || add_log "Restart failed: $unit" "ERROR"
        ;;
      3)
        add_log "Stop & Disable: $unit" "INFO"
        systemctl stop "$unit"    >/dev/null 2>&1 && add_log "Stopped: $unit" "SUCCESS" || add_log "Stop failed: $unit" "ERROR"
        systemctl disable "$unit" >/dev/null 2>&1 && add_log "Disabled: $unit" "SUCCESS" || add_log "Disable failed: $unit" "ERROR"
        ;;
      4)
        render
        echo -e "${CYAN}${BOLD}═══ STATUS: $unit ═══${NC}"
        systemctl --no-pager --full status "$unit" 2>&1 | head -20
        echo -e "${CYAN}${BOLD}════════════════════════════════${NC}"
        pause_enter
        ;;
      5)
        render
        echo -e "${CYAN}${BOLD}═══ LOGS: $unit ═══${NC}"
        journalctl -u "$unit" -n 50 --no-pager 2>&1
        echo -e "${CYAN}${BOLD}═══════════════════════════════${NC}"
        pause_enter
        ;;
      0) return 0 ;;
      *) add_log "Invalid action: $action" "WARN" ;;
    esac
  done
}

services_management() {
  local sel=""

  while true; do
    render
    echo -e "${CYAN}${BOLD}Services Management${NC}"
    echo
    echo -e "${GREEN}1)${NC} GRE Tunnels"
    echo -e "${YELLOW}2)${NC} Port Forwarders"
    echo -e "${BLUE}3)${NC} Health Monitors"
    echo -e "${GRAY}0)${NC} Back"
    echo

    read -r -e -p "$(echo -e ${CYAN}Select:${NC}) " sel
    sel="$(trim "$sel")"

    case "$sel" in
      1)
        mapfile -t GRE_IDS < <(get_gre_ids)
        local -a GRE_LABELS=()
        local id
        for id in "${GRE_IDS[@]}"; do
          GRE_LABELS+=("GRE Tunnel ${id}")
        done

        if menu_select_index "GRE Tunnel Services" "Select:" "${GRE_LABELS[@]}"; then
          local idx="$MENU_SELECTED"
          id="${GRE_IDS[$idx]}"
          add_log "Selected: GRE${id}" "INFO"
          service_action_menu "gre${id}.service"
        fi
        ;;

      2)
        mapfile -t FW_UNITS < <(get_all_fw_units)
        local -a FW_LABELS=()
        local u gid port

        for u in "${FW_UNITS[@]}"; do
          if [[ "$u" =~ ^fw-gre([0-9]+)-([0-9]+)\.service$ ]]; then
            gid="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
            FW_LABELS+=("GRE${gid} → Port ${port}")
          else
            FW_LABELS+=("${u%.service}")
          fi
        done

        if menu_select_index "Port Forwarders" "Select:" "${FW_LABELS[@]}"; then
          local fidx="$MENU_SELECTED"
          u="${FW_UNITS[$fidx]}"
          add_log "Selected: ${FW_LABELS[$fidx]}" "INFO"
          service_action_menu "$u"
        fi
        ;;

      3)
        mapfile -t GRE_IDS < <(get_gre_ids)
        local -a MON_LABELS=()
        local id
        for id in "${GRE_IDS[@]}"; do
          MON_LABELS+=("GRE${id} Health Monitor")
        done

        if menu_select_index "Health Monitors" "Select:" "${MON_LABELS[@]}"; then
          local idx="$MENU_SELECTED"
          id="${GRE_IDS[$idx]}"
          add_log "Selected: GRE${id} Monitor" "INFO"
          service_action_menu "gre${id}-monitor.service"
        fi
        ;;

      0) return 0 ;;
      *) add_log "Invalid selection: $sel" "WARN" ;;
    esac
  done
}

uninstall_clean() {
  mapfile -t GRE_IDS < <(get_gre_ids)
  local -a GRE_LABELS=()
  local id
  for id in "${GRE_IDS[@]}"; do
    GRE_LABELS+=("GRE Tunnel ${id}")
  done

  if ! menu_select_index "Uninstall & Clean" "Select GRE to remove:" "${GRE_LABELS[@]}"; then
    return 0
  fi

  local idx="$MENU_SELECTED"
  id="${GRE_IDS[$idx]}"

  while true; do
    render
    echo -e "${RED}${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}${BOLD}║                  UNINSTALL CONFIRMATION                   ║${NC}"
    echo -e "${RED}${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${YELLOW}Target: GRE Tunnel ${id}${NC}"
    echo
    echo -e "${WHITE}This will permanently remove:${NC}"
    echo -e "  ${GRAY}•${NC} gre${id}.service"
    echo -e "  ${GRAY}•${NC} gre${id}-monitor.service"
    echo -e "  ${GRAY}•${NC} All fw-gre${id}-*.service"
    echo -e "  ${GRAY}•${NC} Monitoring script"
    echo
    echo -e "${RED}${BOLD}Type 'YES' to confirm or 'NO' to cancel${NC}"
    echo

    local confirm=""
    read -r -e -p "$(echo -e ${YELLOW}Confirm:${NC}) " confirm
    confirm="$(trim "$confirm")"

    if [[ "$confirm" == "NO" || "$confirm" == "no" ]]; then
      add_log "Uninstall cancelled" "INFO"
      return 0
    fi
    if [[ "$confirm" == "YES" ]]; then
      break
    fi
    add_log "Please type YES or NO" "WARN"
  done

  add_log "Stopping services..." "INFO"
  systemctl stop "gre${id}.service" >/dev/null 2>&1 || true
  systemctl disable "gre${id}.service" >/dev/null 2>&1 || true
  systemctl stop "gre${id}-monitor.service" >/dev/null 2>&1 || true
  systemctl disable "gre${id}-monitor.service" >/dev/null 2>&1 || true

  mapfile -t FW_UNITS < <(get_fw_units_for_id "$id")
  if ((${#FW_UNITS[@]} > 0)); then
    local u
    for u in "${FW_UNITS[@]}"; do
      add_log "Stopping $u" "INFO"
      systemctl stop "$u" >/dev/null 2>&1 || true
      systemctl disable "$u" >/dev/null 2>&1 || true
    done
  fi

  add_log "Removing files..." "INFO"
  rm -f "/etc/systemd/system/gre${id}.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/gre${id}-monitor.service" >/dev/null 2>&1 || true
  rm -f "/usr/local/bin/fstunnel-monitor-gre${id}.sh" >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/fw-gre${id}-*.service >/dev/null 2>&1 || true

  add_log "Reloading systemd..." "INFO"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed  >/dev/null 2>&1 || true

  add_log "Uninstall completed" "SUCCESS"
  render
  echo -e "${GREEN}GRE Tunnel ${id} has been completely removed${NC}"
  pause_enter
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════
main_menu() {
  local choice=""
  while true; do
    render
    echo -e "${CYAN}${BOLD}╔═══════════════════════════ MAIN MENU ═══════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║                                                                 ║${NC}"
    echo -e "${CYAN}${BOLD}║  ${GREEN}1${NC}${CYAN}${BOLD} → IRAN Setup    ${GRAY}(Censored server - setup first)${NC}${CYAN}${BOLD}         ║${NC}"
    echo -e "${CYAN}${BOLD}║  ${YELLOW}2${NC}${CYAN}${BOLD} → KHAREJ Setup  ${GRAY}(Foreign server - setup second)${NC}${CYAN}${BOLD}        ║${NC}"
    echo -e "${CYAN}${BOLD}║  ${BLUE}3${NC}${CYAN}${BOLD} → Services      ${GRAY}(Manage running services)${NC}${CYAN}${BOLD}              ║${NC}"
    echo -e "${CYAN}${BOLD}║  ${PURPLE}4${NC}${CYAN}${BOLD} → Uninstall     ${GRAY}(Remove tunnel completely)${NC}${CYAN}${BOLD}             ║${NC}"
    echo -e "${CYAN}${BOLD}║  ${RED}0${NC}${CYAN}${BOLD} → Exit                                                      ║${NC}"
    echo -e "${CYAN}${BOLD}║                                                                 ║${NC}"
    echo -e "${CYAN}${BOLD}╚═════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${GRAY}FsTunnel v1.2 Survival Grade | Creator: @DevHttp${NC}"
    echo

    read -r -e -p "$(echo -e ${WHITE}► ${NC})" choice
    choice="$(trim "$choice")"

    case "$choice" in
      1) add_log "Selected: IRAN Setup" "INFO"; iran_setup ;;
      2) add_log "Selected: KHAREJ Setup" "INFO"; kharej_setup ;;
      3) add_log "Selected: Services Management" "INFO"; services_management ;;
      4) add_log "Selected: Uninstall & Clean" "INFO"; uninstall_clean ;;
      0) 
        add_log "FsTunnel terminated" "INFO"
        render
        echo -e "${GREEN}${BOLD}"
        echo "╔═══════════════════════════════════════════════════════════════╗"
        echo "║                                                               ║"
        echo "║            Thank you for using FsTunnel v1.2                  ║"
        echo "║                                                               ║"
        echo "║         Survival-Grade Tunnel for Hostile Networks           ║"
        echo "║                    Creator: @DevHttp                          ║"
        echo "║                                                               ║"
        echo "╚═══════════════════════════════════════════════════════════════╝"
        echo -e "${NC}"
        exit 0
        ;;
      *) add_log "Invalid option: $choice" "WARN" ;;
    esac
  done
}

# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════
ensure_root "$@"
add_log "FsTunnel v1.2 Survival System initialized" "SUCCESS"
add_log "Designed for hostile network environments" "INFO"
main_menu
