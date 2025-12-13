#!/usr/bin/env bash
# =============================================================================
# SCRIPT NAME  : ubuntu_configure_network_r1.sh
# VERSION      : 1.1.3
# AUTHOR: Jason Rowsell (jason@jasonrowsell.net)
# CREATED: 12-13-2025
# Tested on Ubuntu 24.04.3 LTS (Noble/Desktop & Server)
# License: MIT License

# Overview     : Safe, modular network configuration script for Ubuntu 24.04.3+
# Feature list : Interactive and CLI IPv4/IPv6 setup, DNS, rollback, logging, connectivity tests.
# =============================================================================
#
# DESCRIPTION:
#   Configures network settings on Ubuntu 24.04.3 LTS systems using Netplan.
#   Supports both static and DHCP configurations for IPv4 and IPv6, hostname
#   setting, DNS resolver configuration, and includes safety features like 
#   config backups, YAML validation, and "netplan try"
#   with timeout to prevent lockout on remote SSH sessions.
#   It also logs all actions to /var/log/network_config.log for auditing.
#         
#
# FEATURES:
#   - Configures IPv4 and IPv6 (static/DHCP) on selected NIC
#   - Sets hostname and updates /etc/hosts
#   - Configures DNS resolvers
#   - Backs up existing network configs before applying changes
#   - Validates Netplan YAML syntax before applying
#   - "netplan try" with timeout to prevent lockout on SSH sessions
#   - Tests connectivity (ping gateway, external IP, DNS resolution)  
#
# REQUIREMENTS:
# Important - This script must be run with sudo
#
#   - Must be run with root privileges (use sudo)
#   - Interactive terminal session
# 
#
# Example:
#
#   Make script executable:
#     chmod +x ubuntu_configure_network_r1.sh
#
#   Run script:
#     sudo ./ubuntu_configure_network_r1.sh
#
# =============================================================================
# REVISION HISTORY
# -----------------------------------------------------------------------------
# DATE         | VERSION | AUTHOR       | CHANGE
# -------------|---------|--------------|--------------------------------------
# 12-13-2025   | 1.1.3   |Jason Rowsell | Initial release with all features.
# =============================================================================
#
#
# License:        MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ---------------------------------------------------------------------------
#
# Begin script

set -euo pipefail
IFS=$'\n\t'

CONFIG_LOG="/var/log/network_config.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BACKUP_DIR="/var/backups/network_config_$TIMESTAMP"
NETPLAN_DIR="/etc/netplan"
NETPLAN_FILE="$NETPLAN_DIR/99-custom-config.yaml"

NETPLAN_TIMEOUT=30
PING_TIMEOUT=2

INTERFACE=""
HOSTNAME=""
DNS_SUFFIX=""

IPV4_MODE=""
IPV4_ADDRESS=""
IPV4_NETMASK=""
IPV4_GATEWAY=""

IPV6_MODE=""
IPV6_ADDRESS=""
IPV6_PREFIX=""
IPV6_GATEWAY=""

DNS_RESOLVERS=()

# -----------------------------------------------------------------------------#
log_action() {
  printf "[%s] [%s] %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$1" "$2" >> "$CONFIG_LOG"
}

error_exit() {
  log_action "ERROR" "$1"
  printf " %s\n" "$1" >&2
  cleanup
  exit 1
}

cleanup() {
  trap - SIGINT SIGTERM
  printf "\nCleanup complete. Exiting.\n" >&2
}

confirm_or_abort() {
  printf "\n%s [y/N]: " "$1"
  read -r ans
  [[ "$ans" =~ ^[Yy]$ ]] || { printf "Aborted.\n"; cleanup; exit 1; }
}

backup_configs() {
  mkdir -p "$BACKUP_DIR"
  cp -a "$NETPLAN_DIR" "$BACKUP_DIR/" || error_exit "Failed to back up Netplan configs"
  cp /etc/hostname /etc/hosts "$BACKUP_DIR/" 2>/dev/null || true
  log_action "BACKUP" "Backed up configs to $BACKUP_DIR"
}

detect_ssh() {
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    printf "\nSSH session detected. Network changes may disconnect you.\n"
    confirm_or_abort "Continue anyway?"
  fi
}

# -----------------------------------------------------------------------------#
select_interface() {
  local nics index=1
  local nic_map=()

  nics=$(ip -o link show | awk -F': ' '{print $2}' | grep -vE '^lo$')

  printf "\nAvailable Network Interfaces:\n"
  while IFS= read -r iface; do
    local state mac speed
    state=$(<"/sys/class/net/$iface/operstate")
    mac=$(<"/sys/class/net/$iface/address")
    speed=$(ethtool "$iface" 2>/dev/null | awk '/Speed:/ {print $2}')
    printf " [%d] %s\tMAC: %s\tStatus: %s\tSpeed: %s\n" \
      "$index" "$iface" "$mac" "$state" "${speed:-unknown}"
    nic_map[$index]="$iface"
    ((index++))
  done <<< "$nics"

  while true; do
    printf "Select an interface by number: "
    read -r choice
    if [[ "${nic_map[$choice]:-}" ]]; then
      INTERFACE="${nic_map[$choice]}"
      break
    fi
  done

  log_action "INTERFACE" "Selected interface: $INTERFACE"
}

# -----------------------------------------------------------------------------#
netmask_to_cidr() {
  local IFS=.
  local total=0

  for o in $1; do
    case "$o" in
      255) ((total+=8)) ;;
      254) ((total+=7)) ;;
      252) ((total+=6)) ;;
      248) ((total+=5)) ;;
      240) ((total+=4)) ;;
      224) ((total+=3)) ;;
      192) ((total+=2)) ;;
      128) ((total+=1)) ;;
      0) ;;
      *) error_exit "Invalid netmask component: $o" ;;
    esac
  done

  [[ "$total" -ge 1 && "$total" -le 32 ]] || error_exit "Invalid netmask: /$total"
  printf "%d" "$total"
}

# -----------------------------------------------------------------------------#
fix_netplan_permissions() {
  find "$NETPLAN_DIR" -type f -name '*.yaml' -exec chmod 600 {} \;
  find "$NETPLAN_DIR" -type f -name '*.yaml' -exec chown root:root {} \;
  log_action "PERMISSIONS" "Normalized permissions on all Netplan YAML files"
}

validate_netplan_yaml() {
  netplan generate 2>/tmp/netplan.err || {
    cat /tmp/netplan.err >&2
    error_exit "Netplan YAML validation failed"
  }
}

generate_netplan_yaml() {
  {
    printf "network:\n  version: 2\n  ethernets:\n    %s:\n" "$INTERFACE"

    case "$IPV4_MODE" in
      dhcp)
        printf "      dhcp4: true\n"
        ;;
      static)
        [[ -n "$IPV4_ADDRESS" && -n "$IPV4_NETMASK" && -n "$IPV4_GATEWAY" ]] \
          || error_exit "Static IPv4 requires address, netmask, gateway"

        local cidr
        cidr=$(netmask_to_cidr "$IPV4_NETMASK")

        printf "      dhcp4: false\n"
        printf "      addresses:\n        - %s/%s\n" "$IPV4_ADDRESS" "$cidr"
        printf "      routes:\n        - to: 0.0.0.0/0\n          via: %s\n" "$IPV4_GATEWAY"
        ;;
      *)
        error_exit "Invalid IPv4 mode: $IPV4_MODE"
        ;;
    esac

    case "$IPV6_MODE" in
      none|"")
        printf "      dhcp6: false\n"
        ;;
      dhcp)
        printf "      dhcp6: true\n"
        ;;
      static)
        [[ -n "$IPV6_ADDRESS" && -n "$IPV6_PREFIX" ]] \
          || error_exit "Static IPv6 requires address and prefix"

        printf "      dhcp6: false\n"
        printf "      addresses:\n        - %s/%s\n" "$IPV6_ADDRESS" "$IPV6_PREFIX"
        [[ -n "$IPV6_GATEWAY" ]] && \
          printf "      routes:\n        - to: ::/0\n          via: %s\n" "$IPV6_GATEWAY"
        ;;
      *)
        error_exit "Invalid IPv6 mode: $IPV6_MODE"
        ;;
    esac

    if [[ "${#DNS_RESOLVERS[@]}" -gt 0 ]]; then
      printf "      nameservers:\n        addresses:\n"
      for d in "${DNS_RESOLVERS[@]}"; do
        printf "          - %s\n" "$d"
      done
      [[ -n "$DNS_SUFFIX" ]] && \
        printf "        search:\n          - %s\n" "$DNS_SUFFIX"
    fi
  } > "$NETPLAN_FILE"

  fix_netplan_permissions
}

preview_netplan_yaml() {
  printf "\n%s\n" "--- Netplan Preview ---"
  cat "$NETPLAN_FILE"
  printf "%s\n" "--- End Preview ---"
}

apply_netplan() {
  validate_netplan_yaml
  netplan try --timeout "$NETPLAN_TIMEOUT"
}

update_hostname() {
  [[ -z "$HOSTNAME" ]] && return
  hostnamectl set-hostname "$HOSTNAME"
  echo "$HOSTNAME" > /etc/hostname

  if [[ "$IPV4_MODE" == "static" ]]; then
    grep -q "$HOSTNAME" /etc/hosts || \
      echo "$IPV4_ADDRESS  $HOSTNAME" >> /etc/hosts
  fi
}

test_connectivity() {
  [[ "$IPV4_MODE" == "static" ]] && ping -c2 -W"$PING_TIMEOUT" "$IPV4_GATEWAY"
  ping -c2 -W"$PING_TIMEOUT" 1.1.1.1
  getent hosts google.com >/dev/null
}

# -----------------------------------------------------------------------------#
main() {
  trap cleanup SIGINT SIGTERM

  detect_ssh
  backup_configs
  select_interface

  printf "Hostname (optional): "
  read -r HOSTNAME

  printf "IPv4 mode (dhcp/static): "
  read -r IPV4_MODE

  if [[ "$IPV4_MODE" == "static" ]]; then
    printf "IPv4 address: "
    read -r IPV4_ADDRESS
    printf "Subnet mask: "
    read -r IPV4_NETMASK
    printf "Gateway: "
    read -r IPV4_GATEWAY
  fi

  printf "IPv6 mode (none/dhcp/static): "
  read -r IPV6_MODE

  if [[ "$IPV6_MODE" == "static" ]]; then
    printf "IPv6 address: "
    read -r IPV6_ADDRESS
    printf "Prefix length: "
    read -r IPV6_PREFIX
    printf "IPv6 gateway (optional): "
    read -r IPV6_GATEWAY || true
  fi

  printf "DNS resolvers (comma-separated): "
  read -r dns
  IFS=',' read -r -a DNS_RESOLVERS <<< "$dns"

  generate_netplan_yaml
  preview_netplan_yaml
  confirm_or_abort "Apply configuration?"

  apply_netplan
  update_hostname
  test_connectivity

  log_action "DONE" "Network configuration applied successfully"
  printf "\nNetwork configuration applied successfully.\n"
}

main "$@"

#END Script