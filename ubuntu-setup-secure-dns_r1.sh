#!/usr/bin/env bash
# =============================================================================
# SCRIPT NAME:  ubuntu-setup-secure-dns_r1.sh
# VERSION      : 1.1.0
# AUTHOR: Jason Rowsell (jason@jasonrowsell.net)
# CREATED: 12-13-2025
# Tested on Ubuntu 24.04.3 LTS (Noble/Desktop & Server)
# License: MIT License'
# =============================================================================
#
# DESCRIPTION:
#   Configures Secure DNS (DNS-over-TLS via systemd-resolved) on Ubuntu 24.04.3.
#   The script defaults to Cloudflare DNS but supports Google and Quad9 as well.
#   It includes dry-run support to preview changes, writes audit logs, and works
#   across both desktop and server variants of Ubuntu.
#
#   Features:
#     - Defaults to Cloudflare (DoT) for secure DNS resolution
#     - Supports alternative providers: Google, Quad9 via --provider flag
#     - --dry-run flag previews changes without applying them
#     - All actions logged to /var/log/secure-dns-setup.log
#     - Auto-detects and validates Ubuntu environment
#     - Automatically backs up existing configuration
#     - Idempotent: safe to run multiple times
#
# Example:
#
#   Make script executable:
#     chmod +x ubuntu-setup-secure-dns_r1.sh
#
#   Run script with default provider (Cloudflare):
#     sudo ./ubuntu-setup-secure-dns_r1.sh
#
#   Run with Google DNS and dry-run mode:
#     sudo ./ubuntu-setup-secure-dns_r1.sh --provider google --dry-run
#
# =============================================================================
# REVISION HISTORY
# -----------------------------------------------------------------------------
# DATE         | VERSION | AUTHOR        | CHANGE
# -------------|---------|---------------|--------------------------------------
# 12-13-2025   | 1.1.0   | Jason Rowsell | Added  dry-run, logging
# =============================================================================
#
# License: MIT License
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

# -----------------------------------------------------------------------------
# Global Configuration
# -----------------------------------------------------------------------------
LOG_FILE="/var/log/secure-dns-setup.log"
RESOLVED_CONF="/etc/systemd/resolved.conf"
RESOLV_CONF="/etc/resolv.conf"
STUB_TARGET="/run/systemd/resolve/stub-resolv.conf"
CONFIG_DIR="/etc/systemd/resolved.conf.d"
CONFIG_FILE="$CONFIG_DIR/secure-dns.conf"
RESOLVECTL_CMD="/usr/bin/resolvectl"
DRY_RUN=false
PROVIDER="cloudflare"

# -----------------------------------------------------------------------------
# DNS Providers Map
# -----------------------------------------------------------------------------
declare -A PROVIDERS
PROVIDERS["cloudflare"]="1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com"
PROVIDERS["google"]="8.8.8.8#dns.google 8.8.4.4#dns.google"
PROVIDERS["quad9"]="9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net"

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
log_action() {
    local msg="$1"
    printf "[%s] %s\n" "$(date '+%F %T')" "$msg" | tee -a "$LOG_FILE"
}

log_info() { log_action "INFO: $1"; }
log_error() { log_action "ERROR: $1" >&2; }
log_warn() { log_action "WARN: $1"; }

# -----------------------------------------------------------------------------
# Parse command-line arguments
# -----------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=true
                ;;
            --provider)
                shift
                PROVIDER="${1,,}"  # normalize to lowercase
                ;;
            *)
                log_error "Unknown option: $1"
                return 1
                ;;
        esac
        shift
    done

    if [[ -z "${PROVIDERS[$PROVIDER]:-}" ]]; then
        log_error "Unsupported provider: $PROVIDER"
        log_info "Supported providers: ${!PROVIDERS[*]}"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Validate OS is Ubuntu
# -----------------------------------------------------------------------------
detect_variant() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            log_error "This script only supports Ubuntu."
            return 1
        fi
        log_info "Detected Ubuntu variant: $NAME $VERSION_ID"
    else
        log_error "/etc/os-release not found. Cannot detect OS."
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Enable and start systemd-resolved
# -----------------------------------------------------------------------------
check_resolved_status() {
    if ! systemctl is-enabled --quiet systemd-resolved; then
        $DRY_RUN && log_info "Would enable systemd-resolved" && return 0
        systemctl enable systemd-resolved || {
            log_error "Failed to enable systemd-resolved"
            return 1
        }
    fi

    if ! systemctl is-active --quiet systemd-resolved; then
        $DRY_RUN && log_info "Would start systemd-resolved" && return 0
        systemctl start systemd-resolved || {
            log_error "Failed to start systemd-resolved"
            return 1
        }
    fi

    log_info "systemd-resolved is active and enabled"
}

# -----------------------------------------------------------------------------
# Create config directory if needed
# -----------------------------------------------------------------------------
prepare_config_dir() {
    $DRY_RUN && log_info "Would create directory: $CONFIG_DIR" && return 0
    mkdir -p "$CONFIG_DIR" || {
        log_error "Failed to create $CONFIG_DIR"
        return 1
    }
}

# -----------------------------------------------------------------------------
# Backup existing resolved.conf
# -----------------------------------------------------------------------------
backup_original_conf() {
    if [[ -f "$RESOLVED_CONF" ]]; then
        local backup="$RESOLVED_CONF.bak.$(date +%s)"
        $DRY_RUN && log_info "Would back up $RESOLVED_CONF to $backup" && return 0
        cp "$RESOLVED_CONF" "$backup" || {
            log_error "Backup failed for $RESOLVED_CONF"
            return 1
        }
        log_info "Backed up $RESOLVED_CONF to $backup"
    fi
}

# -----------------------------------------------------------------------------
# Write DNS configuration
# -----------------------------------------------------------------------------
write_dns_config() {
    local dns_config="${PROVIDERS[$PROVIDER]}"
    local dns_entries=($dns_config)

    local content="[Resolve]
DNS=${dns_entries[0]}
FallbackDNS=${dns_entries[1]}
DNSOverTLS=yes
"

    $DRY_RUN && log_info "Would write DNS config to $CONFIG_FILE" && return 0

    printf "%s" "$content" > "$CONFIG_FILE" || {
        log_error "Failed to write config to $CONFIG_FILE"
        return 1
    }

    log_info "Wrote secure DNS config for $PROVIDER to $CONFIG_FILE"
}

# -----------------------------------------------------------------------------
# Relink /etc/resolv.conf to systemd stub resolver
# -----------------------------------------------------------------------------
link_resolv_conf() {
    $DRY_RUN && log_info "Would link $RESOLV_CONF to $STUB_TARGET" && return 0

    rm -f "$RESOLV_CONF" || {
        log_error "Failed to remove existing $RESOLV_CONF"
        return 1
    }

    ln -s "$STUB_TARGET" "$RESOLV_CONF" || {
        log_error "Failed to link $RESOLV_CONF to stub resolver"
        return 1
    }

    log_info "Linked $RESOLV_CONF to $STUB_TARGET"
}

# -----------------------------------------------------------------------------
# Restart systemd-resolved
# -----------------------------------------------------------------------------
restart_resolved() {
    $DRY_RUN && log_info "Would restart systemd-resolved" && return 0

    systemctl daemon-reexec || {
        log_error "systemd daemon-reexec failed"
        return 1
    }

    systemctl restart systemd-resolved || {
        log_error "Failed to restart systemd-resolved"
        return 1
    }

    log_info "Restarted systemd-resolved"
}

# -----------------------------------------------------------------------------
# Validate resolvectl command
# -----------------------------------------------------------------------------
check_resolvectl_available() {
    [[ -x "$RESOLVECTL_CMD" ]] || {
        log_error "resolvectl not found or not executable"
        return 1
    }
}

# -----------------------------------------------------------------------------
# Validate DNS is using selected provider
# -----------------------------------------------------------------------------
validate_dns_provider() {
    local expected_host="${PROVIDERS[$PROVIDER]#*#}" # strip first part
    local servers; servers=$("$RESOLVECTL_CMD" dns | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}#[^ ]+') || true

    [[ -n "$servers" ]] || {
        log_error "No DNS servers returned from resolvectl"
        return 1
    }

    if ! printf "%s\n" "$servers" | grep -q "$expected_host"; then
        log_error "Secure DNS is not using $PROVIDER ($expected_host)"
        return 1
    fi

    log_info "Secure DNS is active and using $PROVIDER ($expected_host)"
}

# -----------------------------------------------------------------------------
# Perform test DNS query
# -----------------------------------------------------------------------------
test_dns_query() {
    "$RESOLVECTL_CMD" query example.com >/dev/null 2>&1 || {
        log_error "DNS resolution failed"
        return 1
    }

    log_info "DNS query successful"
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
main() {
    parse_args "$@" || exit 1
    detect_variant || exit 1
    check_resolvectl_available || exit 1
    check_resolved_status || exit 1
    prepare_config_dir || exit 1
    backup_original_conf || exit 1
    write_dns_config || exit 1
    link_resolv_conf || exit 1
    restart_resolved || exit 1
    validate_dns_provider || exit 1
    test_dns_query || exit 1
}

main "$@"

#END Script