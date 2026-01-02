#!/usr/bin/env bash
# =============================================================================
# =============================================================================
# SCRIPT NAME  : ubuntu-diskspace-triage-diag.sh
# VERSION      : 1.1.0
# AUTHOR: Jason Rowsell (jason@jasonrowsell.net)
# Tested on Ubuntu 24.04.3 LTS (Noble/Desktop & Server)
# License: MIT License
#
#
# Purpose: Diagnostics-only triage for disk space and inode pressure on Ubuntu 24.x+.
#          Produces a numbered report to stdout and a log file. NO remediation.
#
# Target OS: Ubuntu 24.x+ (systemd)
# Shell: bash 5.x
#
# Safety Model (DIAGNOSTICS-ONLY):
#   - NO --apply mode. No state changes to the system (packages/services/config/mounts/etc).
#   - Read-only inspection commands only.
#   - NOTE: The ONLY writes performed are the required log file and lock file.
#
# WILL change:
#   - Create/append a log file: /var/log/<script>.log if writable; else ./logs/<script>.log
#   - Create a lock file for concurrency control
#
# WILL NOT change:
#   - Filesystems, mounts, permissions (except log file mode), packages, services, firewall, sysctl, users, configs
#   - Delete/truncate/vacuum/clean anything (no rm, no apt clean, no journal vacuum)
#
# Preconditions:
#   - Privileges: root NOT required (some paths may be inaccessible without root)
#   - Network: not required
#   - Commands: df, du, find, sort, head, awk, sed, stat, flock (optional: timeout, numfmt, journalctl, snap, docker, podman)
#
# Usage:
#   ./ubuntu-diskspace-triage-diag.sh [--min-file-size-mb 500] [--top-n 20] [--timeout-sec 30]
#                                    [--color=auto|always|never] [--yes] [--verbose] [--debug]
#
# Logging:
#   - root & /var/log writable: /var/log/ubuntu-diskspace-triage-diag.log
#   - otherwise: ./logs/ubuntu-diskspace-triage-diag.log
#
# Revisions:
#
# -----------------------------------------------------------------------------
# DATE         | VERSION | AUTHOR       | CHANGE
# -------------|---------|--------------|--------------------------------------
# 01-02-2026   | 1.1.0   |Jason Rowsell | Initial release with all features.
# =============================================================================
#
# Comment Vocabulary Legend:
#   [SAFE]  Read-only / diagnostics behavior
#   [RISK]  Potentially sensitive output or heavy scan (still read-only)
#   [GUARD] Intentional tolerance of non-zero exit codes under strict mode
#   [NOTE]  Operator guidance / interpretation notes
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
#
# ------------------------------- 1) Header -----------------------------------
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
shopt -s inherit_errexit 2>/dev/null || true  # [GUARD] best-effort; non-fatal by design

# --------------------------- 2) Globals / Defaults ----------------------------
readonly SCRIPT_NAME="$(basename "$0")"
readonly RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
readonly SAFE_PATH_BASE="/usr/sbin:/usr/bin:/sbin:/bin"
if [[ -d /snap/bin ]]; then
  readonly PATH="${SAFE_PATH_BASE}:/snap/bin"
else
  readonly PATH="${SAFE_PATH_BASE}"
fi

# Flags / tunables (defaults)
color_mode="auto"          # auto|always|never
assume_yes=0               # no prompts anyway; accepted for UX parity
min_file_size_mb=500       # default threshold for "large files" scans
top_n=20                   # default top-N lists
timeout_sec=30             # default timeout for expensive calls
verbose=0
debug=0

# Runtime globals
LOG_FILE=""
LOCK_FILE=""
interactive=0
color_enabled=0

# Report findings (for recommendations)
declare -a FS_WARN_80=()
declare -a FS_WARN_90=()
declare -a FS_WARN_95=()
declare -a INODE_WARN_80=()
declare -a INODE_WARN_90=()
declare -a INODE_WARN_95=()
apt_cache_bytes=""
apt_lists_bytes=""
journal_bytes=""
varlog_bytes=""
snap_bytes=""
docker_hint=""
podman_hint=""
large_files_found=0
large_tmp_found=0
coredumps_found=0

# Breadcrumb for ERR trap
LAST_ACTION="init"

# ---------------------- 3) Logging + Redaction Helpers ------------------------
_ts_utc() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

redact_str() {
  # [SAFE] Best-effort redaction for any user-supplied strings we might echo.
  local s="${1-}"
  s="${s//password=/password=REDACTED}"
  s="${s//passwd=/passwd=REDACTED}"
  s="${s//token=/token=REDACTED}"
  s="${s//secret=/secret=REDACTED}"
  s="${s//apikey=/apikey=REDACTED}"
  s="${s//api_key=/api_key=REDACTED}"
  s="${s//key=/key=REDACTED}"
  printf '%s' "$s"
}

_log_init() {
  # Select log path per requirement; create log file with mode 600.
  local base="${SCRIPT_NAME%.sh}.log"
  local varlog="/var/log/${base}"
  local locallog="./logs/${base}"

  # Determine interactive/headless early for color defaults.
  if [[ -t 0 ]] && [[ -t 1 ]] && [[ -z "${CI:-}" ]]; then
    interactive=1
  else
    interactive=0
  fi

  # Prefer /var/log if writable (directory writable and file creatable).
  if [[ -d /var/log ]] && [[ -w /var/log ]]; then
    LOG_FILE="$varlog"
  else
    LOG_FILE="$locallog"
  fi

  # Ensure ./logs exists if needed.
  if [[ "$LOG_FILE" == ./* ]]; then
    if [[ ! -d ./logs ]]; then
      mkdir -p ./logs
    fi
  fi

  # Create/append log file; set mode 600. (This is the required/allowed write.)
  : >>"$LOG_FILE"
  chmod 600 "$LOG_FILE"
}

emit() {
  # Usage: emit "line"
  local line="$*"
  printf '%s\n' "$line"
  if [[ -n "${LOG_FILE:-}" ]]; then
    printf '%s\n' "$line" >>"$LOG_FILE"
  fi
}

emit_ts() {
  # Usage: emit_ts "message"  (timestamps are only for operator context)
  local msg="$*"
  emit "[$(_ts_utc)] $msg"
}

warn() {
  emit_ts "WARN: $*"
}

die() {
  emit_ts "ERROR: $*"
  exit 1
}

# Color helpers (stdout only)
readonly C_RESET=$'\033[0m'
readonly C_BOLD=$'\033[1m'
readonly C_DIM=$'\033[2m'
readonly C_RED=$'\033[31m'
readonly C_YEL=$'\033[33m'
readonly C_GRN=$'\033[32m'
readonly C_BLU=$'\033[34m'

emit_hdr() {
  local s="$*"
  if [[ "$color_enabled" -eq 1 ]]; then
    printf '%b\n' "${C_BOLD}${s}${C_RESET}"
    if [[ -n "${LOG_FILE:-}" ]]; then printf '%s\n' "$s" >>"$LOG_FILE"; fi
  else
    emit "$s"
  fi
}

emit_badge() {
  # Usage: emit_badge "LABEL" "text" (colored label on stdout only)
  local label="$1"; shift
  local text="$*"
  local out_label="$label"
  if [[ "$color_enabled" -eq 1 ]]; then
    case "$label" in
      OK)    out_label="${C_GRN}${label}${C_RESET}" ;;
      WARN)  out_label="${C_YEL}${label}${C_RESET}" ;;
      HIGH)  out_label="${C_RED}${label}${C_RESET}" ;;
      INFO)  out_label="${C_BLU}${label}${C_RESET}" ;;
      *)     out_label="${C_BOLD}${label}${C_RESET}" ;;
    esac
    printf '%b %s\n' "$out_label" "$text"
    if [[ -n "${LOG_FILE:-}" ]]; then printf '%s %s\n' "$label" "$text" >>"$LOG_FILE"; fi
  else
    emit "$label $text"
  fi
}

# --------------------------- 4) Concurrency Lock ------------------------------
acquire_lock() {
  LAST_ACTION="acquire_lock"
  if ! command -v flock >/dev/null 2>&1; then
    warn "flock not found; proceeding WITHOUT concurrency lock (install util-linux to enable)."
    LOCK_FILE=""
    return 0
  fi

  local lock_dir=""
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    if [[ -d /run/lock ]] && [[ -w /run/lock ]]; then
      lock_dir="/run/lock"
    elif [[ -d /var/lock ]] && [[ -w /var/lock ]]; then
      lock_dir="/var/lock"
    else
      lock_dir="."
    fi
  else
    lock_dir="."
  fi

  LOCK_FILE="${lock_dir}/${SCRIPT_NAME%.sh}.lock"

  # shellcheck disable=SC2094
  exec 9>"$LOCK_FILE" || { warn "Unable to open lock file: $LOCK_FILE (continuing without lock)."; LOCK_FILE=""; return 0; }

  if ! flock -n 9; then
    emit_ts "Another instance is running (lock: $LOCK_FILE)."
    exit 7
  fi
}

# --------------------------- 5) Traps / Cleanup -------------------------------
on_err() {
  local ec=$?
  local line="${BASH_LINENO[0]:-?}"
  local action="${LAST_ACTION:-unknown}"
  emit_ts "FAILED: exit=${ec} line=${line} action=${action}"
  if [[ "${debug:-0}" -eq 1 ]]; then
    # [GUARD] Only show failing command in debug; redact best-effort.
    local cmd="${BASH_COMMAND:-?}"
    emit_ts "FAILED_CMD: $(redact_str "$cmd")"
  fi
  exit "$ec"
}

on_term() {
  emit_ts "Received termination signal; exiting safely."
  exit 1
}

cleanup() {
  # No temp files are created (diagnostics-only).
  :
}

trap on_err ERR
trap on_term INT TERM
trap cleanup EXIT

# ---------------------- 6) Argument Parsing + Usage ---------------------------
usage() {
  cat <<'USAGE'
ubuntu-diskspace-triage-diag.sh (diagnostics-only)

Usage:
  ./ubuntu-diskspace-triage-diag.sh [options]

Options:
  --help, -h                  Show help
  --color=auto|always|never    Colorize stdout (default: auto)
  --yes                        Accepted for UX parity (no prompts are used)
  --min-file-size-mb N         Large-file threshold for scans (default: 500)
  --top-n N                    Top-N entries for lists (default: 20)
  --timeout-sec N              Timeout (seconds) for expensive calls (default: 30)
  --verbose                    More context in output
  --debug                      Include extra failure context (still no secrets)

Notes:
  - This script performs NO cleanup or changes. It only reports findings.
  - The only writes are the log file and lock file required for safe operation.

Exit codes:
  0 success
  2 bad arguments
  3 missing dependency (hard requirement)
  7 lock held / cannot proceed with lock
USAGE
}

parse_args() {
  LAST_ACTION="parse_args"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help) usage; exit 0 ;;
      --color=auto)   color_mode="auto" ;;
      --color=always) color_mode="always" ;;
      --color=never)  color_mode="never" ;;
      --yes) assume_yes=1 ;;
      --min-file-size-mb)
        shift
        [[ $# -gt 0 ]] || { usage; exit 2; }
        min_file_size_mb="$1"
        ;;
      --top-n)
        shift
        [[ $# -gt 0 ]] || { usage; exit 2; }
        top_n="$1"
        ;;
      --timeout-sec)
        shift
        [[ $# -gt 0 ]] || { usage; exit 2; }
        timeout_sec="$1"
        ;;
      --verbose) verbose=1 ;;
      --debug) debug=1 ;;
      --apply|--force|--rollback|--plan|--dry-run|--check)
        die "Unsupported mode '$1' (this script is diagnostics-only; no apply/plan modes exist)."
        ;;
      *)
        die "Unknown argument: $(redact_str "$1")"
        ;;
    esac
    shift
  done

  # Validate numeric flags
  if ! [[ "$min_file_size_mb" =~ ^[0-9]+$ ]] || [[ "$min_file_size_mb" -lt 1 ]]; then
    die "--min-file-size-mb must be a positive integer"
  fi
  if ! [[ "$top_n" =~ ^[0-9]+$ ]] || [[ "$top_n" -lt 1 ]] || [[ "$top_n" -gt 200 ]]; then
    die "--top-n must be an integer in range 1..200"
  fi
  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || [[ "$timeout_sec" -lt 1 ]] || [[ "$timeout_sec" -gt 600 ]]; then
    die "--timeout-sec must be an integer in range 1..600"
  fi
}

init_color() {
  LAST_ACTION="init_color"
  case "$color_mode" in
    always) color_enabled=1 ;;
    never)  color_enabled=0 ;;
    auto)
      if [[ "$interactive" -eq 1 ]]; then color_enabled=1; else color_enabled=0; fi
      ;;
    *) color_enabled=0 ;;
  esac
}

# -------------------------- 7) Preflight Validation ---------------------------
require_cmd() {
  local c="$1"
  if ! command -v "$c" >/dev/null 2>&1; then
    die "Missing required command: $c"
  fi
}

utf8_locale_check() {
  LAST_ACTION="preflight_locale"
  if command -v locale >/dev/null 2>&1; then
    local charmap=""
    if charmap="$(locale charmap 2>/dev/null)"; then
      if [[ "$charmap" != "UTF-8" ]]; then
        warn "Locale charmap is '$charmap' (UTF-8 recommended)."
      fi
    else
      warn "Unable to determine locale charmap."
    fi
  else
    warn "locale command not found; cannot validate UTF-8 locale."
  fi
}

bytes_free_for_path() {
  # Usage: bytes_free_for_path /path  -> prints bytes available or empty
  local p="$1"
  local out=""
  out="$(LC_ALL=C df -PB1 -- "$p" 2>/dev/null | awk 'NR==2 {print $4}' || true)"  # [GUARD] df may fail for some paths
  if [[ -n "$out" ]] && [[ "$out" =~ ^[0-9]+$ ]]; then
    printf '%s' "$out"
  else
    printf ''
  fi
}

mem_available_bytes() {
  # Reads /proc/meminfo (MemAvailable) and returns bytes or empty.
  local kb=""
  kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null || true)"  # [GUARD] best-effort
  if [[ -n "$kb" ]] && [[ "$kb" =~ ^[0-9]+$ ]]; then
    printf '%s' "$((kb * 1024))"
  else
    printf ''
  fi
}

human_bytes() {
  # Usage: human_bytes 12345 -> 12K (best effort)
  local b="${1:-}"
  if [[ -z "$b" ]] || ! [[ "$b" =~ ^[0-9]+$ ]]; then
    printf '%s' "-"
    return 0
  fi
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --to=iec --suffix=B --format="%.3g" "$b" 2>/dev/null || printf '%sB' "$b"  # [GUARD] numfmt may fail on some locales
  else
    printf '%sB' "$b"
  fi
}

fs_rw_validation() {
  # "read-only test only": check writable bits and mount ro/rw from /proc/mounts.
  LAST_ACTION="preflight_fs_rw"
  local root_opts=""
  root_opts="$(awk '$2=="/" {print $4}' /proc/mounts 2>/dev/null | head -n 1 || true)"  # [GUARD] best-effort
  if [[ -n "$root_opts" ]]; then
    if [[ "$root_opts" == *"ro"* ]] && [[ "$root_opts" != *"rw"* ]]; then
      warn "Root filesystem appears mounted read-only (opts: $root_opts)."
    fi
  fi
  if [[ -w / ]]; then
    :
  else
    warn "Directory '/' is not writable for current user (expected if non-root on hardened systems)."
  fi
  if [[ -d /var/log ]]; then
    if [[ -w /var/log ]]; then
      :
    else
      if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        warn "/var/log not writable even as root (unexpected); log fallback may be used."
      fi
    fi
  fi
}

preflight_checks() {
  LAST_ACTION="preflight_checks"
  require_cmd df
  require_cmd du
  require_cmd find
  require_cmd sort
  require_cmd head
  require_cmd awk
  require_cmd sed
  require_cmd stat

  utf8_locale_check
  fs_rw_validation

  # Disk/mem sanity (warn <100MB, fail <50MB) - best-effort
  local root_free="" mem_free=""
  root_free="$(bytes_free_for_path /)"
  mem_free="$(mem_available_bytes)"

  if [[ -n "$root_free" ]]; then
    if [[ "$root_free" -lt $((50 * 1024 * 1024)) ]]; then
      warn "Very low free space on '/': $(human_bytes "$root_free") (report may be incomplete)."
      # Diagnostics-only: do NOT hard-fail; keep going to still provide output.
    elif [[ "$root_free" -lt $((100 * 1024 * 1024)) ]]; then
      warn "Low free space on '/': $(human_bytes "$root_free")"
    fi
  else
    warn "Unable to determine free space on '/'."
  fi

  if [[ -n "$mem_free" ]]; then
    if [[ "$mem_free" -lt $((50 * 1024 * 1024)) ]]; then
      warn "Very low available memory: $(human_bytes "$mem_free") (report may be incomplete)."
    elif [[ "$mem_free" -lt $((100 * 1024 * 1024)) ]]; then
      warn "Low available memory: $(human_bytes "$mem_free")"
    fi
  else
    warn "Unable to determine MemAvailable."
  fi
}

# --------------------- 8) Risk Model + Gating Checks --------------------------
risk_model_banner() {
  LAST_ACTION="risk_model"
  emit_hdr "0) Safety Model"
  emit "   - Diagnostics-only script: NO cleanup actions are performed."
  emit "   - Read-only commands only. The only writes are the required log and lock files."
  emit ""
}

# ------------------------ 9) Plan/Diff (Not Used) -----------------------------
plan_diff_placeholder() {
  LAST_ACTION="plan_placeholder"
  if [[ "$verbose" -eq 1 ]]; then
    emit_hdr "Plan/Diff"
    emit "   - Not applicable (diagnostics-only; no changes are planned)."
    emit ""
  fi
}

# -------------------------- 10) Apply (Not Used) ------------------------------
apply_placeholder() {
  LAST_ACTION="apply_placeholder"
  if [[ "$verbose" -eq 1 ]]; then
    emit_hdr "Apply"
    emit "   - Not applicable (diagnostics-only; no changes are applied)."
    emit ""
  fi
}

# -------------------------- Helpers for Report Data ---------------------------
capture_cmd() {
  # Usage: capture_cmd "desc" cmd...
  # Sets globals: CAPTURED_OUTPUT, CAPTURED_RC
  LAST_ACTION="$1"
  shift
  local out="" rc=0
  if command -v timeout >/dev/null 2>&1; then
    if out="$(timeout --preserve-status --signal=TERM "${timeout_sec}" "$@" 2>&1)"; then
      rc=0
    else
      rc=$?
    fi
  else
    if out="$("$@" 2>&1)"; then
      rc=0
    else
      rc=$?
    fi
  fi
  CAPTURED_OUTPUT="$out"
  CAPTURED_RC="$rc"
  return 0
}

emit_block_indented() {
  # Usage: emit_block_indented "text block" "indent"
  local block="${1-}"
  local indent="${2:-   }"
  if [[ -z "$block" ]]; then
    emit "${indent}(no output)"
    return 0
  fi
  while IFS= read -r line; do
    emit "${indent}${line}"
  done <<<"$block"
}

is_network_fstype() {
  # Usage: is_network_fstype "<fstype>" -> 0 if network-ish, 1 otherwise
  local t="${1,,}"
  case "$t" in
    nfs|nfs4|cifs|smbfs|sshfs|fuse.sshfs|afs|davfs|glusterfs|ceph|lustre|gcsfuse|s3fs|fuseblk)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

fstype_for_path() {
  # Best-effort filesystem type for a path (uses stat -f).
  local p="$1"
  local t=""
  t="$(LC_ALL=C stat -f -c %T -- "$p" 2>/dev/null || true)"  # [GUARD] stat may fail on weird paths
  printf '%s' "$t"
}

# ----------------------- 11) Postflight Validation ----------------------------
postflight_validation() {
  LAST_ACTION="postflight_validation"
  emit_hdr "6) Postflight Validation"
  emit "   - No changes were made. Consider re-running:"
  emit "     - df -hT -l"
  emit "     - df -hi -l"
  emit "     - du -x --apparent-size -d 1 / | sort -nr | head -n ${top_n}"
  emit ""
}

# ----------------------------- Report Sections --------------------------------
report_summary() {
  LAST_ACTION="report_summary"
  emit_hdr "1) Summary"
  local hn="" os_pretty="" kernel="" up="" user="" is_root="no"
  hn="$(hostname 2>/dev/null || echo "unknown")"
  kernel="$(uname -r 2>/dev/null || echo "unknown")"
  up="$(uptime -p 2>/dev/null || true)"  # [GUARD] uptime might not support -p on minimal systems
  user="$(id -un 2>/dev/null || echo "unknown")"
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then is_root="yes"; fi

  if [[ -r /etc/os-release ]]; then
    os_pretty="$(awk -F= '/^PRETTY_NAME=/{gsub(/^"|"$|'\''/,"",$2); print $2}' /etc/os-release 2>/dev/null || true)"  # [GUARD]
  fi
  if [[ -z "$os_pretty" ]]; then os_pretty="unknown"; fi

  emit "   Hostname:        $hn"
  emit "   OS:              $os_pretty"
  emit "   Kernel:          $kernel"
  emit "   Uptime:          ${up:-unknown}"
  emit "   Date (UTC):      $(date -u -Is)"
  emit "   Current user:    $user"
  emit "   Running as root: $is_root"
  emit ""
}

report_df_space_and_inodes() {
  LAST_ACTION="report_df"
  emit_hdr "2) Disk Space and Inodes (local filesystems)"
  emit "   df -hT -l"
  capture_cmd "df_hT" df -hT -l
  if [[ "$CAPTURED_RC" -ne 0 ]]; then
    warn "df -hT -l returned rc=$CAPTURED_RC (showing captured output)."
  fi
  emit_block_indented "$CAPTURED_OUTPUT" "     "
  emit ""

  emit "   df -hi -l"
  capture_cmd "df_hi" df -hi -l
  if [[ "$CAPTURED_RC" -ne 0 ]]; then
    warn "df -hi -l returned rc=$CAPTURED_RC (showing captured output)."
  fi
  emit_block_indented "$CAPTURED_OUTPUT" "     "
  emit ""

  # Flag thresholds (skip noisy pseudo types for flagging, but not for display)
  emit "   Flags (usage >80%, >90%, >95%)"
  local dfp=""
  dfp="$(LC_ALL=C df -P -l -T 2>/dev/null || true)"  # [GUARD] diagnostics; tolerate partial/permission errors
  if [[ -n "$dfp" ]]; then
    local flagged_any=0
    while IFS= read -r line; do
      # Skip header
      if [[ "$line" == Filesystem* ]]; then
        continue
      fi
      # Parse: FS TYPE 1K-blocks Used Avail Use% Mount
      # Use awk to avoid bash word-splitting footguns.
      local fs="" fstype="" usep="" mnt=""
      fs="$(awk '{print $1}' <<<"$line" 2>/dev/null || true)"        # [GUARD]
      fstype="$(awk '{print $2}' <<<"$line" 2>/dev/null || true)"    # [GUARD]
      usep="$(awk '{print $6}' <<<"$line" 2>/dev/null || true)"      # [GUARD]
      mnt="$(awk '{print $7}' <<<"$line" 2>/dev/null || true)"       # [GUARD]
      usep="${usep%\%}"

      # Exclude some pseudo types from flagging to reduce noise
      case "${fstype,,}" in
        tmpfs|devtmpfs|squashfs|proc|sysfs|devpts|cgroup2|securityfs|pstore|bpf|tracefs|efivarfs|configfs|debugfs|mqueue|hugetlbfs|fusectl|autofs)
          continue
          ;;
      esac

      if [[ "$usep" =~ ^[0-9]+$ ]]; then
        if [[ "$usep" -ge 95 ]]; then
          FS_WARN_95+=("${mnt} (${fs}, ${fstype}) ${usep}%")
          flagged_any=1
        elif [[ "$usep" -ge 90 ]]; then
          FS_WARN_90+=("${mnt} (${fs}, ${fstype}) ${usep}%")
          flagged_any=1
        elif [[ "$usep" -ge 80 ]]; then
          FS_WARN_80+=("${mnt} (${fs}, ${fstype}) ${usep}%")
          flagged_any=1
        fi
      fi
    done <<<"$dfp"

    if [[ "${#FS_WARN_95[@]}" -gt 0 ]]; then
      emit_badge "HIGH" "Filesystems >=95%:"
      for x in "${FS_WARN_95[@]}"; do emit "     - $x"; done
    fi
    if [[ "${#FS_WARN_90[@]}" -gt 0 ]]; then
      emit_badge "WARN" "Filesystems >=90%:"
      for x in "${FS_WARN_90[@]}"; do emit "     - $x"; done
    fi
    if [[ "${#FS_WARN_80[@]}" -gt 0 ]]; then
      emit_badge "INFO" "Filesystems >=80%:"
      for x in "${FS_WARN_80[@]}"; do emit "     - $x"; done
    fi
    if [[ "$flagged_any" -eq 0 ]]; then
      emit_badge "OK" "No local (non-pseudo) filesystems over 80%."
    fi
  else
    warn "Unable to parse df -P -l -T for threshold flags."
  fi

  emit ""

  # Inode flags
  emit "   Inode flags (IUse% >80%, >90%, >95%)"
  local dfi=""
  dfi="$(LC_ALL=C df -Pi -l 2>/dev/null || true)"  # [GUARD] diagnostics; tolerate partial errors
  if [[ -n "$dfi" ]]; then
    local inode_flagged=0
    while IFS= read -r line; do
      if [[ "$line" == Filesystem* ]]; then
        continue
      fi
      # POSIX df -Pi: FS Inodes IUsed IFree IUse% Mount
      local iuse="" mnt=""
      iuse="$(awk '{print $5}' <<<"$line" 2>/dev/null || true)"  # [GUARD]
      mnt="$(awk '{print $6}' <<<"$line" 2>/dev/null || true)"   # [GUARD]
      iuse="${iuse%\%}"
      if [[ "$iuse" =~ ^[0-9]+$ ]]; then
        if [[ "$iuse" -ge 95 ]]; then
          INODE_WARN_95+=("${mnt} ${iuse}%")
          inode_flagged=1
        elif [[ "$iuse" -ge 90 ]]; then
          INODE_WARN_90+=("${mnt} ${iuse}%")
          inode_flagged=1
        elif [[ "$iuse" -ge 80 ]]; then
          INODE_WARN_80+=("${mnt} ${iuse}%")
          inode_flagged=1
        fi
      fi
    done <<<"$dfi"

    if [[ "${#INODE_WARN_95[@]}" -gt 0 ]]; then
      emit_badge "HIGH" "Inodes >=95%:"
      for x in "${INODE_WARN_95[@]}"; do emit "     - $x"; done
    fi
    if [[ "${#INODE_WARN_90[@]}" -gt 0 ]]; then
      emit_badge "WARN" "Inodes >=90%:"
      for x in "${INODE_WARN_90[@]}"; do emit "     - $x"; done
    fi
    if [[ "${#INODE_WARN_80[@]}" -gt 0 ]]; then
      emit_badge "INFO" "Inodes >=80%:"
      for x in "${INODE_WARN_80[@]}"; do emit "     - $x"; done
    fi
    if [[ "$inode_flagged" -eq 0 ]]; then
      emit_badge "OK" "No local inode usage over 80%."
    fi
  else
    warn "Unable to parse df -Pi -l for inode threshold flags."
  fi

  emit ""
}

report_top_consumers() {
  LAST_ACTION="report_top_consumers"
  emit_hdr "3) Top Consumers"

  emit "   3.1) Top ${top_n} directories under / (one filesystem, apparent size) [RISK: may be slow]"
  # [GUARD] du may return non-zero due to permission errors; output is still useful.
  local du_out=""
  if command -v timeout >/dev/null 2>&1; then
    du_out="$(timeout --preserve-status --signal=TERM "${timeout_sec}" du -x --apparent-size -B1 -d 1 / 2>/dev/null || true)"  # [GUARD]
  else
    du_out="$(du -x --apparent-size -B1 -d 1 / 2>/dev/null || true)"  # [GUARD]
  fi

  if [[ -z "$du_out" ]]; then
    emit "     (no output; permission denied or timed out)"
  else
    # Exclude the root entry "/" itself, sort by bytes desc, show top N.
    local processed=""
    processed="$(awk '$2 != "/" {print $1 "\t" $2}' <<<"$du_out" 2>/dev/null | LC_ALL=C sort -nr | head -n "$top_n" || true)"  # [GUARD]
    if [[ -z "$processed" ]]; then
      emit "     (no directory entries found)"
    else
      while IFS=$'\t' read -r bytes path; do
        emit "     $(human_bytes "$bytes")  $path"
      done <<<"$processed"
    fi
  fi
  emit ""

  emit "   3.2) Top ${top_n} files >= ${min_file_size_mb}MB across /var /home /opt /srv /tmp (no network mounts) [RISK: may be slow]"
  local paths=(/var /home /opt /srv /tmp)
  local candidates=""
  local scanned_any=0

  for p in "${paths[@]}"; do
    if [[ -d "$p" ]]; then
      local fstype=""
      fstype="$(fstype_for_path "$p")"
      if [[ -n "$fstype" ]]; then
        if is_network_fstype "$fstype"; then
          emit_badge "INFO" "Skipping $p (filesystem type '$fstype' looks network-mounted)."
          continue
        fi
      fi

      scanned_any=1
      # Find large files on that filesystem only (-xdev). Keep output as "bytes<TAB>path".
      # [GUARD] find may hit permission errors and exit non-zero; we still want partial results.
      local cmd_out=""
      if command -v timeout >/dev/null 2>&1; then
        cmd_out="$(timeout --preserve-status --signal=TERM "${timeout_sec}" \
          find "$p" -xdev -type f -size +"${min_file_size_mb}"M -printf '%s\t%p\n' 2>/dev/null || true)"  # [GUARD]
      else
        cmd_out="$(find "$p" -xdev -type f -size +"${min_file_size_mb}"M -printf '%s\t%p\n' 2>/dev/null || true)"  # [GUARD]
      fi

      if [[ -n "$cmd_out" ]]; then
        candidates+=$'\n'"$cmd_out"
      fi
    fi
  done

  if [[ "$scanned_any" -eq 0 ]]; then
    emit "     (no target paths exist on this system)"
  else
    candidates="${candidates#"$'\n'"}"
    if [[ -z "$candidates" ]]; then
      emit "     (no files found at or above threshold)"
    else
      large_files_found=1
      local top_files=""
      top_files="$(printf '%s\n' "$candidates" | awk 'NF>=2' | LC_ALL=C sort -nr | head -n "$top_n" || true)"  # [GUARD]
      while IFS=$'\t' read -r bytes path; do
        [[ -n "${bytes:-}" ]] || continue
        emit "     $(human_bytes "$bytes")  $path"
      done <<<"$top_files"
    fi
  fi
  emit ""
}

report_usual_suspects() {
  LAST_ACTION="report_usual_suspects"
  emit_hdr "4) Usual Suspects (read-only checks)"

  # 4.1 APT caches
  emit "   4.1) APT cache and lists size"
  if [[ -d /var/cache/apt ]]; then
    apt_cache_bytes="$(du -sb /var/cache/apt 2>/dev/null | awk '{print $1}' || true)"  # [GUARD]
    emit "     /var/cache/apt:       $(human_bytes "${apt_cache_bytes:-}")"
    capture_cmd "du_apt_cache" du -sh /var/cache/apt
    emit_block_indented "$CAPTURED_OUTPUT" "       "
  else
    emit "     /var/cache/apt:       (not present)"
  fi

  if [[ -d /var/lib/apt/lists ]]; then
    apt_lists_bytes="$(du -sb /var/lib/apt/lists 2>/dev/null | awk '{print $1}' || true)"  # [GUARD]
    emit "     /var/lib/apt/lists:   $(human_bytes "${apt_lists_bytes:-}")"
    capture_cmd "du_apt_lists" du -sh /var/lib/apt/lists
    emit_block_indented "$CAPTURED_OUTPUT" "       "
  else
    emit "     /var/lib/apt/lists:   (not present)"
  fi
  emit ""

  # 4.2 systemd journal usage + Storage=
  emit "   4.2) systemd journal disk usage and Storage= setting"
  if command -v journalctl >/dev/null 2>&1; then
    capture_cmd "journalctl_disk_usage" journalctl --disk-usage
    if [[ "$CAPTURED_RC" -ne 0 ]]; then
      warn "journalctl --disk-usage returned rc=$CAPTURED_RC (permission denied is common when non-root)."
    fi
    emit_block_indented "$CAPTURED_OUTPUT" "     "
  else
    emit "     journalctl not found."
  fi

  # Estimate journal directory bytes for recommendation heuristics
  if [[ -d /var/log/journal ]]; then
    journal_bytes="$(du -sb /var/log/journal 2>/dev/null | awk '{print $1}' || true)"  # [GUARD]
    emit "     /var/log/journal (est): $(human_bytes "${journal_bytes:-}")"
  elif [[ -d /run/log/journal ]]; then
    journal_bytes="$(du -sb /run/log/journal 2>/dev/null | awk '{print $1}' || true)"  # [GUARD]
    emit "     /run/log/journal (est): $(human_bytes "${journal_bytes:-}")"
  fi

  # Storage= config resolution (best-effort)
  local storage_lines=""
  if [[ -r /etc/systemd/journald.conf ]]; then
    storage_lines="$(awk '
      /^[[:space:]]*#/ {next}
      /^[[:space:]]*Storage[[:space:]]*=/ {print FILENAME ":" NR ":" $0}
    ' /etc/systemd/journald.conf 2>/dev/null || true)"  # [GUARD]
  fi
  if [[ -d /etc/systemd/journald.conf.d ]]; then
    # [GUARD] globs may not match; use loop.
    local f
    for f in /etc/systemd/journald.conf.d/*.conf; do
      if [[ -r "$f" ]]; then
        local add=""
        add="$(awk '
          /^[[:space:]]*#/ {next}
          /^[[:space:]]*Storage[[:space:]]*=/ {print FILENAME ":" NR ":" $0}
        ' "$f" 2>/dev/null || true)"  # [GUARD]
        if [[ -n "$add" ]]; then
          storage_lines+=$'\n'"$add"
        fi
      fi
    done
  fi

  if [[ -n "$storage_lines" ]]; then
    emit "     Storage= lines found (may not reflect effective precedence):"
    emit_block_indented "$storage_lines" "       "
  else
    emit "     Storage= setting not found in /etc overrides (defaults may apply)."
  fi
  emit ""

  # 4.3 snap usage
  emit "   4.3) Snap usage (if present)"
  if command -v snap >/dev/null 2>&1; then
    capture_cmd "snap_list" snap list
    emit_block_indented "$CAPTURED_OUTPUT" "     "

    if [[ -d /var/lib/snapd ]]; then
      snap_bytes="$(du -sb /var/lib/snapd 2>/dev/null | awk '{print $1}' || true)"  # [GUARD]
      emit "     /var/lib/snapd (est): $(human_bytes "${snap_bytes:-}")"
      capture_cmd "du_snapd" du -sh /var/lib/snapd
      emit_block_indented "$CAPTURED_OUTPUT" "       "
    fi
    if [[ -d /var/lib/snapd/snaps ]]; then
      capture_cmd "du_snap_snaps" du -sh /var/lib/snapd/snaps
      emit "     /var/lib/snapd/snaps:"
      emit_block_indented "$CAPTURED_OUTPUT" "       "
    fi
  else
    emit "     snap not installed."
  fi
  emit ""

  # 4.4 container storage
  emit "   4.4) Container storage (docker/podman if present)"
  if command -v docker >/dev/null 2>&1; then
    capture_cmd "docker_system_df" docker system df
    if [[ "$CAPTURED_RC" -ne 0 ]]; then
      warn "docker system df rc=$CAPTURED_RC (permission denied is common if not root or not in docker group)."
    fi
    emit_block_indented "$CAPTURED_OUTPUT" "     "
    docker_hint="$CAPTURED_OUTPUT"
  else
    emit "     docker not installed."
  fi

  if command -v podman >/dev/null 2>&1; then
    capture_cmd "podman_system_df" podman system df
    if [[ "$CAPTURED_RC" -ne 0 ]]; then
      warn "podman system df rc=$CAPTURED_RC (permission denied is possible depending on setup)."
    fi
    emit_block_indented "$CAPTURED_OUTPUT" "     "
    podman_hint="$CAPTURED_OUTPUT"
  else
    emit "     podman not installed."
  fi
  emit ""

  # 4.5 /var/log summary + top logs
  emit "   4.5) /var/log summary + top ${top_n} largest log files"
  if [[ -d /var/log ]]; then
    varlog_bytes="$(du -sb /var/log 2>/dev/null | awk '{print $1}' || true)"  # [GUARD]
    emit "     /var/log total (est): $(human_bytes "${varlog_bytes:-}")"
    capture_cmd "du_var_log" du -sh /var/log
    emit_block_indented "$CAPTURED_OUTPUT" "       "

    # [GUARD] Best-effort pipeline: find may exit non-zero due to permissions; we still want partial results.
    local logs_out=""
    if command -v timeout >/dev/null 2>&1; then
      logs_out="$(timeout --preserve-status --signal=TERM "${timeout_sec}" bash -c \
        "set +e +o pipefail; find /var/log -xdev -type f -printf '%s\t%p\n' 2>/dev/null | LC_ALL=C sort -nr | head -n '$top_n'; exit 0" \
        2>/dev/null || true)"  # [GUARD]
    else
      logs_out="$(bash -c \
        "set +e +o pipefail; find /var/log -xdev -type f -printf '%s\t%p\n' 2>/dev/null | LC_ALL=C sort -nr | head -n '$top_n'; exit 0" \
        2>/dev/null || true)"  # [GUARD]
    fi

    if [[ -z "$logs_out" ]]; then
      emit "     (no log file entries found or permission denied)"
    else
      while IFS=$'\t' read -r bytes path; do
        [[ -n "${bytes:-}" ]] || continue
        emit "     $(human_bytes "$bytes")  $path"
      done <<<"$logs_out"
    fi
  else
    emit "     /var/log not present."
  fi
  emit ""

  # 4.6 core dumps
  emit "   4.6) Core dumps (/var/lib/systemd/coredump)"
  if [[ -d /var/lib/systemd/coredump ]]; then
    local count=""
    count="$(find /var/lib/systemd/coredump -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ' || true)"  # [GUARD]
    capture_cmd "du_coredump" du -sh /var/lib/systemd/coredump
    emit "     Files: ${count:-unknown}"
    emit_block_indented "$CAPTURED_OUTPUT" "     "
    if [[ -n "$count" ]] && [[ "$count" =~ ^[0-9]+$ ]] && [[ "$count" -gt 0 ]]; then
      coredumps_found=1
    fi
  else
    emit "     (not present)"
  fi
  emit ""

  # 4.7 orphaned large temp files
  emit "   4.7) Orphaned large temp files (list only; older than 7 days) in /tmp and /var/tmp"
  local tmp_paths=(/tmp /var/tmp)
  local tmp_candidates=""
  for tp in "${tmp_paths[@]}"; do
    if [[ -d "$tp" ]]; then
      local tp_fstype=""
      tp_fstype="$(fstype_for_path "$tp")"
      if [[ -n "$tp_fstype" ]]; then
        if is_network_fstype "$tp_fstype"; then
          emit_badge "INFO" "Skipping $tp (filesystem type '$tp_fstype' looks network-mounted)."
          continue
        fi
      fi
      # [GUARD] find may fail for permissions; keep partial.
      local t_out=""
      if command -v timeout >/dev/null 2>&1; then
        t_out="$(timeout --preserve-status --signal=TERM "${timeout_sec}" \
          find "$tp" -xdev -type f -mtime +7 -size +"${min_file_size_mb}"M -printf '%s\t%TY-%Tm-%Td\t%p\n' 2>/dev/null || true)"  # [GUARD]
      else
        t_out="$(find "$tp" -xdev -type f -mtime +7 -size +"${min_file_size_mb}"M -printf '%s\t%TY-%Tm-%Td\t%p\n' 2>/dev/null || true)"  # [GUARD]
      fi
      if [[ -n "$t_out" ]]; then
        tmp_candidates+=$'\n'"$t_out"
      fi
    fi
  done

  tmp_candidates="${tmp_candidates#"$'\n'"}"
  if [[ -z "$tmp_candidates" ]]; then
    emit "     (none found matching: age>7d and size>=${min_file_size_mb}MB)"
  else
    large_tmp_found=1
    local tmp_top=""
    tmp_top="$(printf '%s\n' "$tmp_candidates" | awk 'NF>=3' | LC_ALL=C sort -nr | head -n "$top_n" || true)"  # [GUARD]
    while IFS=$'\t' read -r bytes ymd path; do
      [[ -n "${bytes:-}" ]] || continue
      emit "     $(human_bytes "$bytes")  ${ymd}  $path"
    done <<<"$tmp_top"
  fi
  emit ""
}

report_recommendations() {
  LAST_ACTION="report_recommendations"
  emit_hdr "5) Recommendations (suggested next actions; NOT performed)"
  local n=1

  if [[ "${#FS_WARN_95[@]}" -gt 0 ]]; then
    emit_badge "HIGH" "${n}) Immediate: free space on filesystems >=95% (risk of outages / writes failing)."
    n=$((n+1))
  elif [[ "${#FS_WARN_90[@]}" -gt 0 ]]; then
    emit_badge "WARN" "${n}) Soon: free space on filesystems >=90%."
    n=$((n+1))
  elif [[ "${#FS_WARN_80[@]}" -gt 0 ]]; then
    emit_badge "INFO" "${n}) Monitor: filesystems >=80%."
    n=$((n+1))
  fi

  if [[ "${#INODE_WARN_95[@]}" -gt 0 || "${#INODE_WARN_90[@]}" -gt 0 || "${#INODE_WARN_80[@]}" -gt 0 ]]; then
    emit_badge "WARN" "${n}) Inode pressure detected: investigate directories creating many small files (logs, caches, build artifacts)."
    n=$((n+1))
  fi

  if [[ "$large_files_found" -eq 1 ]]; then
    emit_badge "INFO" "${n}) Large files found: review the Top Files list and decide whether they can be archived, rotated, or moved."
    emit "     - Pay special attention to databases, VM images, backups, and forgotten tarballs."
    n=$((n+1))
  fi

  # APT cache / lists heuristics (>=1GiB)
  local gib=$((1024 * 1024 * 1024))
  if [[ -n "$apt_cache_bytes" ]] && [[ "$apt_cache_bytes" =~ ^[0-9]+$ ]] && [[ "$apt_cache_bytes" -ge "$gib" ]]; then
    emit_badge "INFO" "${n}) APT cache is large: consider 'apt-get clean' during a maintenance window."
    n=$((n+1))
  fi
  if [[ -n "$apt_lists_bytes" ]] && [[ "$apt_lists_bytes" =~ ^[0-9]+$ ]] && [[ "$apt_lists_bytes" -ge "$gib" ]]; then
    emit_badge "INFO" "${n}) APT lists are large: consider pruning old list files (typically via apt maintenance)."
    n=$((n+1))
  fi

  if [[ -n "$journal_bytes" ]] && [[ "$journal_bytes" =~ ^[0-9]+$ ]] && [[ "$journal_bytes" -ge "$gib" ]]; then
    emit_badge "INFO" "${n}) Journals appear large: consider 'journalctl --vacuum-size=' or adjusting journald Storage=/SystemMaxUse= (policy-based)."
    n=$((n+1))
  fi

  if [[ -n "$varlog_bytes" ]] && [[ "$varlog_bytes" =~ ^[0-9]+$ ]] && [[ "$varlog_bytes" -ge "$gib" ]]; then
    emit_badge "INFO" "${n}) /var/log is large: review biggest logs and verify logrotate coverage and application log settings."
    n=$((n+1))
  fi

  if [[ "$coredumps_found" -eq 1 ]]; then
    emit_badge "INFO" "${n}) Core dumps present: investigate crashing processes; consider limiting core dump retention if appropriate."
    n=$((n+1))
  fi

  if [[ "$large_tmp_found" -eq 1 ]]; then
    emit_badge "INFO" "${n}) Large old temp files found: validate whether they are safe to remove; consider tmpfiles.d policies."
    n=$((n+1))
  fi

  if command -v lsof >/dev/null 2>&1; then
    emit_badge "INFO" "${n}) If disk is full but files aren’t obvious: check for deleted-but-open files:"
    emit "     - sudo lsof +L1 | head"
    n=$((n+1))
  fi

  emit ""
  emit "   [NOTE] This script did not perform any cleanup. Apply changes only after review and according to your change process."
  emit ""
}

# ---------------------------- 12) Summary Section -----------------------------
final_summary() {
  LAST_ACTION="final_summary"
  emit_hdr "7) Run Summary"
  emit "   Run ID:     $RUN_ID"
  emit "   Log file:   $LOG_FILE"
  if [[ -n "${LOCK_FILE:-}" ]]; then
    emit "   Lock file:  $LOCK_FILE"
  else
    emit "   Lock file:  (not used)"
  fi
  emit "   Result:     Completed diagnostics (no remediation performed)"
  emit ""
}

# ---------------------------------- 13) main() --------------------------------
main() {
  parse_args "$@"
  _log_init
  init_color
  acquire_lock

  emit_ts "Starting ${SCRIPT_NAME} (RUN_ID=${RUN_ID})"
  if [[ "$interactive" -eq 1 ]]; then
    emit_ts "Mode: interactive (no prompts used)"
  else
    emit_ts "Mode: headless (no prompts used)"
  fi
  emit ""

  preflight_checks
  risk_model_banner
  report_summary
  report_df_space_and_inodes
  report_top_consumers
  report_usual_suspects
  report_recommendations
  postflight_validation
  final_summary
}

main "$@"

# =============================================================================
# Verification (operator-run; not executed by script)
#   bash -n ubuntu-diskspace-triage-diag.sh
#   shellcheck ubuntu-diskspace-triage-diag.sh
#
# Post-run checks (after you take actions in your change process):
#   df -hT -l
#   df -hi -l
#   du -x --apparent-size -d 1 / | sort -nr | head -n 20
#
# ShellCheck notes:
#   - SC2094 suppressed via comment for flock FD usage (intentional).
# =============================================================================
