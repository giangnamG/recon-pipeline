#!/usr/bin/env bash
# =============================================================================
# lib/common.sh — Shared utilities for the recon pipeline
# Source this file at the top of every pipeline script
# =============================================================================

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Logging ─────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[+]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[-]${RESET} $*" >&2; }
step()    { echo -e "\n${BOLD}${YELLOW}━━━ $* ━━━${RESET}"; }
found()   { echo -e "${MAGENTA}[★]${RESET} $*"; }

# ─── Helpers ─────────────────────────────────────────────────────────────────
cmd_exists() { command -v "$1" &>/dev/null; }

count_lines() {
    [[ -f "$1" ]] && awk 'NF' "$1" | wc -l | tr -d ' ' || echo 0
}

normalize_domain() {
    local d="$1"
    d="${d#http://}"; d="${d#https://}"; d="${d%/}"
    echo "${d,,}"  # lowercase
}

usage() { echo -e "${BOLD}Usage:${RESET} $*"; }

output_dir() {
    # All output goes to output/<domain>/ relative to pipeline/ parent
    local domain="$1"
    local base
    base="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/output/${domain}"
    mkdir -p "$base"
    echo "$base"
}

# ─── Banner ──────────────────────────────────────────────────────────────────
banner() {
    local title="$1" domain="$2"
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════╗"
    printf "║  %-44s║\n" "$title"
    printf "║  Target: %-36s║\n" "$domain"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ─── Summary box ─────────────────────────────────────────────────────────────
# Usage: summary_box "TITLE" "Key1" "Val1" "Key2" "Val2" ...
summary_box() {
    local title="$1"; shift
    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗"
    printf  "║  %-44s║\n" "$title"
    echo -e "╠══════════════════════════════════════════════╣"
    while [[ $# -ge 2 ]]; do
        local key="$1" val="$2"; shift 2
        printf  "║  %-14s: %-28s║\n" "$key" "$val"
    done
    echo -e "╚══════════════════════════════════════════════╝${RESET}"
    echo ""
}
