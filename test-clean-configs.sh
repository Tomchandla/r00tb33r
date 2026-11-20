#!/usr/bin/env bash
#
# test-clean-configs.sh <detection.tar>
#
# Runs ./test-detect.sh on several CLEAN host configurations (no rootkit) and
# reports which ones, if any, are flagged. Every config must exit 0; a flag is
# a false positive (-2 marks in the real marking).
set -u

DETECT_TAR="${1:?Usage: $0 <detection.tar>}"
HERE=$(cd "$(dirname "$0")" && pwd)

NAMES=()
CMDS=()
add() { NAMES+=("$1"); CMDS+=("$2"); }

add "baseline" ""

add "listeners-and-connections" '
nohup nc -l 9999 >/dev/null 2>&1 &
nohup nc -l 9998 >/dev/null 2>&1 &
nohup nc -u -l 5353 >/dev/null 2>&1 &
sleep 1
nohup nc 127.0.0.1 9999 >/dev/null 2>&1 &
nohup nc 127.0.0.1 9998 >/dev/null 2>&1 &
sleep 1'

add "extra-kernel-modules" '
kldload cuse 2>/dev/null
kldload fusefs 2>/dev/null
kldload if_tap 2>/dev/null
kldload pf 2>/dev/null
kldload cuse 2>/dev/null
true'

add "module-load-unload-churn" '
for i in 1 2 3 4 5; do kldload cuse 2>/dev/null; kldunload cuse 2>/dev/null; done
kldload fusefs 2>/dev/null
kldunload fusefs 2>/dev/null
true'

add "process-load" '
for i in $(seq 1 150); do nohup sleep 3600 >/dev/null 2>&1 & done
nohup sh -c "while :; do sh -c true; done" >/dev/null 2>&1 &
nohup sh -c "while :; do /bin/echo x >/dev/null; done" >/dev/null 2>&1 &
sleep 2'

add "network-churn" '
nohup sh -c "while :; do nc -l 7777 >/dev/null 2>&1 & p=\$!; sleep 0.2; nc 127.0.0.1 7777 </dev/null >/dev/null 2>&1; kill \$p 2>/dev/null; done" >/dev/null 2>&1 &
nohup nc -l 6666 >/dev/null 2>&1 &
sleep 3'

add "kld_list-configured" '
sysrc kld_list+="cuse" >/dev/null
kldload cuse 2>/dev/null
echo "cuse_load=\"YES\"" >> /boot/loader.conf
true'

FAIL=0
for i in "${!NAMES[@]}"; do
	echo
	echo "################ config: ${NAMES[$i]} ################"
	PRE_CMD="${CMDS[$i]}" SSH_PORT="${SSH_PORT:-2223}" "$HERE/test-detect.sh" "$DETECT_TAR"
	rc=$?
	if [[ $rc -ne 0 ]]; then
		echo ">>> ${NAMES[$i]}: FLAGGED (false positive)"
		FAIL=$((FAIL + 1))
	else
		echo ">>> ${NAMES[$i]}: ok"
	fi
done

echo
echo "=================== summary ==================="
echo "configs run : ${#NAMES[@]}"
echo "false positives : $FAIL"
exit "$FAIL"
