#!/usr/bin/env bash
#
# test-detect.sh <detection.tar> [rootkit-submission.tar]
#
# Boots the SAME cached FreeBSD base image that setup.sh provisioned (in a
# disposable overlay), optionally installs a rootkit, then extracts and runs
# ./detect and reports whether the exit code was correct.
#
#   ./test-detect.sh detection.tar                 # CLEAN host  -> expect exit 0
#   ./test-detect.sh detection.tar submission.tar  # INFECTED    -> expect exit 1
#
# Requires: you have run ./setup.sh <submission.tar> at least once (that builds
# the cache: base image + ssh key). Runs detect as root (needs /dev/kmem).
set -euo pipefail

DETECT_TAR="${1:?Usage: $0 <detection.tar> [rootkit-submission.tar]}"
ROOTKIT_TAR="${2:-}"
CACHE="${CACHE_DIR:-$HOME/.freebsd-cache}"
PORT="${SSH_PORT:-2223}"          # distinct from setup.sh's 2222
REL="14.5-RELEASE"
BASE_IMG="$CACHE/freebsd-$REL.qcow2"
KEY="$CACHE/id_ed25519"
HOST_IP="10.0.2.2"
OVERLAY="$CACHE/detect-overlay-$$.qcow2"

[[ -f "$BASE_IMG" ]] || { echo "No cached base image at $BASE_IMG."; echo "Run ./setup.sh <submission.tar> once first to build the cache."; exit 2; }
[[ -f "$KEY" ]]      || { echo "No SSH key at $KEY. Run ./setup.sh once first."; exit 2; }
[[ -f "$DETECT_TAR" ]] || { echo "detection tar not found: $DETECT_TAR"; exit 2; }

ACCEL=(-cpu max); [[ -w /dev/kvm ]] && ACCEL=(-enable-kvm -cpu host)
QEMU_PID=""
cleanup(){ [[ -n "$QEMU_PID" ]] && kill "$QEMU_PID" 2>/dev/null || true; rm -f "$OVERLAY"; }
trap cleanup EXIT

echo "[*] creating disposable overlay..."
qemu-img create -f qcow2 -b "$BASE_IMG" -F qcow2 "$OVERLAY" >/dev/null

echo "[*] booting VM (serial -> $CACHE/detect-boot.log)..."
qemu-system-x86_64 "${ACCEL[@]}" -m 2048M -smp 2 \
	-drive "file=$OVERLAY,format=qcow2,if=virtio" \
	-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$PORT-:22" \
	-device virtio-net-pci,netdev=n0 \
	-display none -serial file:"$CACHE/detect-boot.log" -monitor none </dev/null &
QEMU_PID=$!

SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)
echo "[*] waiting for sshd..."
until ssh "${SSH_OPTS[@]}" -p "$PORT" root@127.0.0.1 true 2>/dev/null; do sleep 1; done

STATE="CLEAN"
if [[ -n "${PRE_CMD:-}" ]]; then
	echo "[*] preparing host state (PRE_CMD)..."
	ssh "${SSH_OPTS[@]}" -p "$PORT" root@127.0.0.1 "$PRE_CMD" || echo "[!] PRE_CMD returned non-zero (continuing)"
fi
if [[ -n "$ROOTKIT_TAR" ]]; then
	[[ -f "$ROOTKIT_TAR" ]] || { echo "rootkit tar not found: $ROOTKIT_TAR"; exit 2; }
	STATE="INFECTED"
	echo "[*] installing rootkit from $ROOTKIT_TAR ..."
	scp "${SSH_OPTS[@]}" -P "$PORT" "$ROOTKIT_TAR" root@127.0.0.1:/root/rk.tar
	ssh "${SSH_OPTS[@]}" -p "$PORT" root@127.0.0.1 "
		set -e
		rm -rf /root/rk && mkdir -p /root/rk && tar -xf /root/rk.tar -C /root/rk
		cd /root/rk && chmod +x ./install && ./install '$HOST_IP'
	" || echo "[!] rootkit install returned non-zero (continuing)"
fi

echo "[*] running detector on $STATE host..."
scp "${SSH_OPTS[@]}" -P "$PORT" "$DETECT_TAR" root@127.0.0.1:/root/det.tar
set +e
ssh "${SSH_OPTS[@]}" -p "$PORT" root@127.0.0.1 "
	rm -rf /root/det && mkdir -p /root/det && tar -xf /root/det.tar -C /root/det
	cd /root/det && chmod +x ./detect 2>/dev/null; ./detect
"
RC=$?
set -e

echo "========================================================"
echo " host state  : $STATE"
echo " detect exit : $RC   (0 = clean, 1 = rootkit)"
if   [[ "$STATE" == CLEAN    && "$RC" -ne 0 ]]; then echo " RESULT      : FALSE POSITIVE (clean host flagged)"; VERDICT=1
elif [[ "$STATE" == INFECTED && "$RC" -ne 1 ]]; then echo " RESULT      : MISSED DETECTION"; VERDICT=1
else echo " RESULT      : correct"; VERDICT=0; fi
echo "========================================================"

ssh "${SSH_OPTS[@]}" -p "$PORT" root@127.0.0.1 poweroff 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
QEMU_PID=""
exit "${VERDICT:-0}"
