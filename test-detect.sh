#!/usr/bin/env bash
#
# test-detect.sh <detection.tar> [rootkit-submission.tar | --test-pfil | --test-pfil-hidden]
#
# Boots the SAME cached FreeBSD base image that setup.sh provisioned (in a
# disposable overlay), optionally installs a rootkit (or loads a synthetic
# pfil(9) hook KLD), then extracts and runs ./detect and reports whether the
# exit code was correct.
#
#   ./test-detect.sh detection.tar                   # CLEAN host  -> expect exit 0
#   ./test-detect.sh detection.tar submission.tar    # INFECTED    -> expect exit 1
#   ./test-detect.sh detection.tar --test-pfil       # INFECTED    -> expect exit 1 (visible synthetic pfil hook)
#   ./test-detect.sh detection.tar --test-pfil-hidden# INFECTED    -> expect exit 1 (self-hiding pfil hook; exercises OWNER_HIDDEN)
#
# Requires: you have run ./setup.sh <submission.tar> at least once (that builds
# the cache: base image + ssh key). Runs detect as root (needs /dev/kmem).
set -euo pipefail

DETECT_TAR="${1:?Usage: $0 <detection.tar> [rootkit-submission.tar | --test-pfil | --test-pfil-hidden]}"
TARGET_MODE="${2:-}"
CACHE="${CACHE_DIR:-$HOME/.freebsd-cache}"
PORT="${SSH_PORT:-2223}"          # distinct from setup.sh's 2222
REL="14.5-RELEASE"
BASE_IMG="$CACHE/freebsd-$REL.qcow2"
KEY="$CACHE/id_ed25519"
HOST_IP="10.0.2.2"
OVERLAY="$CACHE/detect-overlay-$$.qcow2"

[[ -f "$BASE_IMG" ]]   || { echo "No cached base image at $BASE_IMG."; echo "Run ./setup.sh <submission.tar> once first to build the cache."; exit 2; }
[[ -f "$KEY" ]]        || { echo "No SSH key at $KEY. Run ./setup.sh once first."; exit 2; }
[[ -f "$DETECT_TAR" ]] || { echo "detection tar not found: $DETECT_TAR"; exit 2; }
if [[ -n "$TARGET_MODE" && "$TARGET_MODE" != "--test-pfil" && "$TARGET_MODE" != "--test-pfil-hidden" ]]; then
	[[ -f "$TARGET_MODE" ]] || { echo "rootkit tar not found: $TARGET_MODE"; exit 2; }
fi

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

if [[ "$TARGET_MODE" == "--test-pfil" ]]; then
	STATE="INFECTED"
	echo "[*] building and loading synthetic pfil(9) test hook KLD..."
	ssh "${SSH_OPTS[@]}" -p "$PORT" root@127.0.0.1 '
		set -e
		rm -rf /root/pfil_test && mkdir -p /root/pfil_test
		cat << "EOF" > /root/pfil_test/Makefile
KMOD=	test_pfil_hook
SRCS=	test_pfil_hook.c

.include <bsd.kmod.mk>
EOF
		cat << "EOF" > /root/pfil_test/test_pfil_hook.c
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfil.h>

static pfil_hook_t test_hook = NULL;

static pfil_return_t
dummy_mbuf_chk(struct mbuf **mp, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	return (PFIL_PASS);
}

static int
test_pfil_modevent(module_t mod, int type, void *unused)
{
	struct pfil_hook_args pha;

	switch (type) {
	case MOD_LOAD:
		bzero(&pha, sizeof(pha));
		pha.pa_version = PFIL_VERSION;
		pha.pa_flags = PFIL_IN;
		pha.pa_modname = "test_pfil_hook";
		pha.pa_rulname = "default";
		pha.pa_mbuf_chk = dummy_mbuf_chk;
		pha.pa_type = PFIL_TYPE_IP4;
		test_hook = pfil_add_hook(&pha);
		return (test_hook == NULL ? EINVAL : 0);
	case MOD_UNLOAD:
		if (test_hook != NULL)
			pfil_remove_hook(test_hook);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t test_pfil_mod = {
	"test_pfil_hook",
	test_pfil_modevent,
	NULL
};

DECLARE_MODULE(test_pfil_hook, test_pfil_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
EOF
		cd /root/pfil_test && make && kldload ./test_pfil_hook.ko
	'
elif [[ "$TARGET_MODE" == "--test-pfil-hidden" ]]; then
	STATE="INFECTED"
	echo "[*] building and loading SELF-HIDING pfil(9) test hook KLD..."
	ssh "${SSH_OPTS[@]}" -p "$PORT" root@127.0.0.1 '
		set -e
		rm -rf /root/pfil_hidden && mkdir -p /root/pfil_hidden
		cat << "EOF" > /root/pfil_hidden/Makefile
KMOD=	test_pfil_hidden
SRCS=	test_pfil_hidden.c

.include <bsd.kmod.mk>
EOF
		cat << "EOF" > /root/pfil_hidden/test_pfil_hidden.c
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/linker.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfil.h>

static pfil_hook_t test_hook = NULL;
static module_t    test_mod  = NULL;
static int         hidden    = 0;

static pfil_return_t
dummy_mbuf_chk(struct mbuf **mp, struct ifnet *ifp, int flags,
    void *ruleset, struct inpcb *inp)
{
	return (PFIL_PASS);
}

/*
 * Splice our linker_file out of the global loaded-file list (what kldstat
 * walks and what the detector reads to attribute addresses to modules).
 * This is TAILQ_REMOVE without the head; we skip the tqh_last fixup, which
 * only matters if something inserts at the tail later - nothing does before
 * the VM powers off. No kld_sx lock: safe only in a quiescent test VM.
 */
static void
hide_module(void)
{
	linker_file_t lf;

	if (hidden || test_mod == NULL)
		return;
	lf = module_file(test_mod);
	if (lf == NULL)
		return;
	if (lf->link.tqe_next != NULL)
		lf->link.tqe_next->link.tqe_prev = lf->link.tqe_prev;
	*lf->link.tqe_prev = lf->link.tqe_next;
	hidden = 1;
}

static int
sysctl_hide(SYSCTL_HANDLER_ARGS)
{
	int val = 0, error;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	if (val)
		hide_module();
	return (0);
}

static SYSCTL_NODE(_net, OID_AUTO, test_pfil, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "pfil hide test");
SYSCTL_PROC(_net_test_pfil, OID_AUTO, hide,
    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, 0, 0, sysctl_hide, "I",
    "write 1 to unlink (hide) this module");

static int
test_pfil_modevent(module_t mod, int type, void *unused)
{
	struct pfil_hook_args pha;

	switch (type) {
	case MOD_LOAD:
		test_mod = mod;
		bzero(&pha, sizeof(pha));
		pha.pa_version = PFIL_VERSION;
		pha.pa_flags = PFIL_IN;
		pha.pa_modname = "test_pfil_hidden";
		pha.pa_rulname = "default";
		pha.pa_mbuf_chk = dummy_mbuf_chk;
		pha.pa_type = PFIL_TYPE_IP4;
		test_hook = pfil_add_hook(&pha);
		return (test_hook == NULL ? EINVAL : 0);
	case MOD_UNLOAD:
		if (hidden)
			return (EBUSY);   /* cannot cleanly unload once unlinked */
		if (test_hook != NULL)
			pfil_remove_hook(test_hook);
		return (0);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t test_pfil_mod = {
	"test_pfil_hidden",
	test_pfil_modevent,
	NULL
};

DECLARE_MODULE(test_pfil_hidden, test_pfil_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
EOF
		cd /root/pfil_hidden && make && kldload ./test_pfil_hidden.ko
		if kldstat | grep -q test_pfil_hidden; then
			echo "[*] visible in kldstat before hide"
		fi
		sysctl net.test_pfil.hide=1
		if kldstat | grep -q test_pfil_hidden; then
			echo "[!] still visible in kldstat after hide - hide FAILED (test invalid)"
			exit 1
		fi
		echo "[*] gone from kldstat after hide (hidden-module path now exercised)"
	'
elif [[ -n "$TARGET_MODE" ]]; then
	STATE="INFECTED"
	echo "[*] installing rootkit from $TARGET_MODE ..."
	scp "${SSH_OPTS[@]}" -P "$PORT" "$TARGET_MODE" root@127.0.0.1:/root/rk.tar
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