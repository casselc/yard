#!/bin/sh
# t20-spawn-j0.sh -- yard-spawn J0 end to end on the host (root).
# NEEDS     n0-10-zfs (/yard/jails), n0-30-tasks (tasks.conf, class yard_task, devfs ruleset 10),
#           n0-40-template (/yard/tmpl/base). Optional: n0-20-audit (audit check), n0-50-pf (broker check).
# PURPOSE   Checks, each PASS/MISMATCH against a stated expectation:
#           A task uid + rctl user: rules; B identity inside a call (uid, jail name, hostname, ro root,
#           rw/ro workspace, minimal /dev); C timeout kills the whole tree via jail_remove; D per-call
#           vmemoryuse rule; E user: accounting aggregates the task's processes; F audit zonename + auid
#           set before attach; G broker sandbox: metadata IPs rdr'd to a fake broker on the host side
#           of the epair, everything else blocked; H latency (bench); I nothing left behind.
# PREDICT   A: 4 user rules. B: uid=task uid, hostname=call id, jailed=1, touch / fails, rw ws ok,
#           ro ws fails, /dev has <= 12 entries. C: exit 124 after 2.0-2.5 s, 0 processes of the uid
#           left, 0 dying jails. D: dd 10M ok, dd 100M "Cannot allocate memory" (Phase 0 spike 22).
#           E: rctl -u user:<uid> maxproc >= 50 while 50 sleeps run. F: >= 1 record naming
#           ysbx_j0a.caud1 with auid = $SUDO_UID. G: both metadata fetches return "yard-fake-broker",
#           1.1.1.1 and the host's sshd blocked. H: hypothesis -- Phase 0's 0.52 ms child cost plus
#           4 nmounts + 4 unmounts (~0.15 ms each), the Go fork/exec of the shim (~0.3 ms) and the
#           login-class lookup: total p50 ~2.0 ms (1.5-3.5), p99 < 6 ms; +0.1 ms with -mem (two
#           rctl syscalls instead of Phase 0's 0.8 ms CLI). I: no ysbx_ jails (live or dying), no
#           mounts under /yard/jails/j0*, no rctl rules for the task uid or ysbx_ jails, no yard epairs.
# CHANGES   Temporary: sandboxes j0a/j0b under /yard/jails (destroyed with -purge), task j0test (uid freed),
#           an nc fake broker, a pf anchor yard/sbx-j0b (flushed), one epair (destroyed).
# UNDO      Automatic (trap). If interrupted: yard-spawn sbx-destroy -id j0a -purge; same for j0b;
#           yard-spawn task-end -task j0test.
# RUNTIME   ~1 min.
export YARD_OPS="$(cd "$(dirname "$0")/.." && pwd)"
. "$YARD_OPS/lib.sh"
step_wrap t20-spawn-j0 "$0" "$@"
B=$OPS/../bin; SP=$B/yard-spawn
[ -x $B/yard-exec-shim ] || die "no $B/yard-exec-shim (run tools/deploy-nuc.sh)"
[ -f /yard/tmpl/base/.yard-template-ok ] || die "template missing: run n0-40-template.sh"
[ -f /usr/local/etc/yard/tasks.conf ] || die "tasks.conf missing: run n0-30-tasks.sh"
[ "$(sysctl -n kern.racct.enable)" = 1 ] || die "kern.racct.enable=0"
say "revision $(cat $B/REVISION 2>/dev/null); template $(cat /yard/tmpl/base/.yard-template-ok)"
W=$STATE/t20; rm -rf $W; mkdir -p $W
FAILS=0; NCP=""
pass() { say "PASS $*"; }
miss() { say "MISMATCH $*"; FAILS=$((FAILS+1)); }
expect() { # expect LABEL WANT GOT
	if [ "$2" = "$3" ]; then pass "$1: $3"; else miss "$1: want '$2', got '$3'"; fi
}
cleanup() {
	set +e
	for p in $NCP; do kill -TERM -- -$p 2>/dev/null; done; NCP=""
	$SP sbx-destroy -id j0a -purge >/dev/null 2>&1
	$SP sbx-destroy -id j0b -purge >/dev/null 2>&1
	$SP task-end -task j0test >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

say "=== A task uid and rctl user: rules"
U=$($SP task-begin -task j0test)
say "task uid $U"
[ -n "$U" ] || die "task-begin returned no uid (see the yard-spawn error above); the remaining checks need one"
expect "A user rules" 4 "$(rctl | grep -c "^user:$U:")"
R="$SP run -sbx j0a -uid $U"

say "=== B identity inside a call"
$SP sbx-create -id j0a -net none -owner $U | tee $W/sbx-a.json
expect "B uid" "$U" "$($R -call cid1 -- id -u)"
expect "B hostname" "cid2" "$($R -call cid2 -- hostname)"
expect "B jailed" 1 "$($R -call cid3 -- /sbin/sysctl -n security.jail.jailed)"
expect "B jail name" "ysbx_j0a.cid4" "$(sh -c "$R -call cid4 -timeout 5s -- sleep 2" & sleep 1; jls -n name | sed -n 's/^name=//p' | grep '^ysbx_j0a\.cid4$'; wait)"
if $R -call cid5 -- touch /x 2>/dev/null; then miss "B root writable"; else pass "B root read-only"; fi
if $R -call cid6 -- touch /workspace/rw-ok; then pass "B rw workspace writable"; else miss "B rw workspace"; fi
if $R -call cid7 -ws ro -- touch /workspace/ro-x 2>/dev/null; then miss "B ro workspace writable"; else pass "B ro workspace read-only"; fi
n=$($R -call cid8 -- ls /dev | wc -l | tr -d ' ')
[ "$n" -le 12 ] && pass "B /dev entries: $n ($($R -call cid9 -- ls /dev | tr '\n' ' '))" || miss "B /dev has $n entries"
if $R -call cida -- sh -c 'echo hi >/tmp/t && cat /tmp/t' | grep -q hi; then pass "B tmpfs /tmp writable"; else miss "B /tmp"; fi

say "=== C timeout kills the tree"
t0=$(date +%s)
if $R -call ctmo -timeout 2s -json -- sh -c 'sleep 60 & sleep 60 & sleep 60 & wait' 2>$W/c.err; then rc=0; else rc=$?; fi
t1=$(date +%s)
expect "C exit code" 124 "$rc"
say "C elapsed $((t1 - t0)) s; $(grep RESULT $W/c.err)"
sleep 0.2
expect "C processes left for uid" 0 "$(ps -ax -o uid= | awk -v u=$U '$1==u' | wc -l | tr -d ' ')"
expect "C dying jails" 0 "$(jls -d -n name 2>/dev/null | grep -c 'ysbx_j0a\.ctmo')"

say "=== D per-call memory rule"
if $R -call cm1 -mem 64m -- dd if=/dev/zero of=/dev/null bs=10m count=1 2>$W/d1.err; then pass "D 10M allowed"; else miss "D 10M denied: $(cat $W/d1.err)"; fi
if $R -call cm2 -mem 64m -- dd if=/dev/zero of=/dev/null bs=100m count=1 2>$W/d2.err; then miss "D 100M allowed under 64m"; else pass "D 100M denied: $(grep -v RESULT $W/d2.err | head -1)"; fi
expect "D rule removed" 0 "$(rctl | grep -c 'ysbx_j0a.cm')"

say "=== E user: accounting aggregates the task"
$R -call cagg -timeout 20s -- sh -c 'i=0; while [ $i -lt 50 ]; do sleep 5 & i=$((i+1)); done; wait' &
sleep 2
mp=$(rctl -u user:$U | sed -n 's/^maxproc=//p')
[ "${mp:-0}" -ge 50 ] && pass "E rctl -u user:$U maxproc=$mp" || miss "E maxproc=$mp (want >= 50)"
wait

say "=== F audit state before attach"
if service auditd onestatus >/dev/null 2>&1; then
	AD=$(sed -n 's/^dir://p' /etc/security/audit_control)
	audit -n; sleep 1
	SUDO_UID=${SUDO_UID:-1001} $R -call caud1 -- /usr/bin/true
	audit -n; sleep 2
	T=$(ls -t $AD | grep -v -E 'current|crash|not_terminated' | head -1)
	praudit -l $AD/$T >$W/audit.txt 2>/dev/null || true
	n=$(grep -c 'ysbx_j0a.caud1' $W/audit.txt || true)
	[ "$n" -ge 1 ] && pass "F $n records name ysbx_j0a.caud1" || miss "F no records name the call jail (trail $T)"
	grep 'ysbx_j0a.caud1' $W/audit.txt | head -2 | cut -c1-400
else
	say "SKIP F: auditd not running (n0-20-audit.sh not applied)"
fi

say "=== G broker sandbox (metadata rdr)"
if pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
	$SP sbx-create -id j0b -net broker -subnet 200 -broker-port 8099 -owner $U | tee $W/sbx-b.json
	# own process group (set -m), so cleanup kills the listening nc too, not just the loop
	set -m
	( while :; do printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nyard-fake-broker\n' | nc -N -l 10.77.200.1 8099 >>$W/broker.txt 2>&1 || break; done ) </dev/null >/dev/null 2>&1 &
	NCP="$NCP $!"; set +m; sleep 0.5
	RB="$SP run -sbx j0b -uid $U -net inherit -timeout 10s"
	expect "G imds" yard-fake-broker "$($RB -call cg1 -- fetch -T 3 -qo - http://169.254.169.254/latest/meta-data/ 2>/dev/null)"
	expect "G ecs" yard-fake-broker "$($RB -call cg2 -- fetch -T 3 -qo - http://169.254.170.2/v2/credentials/x 2>/dev/null)"
	if $RB -call cg3 -- fetch -T 3 -qo /dev/null http://1.1.1.1/ 2>/dev/null; then miss "G internet reachable"; else pass "G internet blocked"; fi
	if $RB -call cg4 -- fetch -T 3 -qo /dev/null http://10.77.200.1:22/ 2>/dev/null; then miss "G host sshd reachable"; else pass "G host sshd blocked"; fi
	if $SP run -sbx j0b -uid $U -net none -timeout 10s -call cg5 -- fetch -T 3 -qo /dev/null http://169.254.169.254/ 2>/dev/null; then miss "G net=none child reached the broker"; else pass "G net=none child has no network"; fi
	say "G anchor counters:"; pfctl -a yard/sbx-j0b -v -s rules | grep -A1 block
	$SP sbx-destroy -id j0b -purge
	expect "G anchor emptied" 0 "$( (pfctl -a yard/sbx-j0b -s rules; pfctl -a yard/sbx-j0b -s nat) 2>/dev/null | grep -c -v ALTQ)"
else
	say "SKIP G: pf not enabled (n0-50-pf.sh not applied)"
fi

say "=== H latency"
$SP bench -sbx j0a -uid $U -n 200 -ws rw -- /usr/bin/true | tee $W/bench.json
$SP bench -sbx j0a -uid $U -n 200 -ws rw -mem 64m -- /usr/bin/true | tee $W/bench-mem.json

say "=== I leftovers"
$SP sbx-destroy -id j0a -purge
$SP task-end -task j0test >/dev/null
expect "I jails" 0 "$(jls -d -n name 2>/dev/null | grep -c 'ysbx_')"
expect "I mounts" 0 "$(mount -p | awk '{print $2}' | grep -c '^/yard/jails/j0')"
expect "I rctl" 0 "$(rctl | grep -c -E "^user:$U:|ysbx_")"
expect "I epairs" 0 "$(for e in $(ifconfig -l); do ifconfig $e 2>/dev/null | grep -c 'description: yard sbx'; done | awk '{s+=$1} END {print s+0}')"
trap - EXIT
[ $FAILS = 0 ] || die "$FAILS check(s) did not match"
say "OK"
