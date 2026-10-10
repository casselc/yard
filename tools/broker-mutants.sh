#!/bin/sh
# Planted mutants for internal/broker: each replaces the one line marked
# "// MUTANT:<name>" in a scratch copy of the module, and the package's tests
# must then FAIL. The unmutated copy must PASS first. Exit 0 only if every
# mutant is caught.
#
#   tools/broker-mutants.sh            # all
#   tools/broker-mutants.sh bufferSSE  # one
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
. "$here/env.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/broker-mut.XXXXXX")
trap 'rm -rf "$work"' EXIT

# name|replacement (Go, one line; the marked line's indentation is kept)
cat >"$work/mutants" <<'EOF'
trustClientPrincipal|principal := st.principal; if v := pr.In.Header.Get("X-Halo-Principal"); v != "" { principal = v }
forwardClientAuth|if a := pr.In.Header.Get("Authorization"); a != "" { h.Set("Authorization", a) } else { injectKey(h, svc.inject, st.secret) }
bufferSSE|if b, err := io.ReadAll(resp.Body); err == nil { resp.Body = io.NopCloser(strings.NewReader(string(b))) }; return nil
allowAny|return true || a[strings.ToLower(hostport)]
detachUpstream|pr.Out = pr.Out.WithContext(context.WithoutCancel(ctx))
defaultAllow|if s := b.hosts[host]; s != nil { return s }; for _, s := range b.hosts { if s.kind == "halo" { return s } }; return nil
rawIdemKey|st.idem = ik[0]
logSecretValue|st.ev.Credential = svc.secret + ":" + key.value()
peerUnchecked|if a = a.Unmap(); true { return true }
imdsTokenUnbound|if false && v.inc != inc {
blindRetry|_ = a.fence
staleEpoch|case false && (c.Epoch != a.epoch || c.Epoch != sl.epoch):
ttlUnbounded|case false && c.Expiration.After(a.beganAt.Add(s.cfg.MaxCredTTL)):
revokeKeepsCred|_ = sl.cur
advertiseReal|return c.Expiration.UTC().Truncate(time.Second)
connIncarnationUnchecked|live := ok
syncUnserialized|unlock := func() {}
syncAfterClose|if closed && false {
leaseIgnored|return true
leaseNotEnforced|if true {
serialRegression|case false && sn.Serial < b.floors.Serial:
conflictKeepsFirst|if false {
epochRegression|if false && l.Epoch < b.floors.Epochs[p] {
resurrect|if _, gone := b.floors.Retired[l.Incarnation]; false && gone {
staleRequestServed|return true
commitUnchecked|if sl == nil ||
fenceIgnoresJWT|a.fence = now.Add(s.cfg.MaxJWTLifetime + s.cfg.Skew)
evictBusySlot|if !v.live && !now.IsZero() {
connUnlimited|case false:
concurrencyUnlimited|if !acquire(psem) && false {
quotaUnchecked|case false && pq.reqTokens < 1:
bodyUnbounded|if false {
uploadUnbounded|_ = c.ctlr
writeUnbounded|_ = c.ctlr
haloKeyOptional|if false {
haloPlainRemote|if err != nil || false && !a.IsLoopback() {
optimisticOutcome|ev.Outcome = "done"
cloud4xxNotDone|case kind == "cloud" && code >= 400 && code < 500:
metadataEscaped|if false {
sinkBlocks|s.ch <- sinkItem{line: line}; return
denyUnlimited|if false {
ancestorsUnchecked|if false {
secretNotRegular|if false {
specialUseAllowed|if false && p.Contains(a) {
devFakeWithoutDev|if false {
activeUnpersisted|if o, ok := b.floors.Active[l.Incarnation]; false && ok && (o.Addr != l.Addr.String() || o.Principal != p) {
closeUnbounded|case <-make(chan time.Time):
closeUnderLock|b.mu.Lock(); _ = old.srv.Close(); b.mu.Unlock()
dayRollsBack|if day != q.day {
deliveryIgnored|if false {
dirSyncIgnored|if err := ops.syncDir(dir); false && err != nil {
drainRejectedBody|_ = w
expiryFencesAll|if sl.live {
finishTrustsTimer|if false {
floorsUnvalidated|if false {
incarnationFormatUnchecked|if false {
keepOldListener|continue
linkRateUnchecked|if false {
lossForgotten|if ok || true {
meterUnchecked|k := len(p)
missingFloorsIsFirstBoot|case errors.Is(err, ErrNoFloors):
noFramingRecovery|if false {
noRecheckBeforePublish|if false {
prepareDeadlineUnchecked|case false:
rawMethodLogged|return m
renderUnbounded|if err != nil {
replayUnverified|if false {
retryAfterIgnoresHold|w.Header().Set("Retry-After", "1")
sinkUnboundedBytes|if s.closed {
sseDispatchWithoutData|if p.poisoned {
uncertainIgnored|if false {
workersUnbounded|if false {
chunkedBodyStatusIgnored|if false && errors.As(err, &mbe) {
terminalErrorUnreported|ev.Detail = "no_terminal_event"
EOF

fresh() {
	rm -rf "$work/m"
	mkdir -p "$work/m"
	cp "$here/go.mod" "$here/go.sum" "$work/m/"
	cp -r "$here/internal" "$here/cmd" "$work/m/"
}

# -race: the serialization mutant is caught by the race detector
runtests() { (cd "$work/m" && go test -race -count=1 -timeout 180s ./internal/broker/ ./cmd/yard-broker/ >"$work/out" 2>&1); }

fresh
if ! runtests; then
	cat "$work/out"
	echo "design: FAIL (the unmutated package must pass)"
	exit 1
fi
echo "design: PASS"

only=${1:-}
total=0
caught=0
while IFS='|' read -r name repl; do
	[ -n "$only" ] && [ "$name" != "$only" ] && continue
	total=$((total + 1))
	fresh
	n=$(grep -l "// MUTANT:$name\$" "$work"/m/internal/broker/*.go "$work"/m/cmd/yard-broker/*.go | wc -l)
	file=$(grep -l "// MUTANT:$name\$" "$work"/m/internal/broker/*.go "$work"/m/cmd/yard-broker/*.go || true)
	if [ "$n" -ne 1 ] || [ "$(grep -c "// MUTANT:$name\$" "$file")" -ne 1 ]; then
		echo "$name: marker not found exactly once"
		continue
	fi
	MUT_NAME=$name MUT_REPL=$repl python3 - "$file" <<'PY'
import os, re, sys
p = sys.argv[1]
name, repl = os.environ["MUT_NAME"], os.environ["MUT_REPL"]
lines = open(p).read().split("\n")
for i, l in enumerate(lines):
    if l.endswith("// MUTANT:" + name):
        indent = re.match(r"\s*", l).group(0)
        lines[i] = indent + repl
open(p, "w").write("\n".join(lines))
PY
	if (cd "$work/m" && go build ./internal/broker/ ./cmd/yard-broker/ >"$work/out" 2>&1); then :; else
		echo "$name: does not compile"
		cat "$work/out"
		continue
	fi
	if runtests; then
		echo "$name: SURVIVED"
	else
		failed=$(grep -E '^--- FAIL|WARNING: DATA RACE' "$work/out" | awk '{print ($1=="---")?$3:"DATA_RACE"}' | sort -u | head -4 | tr '\n' ' ')
		echo "$name: caught by $failed"
		caught=$((caught + 1))
	fi
done <"$work/mutants"
echo "mutants caught: $caught/$total"
[ "$caught" -eq "$total" ]
