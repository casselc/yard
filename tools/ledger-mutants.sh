#!/usr/bin/env bash
# ledger-mutants.sh: plant each of the ledger's rule violations (spec/agentop/broker.qnt's mutants) and check the
# tests catch it. Usage: tools/ledger-mutants.sh   (from the repo root, after `. ./env.sh`)
set -u
F=internal/ledger/ledger.go
cp $F /tmp/ledger.go.orig.$$
trap 'cp /tmp/ledger.go.orig.$$ $F; rm -f /tmp/ledger.go.orig.$$' EXIT
caught=0; total=0
mut() { # name python-replace-old python-replace-new   (ONLY=name runs one)
  [ -n "${ONLY:-}" ] && [ "$1" != "$ONLY" ] && return
  total=$((total+1))
  cp /tmp/ledger.go.orig.$$ $F
  python3 - "$F" "$2" "$3" <<'PY' || { echo "mutant $1: pattern not found"; return; }
import sys; p,a,b=sys.argv[1:]; s=open(p).read()
assert a in s; open(p,'w').write(s.replace(a,b,1))
PY
  if go test -count=1 ./internal/ledger/ >/tmp/ledger-mut-$1.log 2>&1; then
    echo "SURVIVED $1"
  else
    if grep -q "build failed\|\[setup failed\]" /tmp/ledger-mut-$1.log; then echo "BUILD-FAIL $1"; else echo "caught    $1"; caught=$((caught+1)); fi
  fi
}
# checkConfirmedOnly: admission counts settled usage only, not open reservations or unresolved maxima
mut checkConfirmedOnly "ELSE max_in + max_out END), 0)," "ELSE 0 END), 0),"
# volatileReserve: opening the ledger does not recover in-flight rows (they stay reserved/sent forever)
mut noRecover '`UPDATE calls SET state = ? WHERE state IN (?, ?)`, Unresolved, Reserved, Sent' '`UPDATE calls SET state = ? WHERE 0`, Unresolved'
# dropUnanswered: an unresolved call is held at zero
mut dropUnanswered "COALESCE(SUM(CASE WHEN state = 'settled' THEN charge ELSE max_charge END), 0)," "COALESCE(SUM(CASE WHEN state = 'settled' THEN charge WHEN state = 'unresolved' THEN 0 ELSE max_charge END), 0),"
# moneyOnly: the token limit is not enforced on its own
mut moneyOnly "out := lim.Tokens - ht - in" "out := int64(1 << 40)"
# claimExact: a report with unresolved calls says exact
mut claimExact 's.Certainty = "bounded"' 's.Certainty = "exact"'
# reserveCheapInput: the input bound is priced at plain input, not the most expensive input class
mut reserveCheapInput "func (p Prices) maxIn() int64 { return max(p.Input, p.CacheRead, p.CacheWrite) }" "func (p Prices) maxIn() int64 { return p.Input }"
# noRoundUp: charges round down
mut noRoundUp "func ceilDiv(a, b int64) int64 { return (a + b - 1) / b }" "func ceilDiv(a, b int64) int64 { return a / b }"
# reportInFlight: a report is given while calls are in flight
mut reportInFlight "	if inflight > 0 {
		return s, ErrInFlight" "	if false {
		return s, ErrInFlight"
echo "caught $caught of $total"
[ $caught = $total ]
