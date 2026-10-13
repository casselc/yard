#!/usr/bin/env bash
# route-mutants.sh: plant rule violations in internal/agentroute and check its tests catch them.
#   tools/route-mutants.sh            (from the repo root, after `. ./env.sh`; ONLY=name runs one)
set -u
F=internal/agentroute/route.go
cp $F /tmp/route.go.orig.$$
trap 'cp /tmp/route.go.orig.$$ $F; rm -f /tmp/route.go.orig.$$' EXIT
caught=0; total=0
mut() { # name old new
  [ -n "${ONLY:-}" ] && [ "$1" != "$ONLY" ] && return
  total=$((total+1))
  cp /tmp/route.go.orig.$$ $F
  python3 - "$F" "$2" "$3" <<'PY' || { echo "mutant $1: pattern not found"; return; }
import sys; p,a,b=sys.argv[1:]; s=open(p).read()
assert a in s; open(p,'w').write(s.replace(a,b,1))
PY
  if timeout 600 go test -count=1 ./internal/agentroute/ >/tmp/route-mut-$1.log 2>&1; then echo "SURVIVED $1"
  elif grep -q "build failed\|\[setup failed\]" /tmp/route-mut-$1.log; then echo "BUILD-FAIL $1"
  else echo "caught    $1"; caught=$((caught+1)); fi
}
# lostIsFree: a call halo no longer knows (another incarnation) is settled at zero instead of kept at its maximum
mut lostIsFree '			_ = s.cfg.Ledger.Unresolve(context.Background(), id)
			return nil, fmt.Errorf("halo answered %q", v.Status)' '			_ = s.cfg.Ledger.Settle(context.Background(), id, ledger.Usage{})
			return nil, fmt.Errorf("halo answered %q", v.Status)'
# resolveUnknownFree: Resolve settles an unknown record at zero
mut resolveUnknownFree '		case v.NeverRan():
			if err := l.Settle(ctx, c.Call, ledger.Usage{}); err != nil {' '		case v.NeverRan() || v.Status == "unknown":
			if err := l.Settle(ctx, c.Call, ledger.Usage{}); err != nil {'
# cachedTwice: cached tokens counted on top of the whole prompt
mut cachedTwice 'return ledger.Usage{Input: u.Prompt - cached, CacheRead: cached, Output: u.Completion}' 'return ledger.Usage{Input: u.Prompt, CacheRead: cached, Output: u.Completion}'
# noCancelOnRefusal: a refused copy is not cancelled, so "not accepted yet" never becomes final
mut noCancelOnRefusal '	defer cancel()
	s.cancelOp(ctx, op)
	if _, err := s.finish(ctx, id, op, false); err != nil {' '	defer cancel()
	if _, err := s.finish(ctx, id, op, false); err != nil {'
# exhaustRetryable: a budget refusal answers 429 (the harness retries forever)
mut exhaustRetryable 'apiError(w, 400, "invalid_request_error", "yard: the task'"'"'s "+lim.Limit+" budget is exhausted")' 'apiError(w, 429, "rate_limit_error", "yard: the task'"'"'s "+lim.Limit+" budget is exhausted")'
# (revokeKeepsServing, dropping `active = false`, is equivalent: Close cuts every connection and the ledger
#  refuses an ended attempt; not listed.)
# noClamp: the output is not clamped to what the reservation allowed
mut noClamp 'req["max_tokens"] = json.RawMessage(fmt.Sprint(out))' '_ = out'
echo "caught $caught of $total"
[ $caught = $total ]
