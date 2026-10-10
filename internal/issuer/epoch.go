package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Session credential epochs (spec/sr0 invariant I3; the lifecycle's X6 row).
//
// A session's epoch lives in its lifecycle row and is bumped when the
// session suspends. A token for the session carries yard_sess and
// yard_epoch. Two checks make a credential from before a suspend useless
// after the resume, whatever its exp:
//   - the issuer mints only for the session's current epoch, so a mint
//     requested before the suspend and answered after it is refused;
//   - VerifyEpoch (the broker side, and the warden's broker-side check)
//     rejects a token whose epoch is below the session's current one, so a
//     token held in a restored VM's memory is dead.

const (
	ClaimSession = "yard_sess"
	ClaimEpoch   = "yard_epoch"
)

// EpochSource reports a session's current credential epoch
// (lifecycle.Machine implements it from the sessions row).
type EpochSource interface {
	Epoch(session string) (epoch int64, ok bool)
}

// ErrStaleEpoch: the token or request is for an earlier epoch of its session.
var ErrStaleEpoch = errors.New("credential epoch is not the session's current epoch")

var sessRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// SetEpochs installs the epoch source; without one, session tokens are refused.
func (is *Issuer) SetEpochs(src EpochSource) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.epochs = src
}

func (is *Issuer) checkEpoch(r *Request) error {
	if r.Session == "" {
		if r.Epoch != 0 {
			return deny("epoch without a session")
		}
		return nil
	}
	if !sessRe.MatchString(r.Session) {
		return deny("session %q", r.Session)
	}
	is.mu.Lock()
	src, skip := is.epochs, is.noEpochCheck
	is.mu.Unlock()
	if skip {
		return nil
	}
	if src == nil {
		return deny("session tokens need an epoch source")
	}
	cur, ok := src.Epoch(r.Session)
	if !ok {
		return deny("unknown session %q", r.Session)
	}
	if r.Epoch != cur {
		return &PolicyError{Reason: fmt.Sprintf("session %s epoch %d (current %d): %v", r.Session, r.Epoch, cur, ErrStaleEpoch),
			Err: ErrStaleEpoch}
	}
	return nil
}

// VerifyEpoch is the broker-side check on a verified token's claims. A
// token without a session claim passes only if requireSession is false. A
// session token passes only if its epoch is the session's current one.
func VerifyEpoch(claims map[string]any, src EpochSource, requireSession bool) error {
	s, has := claims[ClaimSession].(string)
	if !has {
		if requireSession {
			return errors.New("token is not session-scoped")
		}
		return nil
	}
	e, err := claimInt(claims[ClaimEpoch])
	if err != nil {
		return fmt.Errorf("%s: %w", ClaimEpoch, err)
	}
	cur, ok := src.Epoch(s)
	if !ok {
		return fmt.Errorf("unknown session %q", s)
	}
	if e != cur {
		return fmt.Errorf("session %s token epoch %d, current %d: %w", s, e, cur, ErrStaleEpoch)
	}
	return nil
}

func claimInt(v any) (int64, error) {
	switch n := v.(type) {
	case float64:
		if n != float64(int64(n)) {
			return 0, fmt.Errorf("not an integer: %v", n)
		}
		return int64(n), nil
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case json.Number:
		return n.Int64()
	}
	return 0, fmt.Errorf("missing or not a number: %v", v)
}
