package keysvc

// Model-based replay: testdata/traces/*.itf.json.gz are ITF traces of
// spec/keys/keys.qnt (design instance): scripted runs and random runs of
// stepKeysvc (spec/keys/gen_traces.sh). For every step the test applies the
// same action with the same nondeterministic picks to Ctl and checks that
// Ctl equals the model's controller state (clock, incarnation, counters,
// sessions, spill keys, ops). Observations Ctl needs (an answer's outcome,
// a resolution's observation, whether the instance runs) are read from the
// trace, as Service reads them from halo_serve. Every step is committed to
// a SQLite Store; a crash or reboot reloads Ctl from it at the restart.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func itfVal(x any) any {
	switch v := x.(type) {
	case map[string]any:
		if b, ok := v["#bigint"]; ok {
			n, err := strconv.ParseInt(b.(string), 10, 64)
			if err != nil {
				panic(err)
			}
			return n
		}
		if s, ok := v["#set"]; ok {
			out := []any{}
			for _, e := range s.([]any) {
				out = append(out, itfVal(e))
			}
			return out
		}
		if m, ok := v["#map"]; ok {
			out := map[string]any{}
			for _, kv := range m.([]any) {
				p := kv.([]any)
				out[fmt.Sprint(itfVal(p[0]))] = itfVal(p[1])
			}
			return out
		}
		if t, ok := v["#tup"]; ok {
			out := []any{}
			for _, e := range t.([]any) {
				out = append(out, itfVal(e))
			}
			return out
		}
		if tag, ok := v["tag"]; ok {
			if val := itfVal(v["value"]); val != nil {
				if l, ok := val.([]any); !ok || len(l) > 0 {
					return map[string]any{"tag": tag, "value": val}
				}
			}
			return tag
		}
		out := map[string]any{}
		for k, e := range v {
			out[k] = itfVal(e)
		}
		return out
	case []any:
		out := []any{}
		for _, e := range v {
			out = append(out, itfVal(e))
		}
		return out
	}
	return x
}

type qState struct {
	y      map[string]any
	action string
	picks  map[string]any
}

func i64(x any) int64                { return x.(int64) }
func rec(x any) map[string]any       { return x.(map[string]any) }
func set(x any) []any                { return x.([]any) }
func (q qState) ops() map[string]any { return rec(q.y["ops"]) }

func loadTrace(t *testing.T, path string) []qState {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if b, err = io.ReadAll(zr); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		States []map[string]any `json:"states"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	var out []qState
	for _, s := range raw.States {
		var q qState
		for k, v := range s {
			switch {
			case strings.HasSuffix(k, "::y") || k == "y":
				q.y = itfVal(v).(map[string]any)
			case k == "mbt::actionTaken":
				q.action = v.(string)
			case k == "mbt::nondetPicks":
				q.picks = map[string]any{}
				for pk, pv := range itfVal(v).(map[string]any) {
					if m, ok := pv.(map[string]any); ok && m["tag"] == "Some" {
						q.picks[pk] = m["value"]
					}
				}
			}
		}
		if q.y == nil {
			break // a .fail() step: the run ends here
		}
		if q.action == "" {
			q.action = q.y["last"].(string)
		}
		out = append(out, q)
	}
	for i := 1; i < len(out); i++ {
		inf := inferPicks(out[i-1], out[i])
		if out[i].picks == nil {
			out[i].picks = inf
		}
		if _, ok := out[i].picks["s"]; !ok && inf["s"] != nil { // actions with a literal session (stepSpill, stepRevoke)
			out[i].picks["s"] = inf["s"]
		}
	}
	return out
}

// inferPicks recovers the arguments of a scripted step from the state change.
func inferPicks(pre, post qState) map[string]any {
	p := map[string]any{}
	for s, v := range rec(post.y["ss"]) {
		if !reflect.DeepEqual(v, rec(pre.y["ss"])[s]) {
			p["s"] = s
		}
	}
	for id, o := range post.ops() {
		if po, had := pre.ops()[id]; !had || !reflect.DeepEqual(o, po) {
			p["id"] = rec(o)["id"]
			p["k"] = rec(o)["key"]
		}
	}
	for id, k := range rec(post.y["keys"]) {
		if !reflect.DeepEqual(k, rec(pre.y["keys"])[id]) {
			p["k"] = rec(k)["id"]
		}
	}
	have := map[string]bool{}
	for _, c := range set(post.y["copies"]) {
		have[fmt.Sprint(c)] = true
	}
	for _, c := range set(pre.y["copies"]) {
		if !have[fmt.Sprint(c)] {
			p["c"] = c
		}
	}
	if _, ok := p["c"]; !ok && len(set(pre.y["copies"])) > 0 {
		p["c"] = set(pre.y["copies"])[0]
	}
	return p
}

// norm is the controller state in one comparable shape.
type norm struct {
	Clock, Inc, NextOp, NextKey int64
	Up                          bool
	Keys                        map[int64]Key
	Sess                        map[string]Sess
	Ops                         map[int64]Op
}

func modelNorm(y map[string]any) norm {
	n := norm{Clock: i64(y["clock"]), Inc: i64(y["ctlInc"]), NextOp: i64(y["nextOp"]), NextKey: i64(y["nextKey"]),
		Up: y["ctlUp"].(bool), Keys: map[int64]Key{}, Sess: map[string]Sess{}, Ops: map[int64]Op{}}
	for _, kv := range rec(y["keys"]) {
		k := rec(kv)
		if k["cons"] != "spill" {
			continue
		}
		n.Keys[i64(k["id"])] = Key{ID: i64(k["id"]), Subj: k["subj"].(string), Ver: i64(k["ver"]),
			Wrapped: k["wrapped"].(bool), Shredding: k["shredding"].(bool), Shredded: k["shredded"].(bool)}
	}
	for s, rv := range rec(y["ss"]) {
		r := rec(rv)
		n.Sess[s] = Sess{St: SState(r["st"].(string)), Phase: Phase(r["phase"].(string)), Epoch: i64(r["epoch"]),
			Op: i64(r["op"]), Spill: i64(r["spill"]), Resumes: i64(r["resumes"])}
	}
	for _, ov := range rec(y["ops"]) {
		o := rec(ov)
		op := Op{ID: i64(o["id"]), Kind: OpKind(o["kind"].(string)), Subj: o["subj"].(string), Key: i64(o["key"]),
			Ver: i64(o["ver"]), Tep: i64(o["tep"]), Oid: i64(o["oid"]), Use: Use(o["use"].(string)), St: OpSt(o["st"].(string)),
			Attempts: i64(o["attempts"]), Inc: i64(o["inc"]), SentAt: i64(o["sentAt"])}
		if op.Kind == OLoadKey {
			op.Key = 0 // the model's project key id; Go keeps no zfs keys here
		}
		n.Ops[op.ID] = op
	}
	return n
}

func ctlNorm(c *Ctl) norm {
	n := norm{Clock: c.Clock, Inc: c.Inc, NextOp: c.NextOp, NextKey: c.NextKey, Up: c.Up,
		Keys: map[int64]Key{}, Sess: c.Sess, Ops: c.Ops}
	for id, k := range c.Keys {
		k.Ckpt, k.Entry = 0, 0
		n.Keys[id] = k
	}
	return n
}

func replayCfg() Config {
	// keysTest.qnt design: TOKEN_TTL 2, HALO_TTL 5, OP_TIMEOUT 2, MAX_OPS 24,
	// MAX_KEYS 7, MAX_EPOCH 4, MAX_ATTEMPTS 2
	return Config{TokenTTL: 2, HaloTTL: 5, OpTimeout: 2, MaxAttempts: 2, MaxOps: 24, MaxKeys: 7, MaxEpoch: 4}
}

func pickS(q qState) string { return q.picks["s"].(string) }
func pickID(q qState) int64 { return q.picks["id"].(int64) }
func pickK(q qState) int64  { return q.picks["k"].(int64) }

func postSt(post qState, id int64) OpSt {
	o, ok := post.ops()[strconv.FormatInt(id, 10)]
	if !ok {
		return ""
	}
	return OpSt(rec(o)["st"].(string))
}

// step applies the trace's action to c. It returns an error if Go refuses
// an action the model took.
func step(c *Ctl, pre, post qState) error {
	var err error
	switch post.action {
	case "Tick", "tickNoRevoke", "tickNoOpen":
		c.Tick()
	case "Reboot", "CtlCrash":
		c.CtlCrash()
	case "CtlRestart":
		err = c.CtlRestart()
	case "HaloRestart", "Replay", "replayStep", "spillReplay", "OpLose", "OpLandDup", "OpLandAnswerLost":
		// environment only (no answer reaches yard-ctl)
	case "OpLand", "revokeCopy", "otherCopy", "lateRevokeCopy":
		cp := rec(post.picks["c"])
		id := i64(cp["op"])
		c.OpAnswer(id, i64(cp["inc"]), postSt(post, id) == Done)
	case "OpTimeout":
		err = c.OpTimeout(pickID(post))
	case "OpResolve":
		err = c.OpResolve(pickID(post), true, postSt(post, pickID(post)) == Done)
	case "OpRetry":
		_, err = c.OpRetry(pickID(post))
	case "OpVerifyRetry":
		_, err = c.OpVerifyRetry(pickID(post), postSt(post, pickID(post)) == Done)
	case "RecoverOps":
		err = c.RecoverOps()
	case "SuspendBegin":
		s := pickS(post)
		_, err = c.SuspendBegin(s, rec(pre.y["inst"])[s].(bool), 0, 0)
	case "SuspendSpill":
		_, err = c.SuspendSpill(pickS(post))
	case "SuspendReseal":
		_, err = c.SuspendReseal(pickS(post))
	case "SuspendCommit":
		err = c.SuspendCommit(pickS(post))
	case "SuspendAbort":
		err = c.SuspendAbort(pickS(post))
	case "RenewOp":
		_, err = c.RenewOp(pickS(post), true) // the model's guard read halo's answer (opOver)
	case "ResumeBegin":
		_, err = c.ResumeBegin(pickS(post))
	case "ResumeLoad":
		_, err = c.ResumeLoad(pickS(post))
	case "ResumeRestore":
		_, err = c.ResumeRestore(pickS(post))
	case "ResumeReopen":
		_, err = c.ResumeReopen(pickS(post))
	case "ResumeComplete":
		err = c.ResumeComplete(pickS(post))
	case "Expire":
		err = c.Expire(pickS(post))
	case "Kill":
		err = c.Kill(pickS(post))
	case "SendRevoke":
		_, err = c.SendRevoke(pickK(post))
	case "ShredSpill":
		err = c.ShredSpill(pickK(post))
	default:
		return fmt.Errorf("action %q not replayed", post.action)
	}
	return err
}

func TestReplayQuintTraces(t *testing.T) {
	files, _ := filepath.Glob("testdata/traces/*.itf.json.gz")
	if len(files) == 0 {
		t.Fatal("no traces (spec/keys/gen_traces.sh)")
	}
	sort.Strings(files)
	steps, actions := 0, map[string]int{}
	for _, f := range files {
		tr := loadTrace(t, f)
		c := NewCtl(replayCfg())
		c.NextKey = 2 // key 1 is the model's project key
		for s := range rec(tr[0].y["ss"]) {
			c.AddSession(s, 1)
		}
		if got, want := ctlNorm(c), modelNorm(tr[0].y); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: init differs:\n go    %+v\n model %+v", f, got, want)
		}
		st, err := OpenStore(filepath.Join(t.TempDir(), "keys.db"))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Commit(NewCtl(c.Cfg), c, func(int64) []byte { return []byte("w") }); err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(tr); i++ {
			prev := c.Clone()
			if err := step(c, tr[i-1], tr[i]); err != nil {
				t.Fatalf("%s step %d %s %v: %v", filepath.Base(f), i, tr[i].action, tr[i].picks, err)
			}
			if err := st.Commit(prev, c, func(int64) []byte { return []byte("w") }); err != nil {
				t.Fatal(err)
			}
			if tr[i].action == "CtlRestart" { // a new process: its state comes from the store
				d, err := st.Load(c.Cfg)
				if err != nil {
					t.Fatal(err)
				}
				d.Clock, d.Up = c.Clock, c.Up
				if !equalDurable(c, d) {
					t.Fatalf("%s step %d: store reload differs", f, i)
				}
				c = d
			}
			if got, want := ctlNorm(c), modelNorm(tr[i].y); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s step %d %s %v:\n go    %+v\n model %+v", filepath.Base(f), i, tr[i].action, tr[i].picks, got, want)
			}
			steps++
			actions[tr[i].action]++
		}
		st.Close()
	}
	t.Logf("replayed %d traces, %d steps; actions %v", len(files), steps, actions)
	for _, a := range []string{"SuspendBegin", "SuspendSpill", "SuspendReseal", "SuspendCommit", "SuspendAbort",
		"ResumeBegin", "ResumeLoad", "ResumeRestore", "ResumeReopen", "ResumeComplete", "Expire", "Kill",
		"SendRevoke", "ShredSpill", "OpVerifyRetry", "RenewOp", "OpResolve", "OpRetry", "RecoverOps", "CtlRestart"} {
		if actions[a] == 0 {
			t.Errorf("action %s never replayed", a)
		}
	}
}
