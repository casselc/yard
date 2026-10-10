package lifecycle

// Model-based replay: the exit criterion "the yard-ctl state machine is
// driven by the same transitions". testdata/traces/*.itf.json are quint run
// --mbt traces of spec/sr0/lifecycle.qnt (see spec/sr0/gen_traces.sh). For
// every step the test applies the same action with the same nondeterministic
// picks to Ctl and checks that Ctl equals the model's controller state
// afterwards. The environment (instances, artifacts, copies in flight) is
// the model's own: observations Ctl needs are read from the trace, as the
// Machine reads them from the backends. Every step is also committed to a
// SQLite Store, and a CtlCrash reloads Ctl from it.

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/casselc/observability/quintgo/connect"
	"github.com/casselc/observability/quintgo/itf"
)

// ----------------------------------------------------------- ITF decoding

// Per-model abstraction from quintgo's typed ITF values to the controller's
// existing projection. Transport decoding and step dispatch are generic.
func itfProjection(v itf.Value) any {
	switch v.Kind {
	case itf.Int:
		if v.I == nil || !v.I.IsInt64() {
			panic("model integer does not fit the controller's int64")
		}
		return v.I.Int64()
	case itf.Bool:
		return v.B
	case itf.Str:
		return v.S
	case itf.List, itf.Set, itf.Tuple:
		out := []any{}
		for _, e := range v.Elems {
			out = append(out, itfProjection(e))
		}
		return out
	case itf.Record:
		out := map[string]any{}
		for k, e := range v.Fields {
			out[k] = itfProjection(e)
		}
		return out
	case itf.Map:
		out := map[string]any{}
		for _, pair := range v.Pairs {
			out[fmt.Sprint(itfProjection(pair[0]))] = itfProjection(pair[1])
		}
		return out
	case itf.Variant:
		if v.Inner == nil || (v.Inner.Kind == itf.Tuple && len(v.Inner.Elems) == 0) {
			return v.Tag
		}
		return map[string]any{"tag": v.Tag, "value": itfProjection(*v.Inner)}
	default:
		panic(fmt.Sprintf("unsupported controller projection kind %v", v.Kind))
	}
}

// Scripted traces infer record-valued picks (notably an in-flight copy).
// quintgo.FromGo intentionally converts scalars only; this is our binding.
func driverPick(v any) (itf.Value, error) {
	if record, ok := v.(map[string]any); ok {
		out := itf.Value{Kind: itf.Record, Fields: map[string]itf.Value{}}
		for k, value := range record {
			field, err := driverPick(value)
			if err != nil {
				return itf.Value{}, err
			}
			out.Fields[k] = field
		}
		return out, nil
	}
	return itf.FromGo(v)
}

type qState struct {
	y      map[string]any
	action string
	picks  map[string]any
	vars   map[string]itf.Value // original typed model variables, for quintgo's driver
}

func loadTrace(t *testing.T, path string) []qState {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if b, err = io.ReadAll(zr); err != nil {
			t.Fatal(err)
		}
		if err := zr.Close(); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := itf.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	var out []qState
	for _, s := range raw.States {
		y, ok := s.Vars["y"]
		if !ok {
			break // a `.fail()` test's blocked step: the run ends here
		}
		q := qState{y: itfProjection(y).(map[string]any), action: s.Action, vars: s.Vars}
		if q.action == "" {
			q.action = q.y["last"].(string) // quint test traces carry no mbt metadata
		} else {
			q.picks = map[string]any{}
			for k, v := range s.Picks {
				q.picks[k] = itfProjection(v)
			}
		}
		out = append(out, q)
	}
	for i := 1; i < len(out); i++ {
		if out[i].picks == nil {
			out[i].picks = inferPicks(out[i-1], out[i])
		}
	}
	return out
}

// inferPicks recovers an action's arguments from the state change, for
// traces without mbt::nondetPicks (quint test --out-itf).
func inferPicks(pre, post qState) map[string]any {
	p := map[string]any{}
	var sess []string
	for s := range rec(post.y["rows"]) {
		sess = append(sess, s)
	}
	sort.Strings(sess)
	p["s"] = sess[0]
	for _, s := range sess {
		for _, k := range []string{"rows", "obs", "drivers", "world", "probe"} {
			if !reflect.DeepEqual(rec(pre.y[k])[s], rec(post.y[k])[s]) {
				p["s"] = s
			}
		}
	}
	s := p["s"].(string)
	drv := func(q qState) []any { return set(rec(q.y["drivers"])[s]) }
	for pk, pv := range rec(post.y["proj"]) {
		if !reflect.DeepEqual(pv, rec(pre.y["proj"])[pk]) {
			p["p"] = pk
		}
	}
	switch post.action {
	case "RecoverProjOps":
		for k, o := range rec(post.y["ops"]) {
			if !reflect.DeepEqual(o, rec(pre.y["ops"])[k]) {
				p["p"] = rec(o)["sess"]
			}
		}
	case "ResumeConsume", "ResumeConsumeForce":
		p["tok"] = i64(rec(rec(pre.y["rows"])[s])["token"])
		for _, d := range drv(post) {
			if !slices.ContainsFunc(drv(pre), func(x any) bool { return x == d }) {
				p["d"] = d
			}
		}
	case "ResumeReject":
		p["tok"], p["d"] = int64(-1), "msg"
	case "ResumeMint", "ResumeComplete", "ResumeAbort", "ResumeFail", "ResumeLoadKey", "ResumeKeyDone":
		p["d"] = drv(pre)[0]
	case "OpLand", "OpLandAnswerLost", "OpLandPartial", "OpLose":
		have := map[string]bool{}
		for _, c := range set(post.y["copies"]) {
			have[fmt.Sprint(c)] = true
		}
		for _, c := range set(pre.y["copies"]) {
			if !have[fmt.Sprint(c)] {
				p["c"] = c
			}
		}
	case "OpTimeout", "OpResolve", "OpRetry":
		for k, o := range rec(post.y["ops"]) {
			if !reflect.DeepEqual(o, rec(pre.y["ops"])[k]) {
				p["id"] = i64(rec(o)["id"])
			}
		}
	}
	return p
}

func i64(x any) int64 { return x.(int64) }
func str(x any) string {
	if m, ok := x.(map[string]any); ok {
		return m["tag"].(string)
	}
	return x.(string)
}
func rec(x any) map[string]any { return x.(map[string]any) }
func set(x any) []any          { return x.([]any) }

// ---------------------------------------------- model state, normalised

// norm is the controller state in one comparable shape.
type norm struct {
	Clock, Inc, NextOp, NextToken int64
	Up                            bool
	Rows                          map[string]Row
	Ops                           map[int64]Op
	Drivers                       map[string][]string
	Obs                           map[string]Obs
	Projects                      map[string]Proj
	Probes                        map[string]Probe
}

func modelNorm(y map[string]any) norm {
	n := norm{Clock: i64(y["clock"]), Inc: i64(y["ctlInc"]), NextOp: i64(y["nextOp"]),
		NextToken: i64(y["nextToken"]), Up: y["ctlUp"].(bool),
		Rows: map[string]Row{}, Ops: map[int64]Op{}, Drivers: map[string][]string{}, Obs: map[string]Obs{},
		Projects: map[string]Proj{}, Probes: map[string]Probe{}}
	for id, pv := range rec(y["proj"]) {
		p := rec(pv)
		n.Projects[id] = Proj{Phase: KPhase(str(p["phase"])), Op: i64(p["op"]), Loaded: p["loaded"].(bool)}
	}
	for id, pv := range rec(y["probe"]) {
		p := rec(pv)
		n.Probes[id] = Probe{Pending: p["pending"].(bool), ReqAt: i64(p["reqAt"]), Inst: i64(p["inst"]), Gen: i64(p["gen"]),
			Answered: p["answered"].(bool), Alive: p["alive"].(bool)}
	}
	for id, rv := range rec(y["rows"]) {
		r := rec(rv)
		n.Rows[id] = Row{ID: id, State: State(str(r["state"])), Kind: r["kind"].(string), Gen: i64(r["gen"]),
			Phase: Phase(str(r["phase"])), Inst: i64(r["inst"]), Ckpt: i64(r["ckpt"]), Op: i64(r["op"]),
			Token: i64(r["token"]), CredEpoch: i64(r["credEpoch"]), DecidedAt: i64(r["decidedAt"]),
			DecidedSeq: i64(r["decidedSeq"]), QuiescedAt: i64(r["quiescedAt"]), SuspendedAt: i64(r["suspendedAt"]),
			Resumes: i64(r["resumes"]), Inbox: i64(r["inbox"]), Force: r["force"].(bool), Drift: r["drift"].(bool)}
	}
	for _, ov := range rec(y["ops"]) {
		o := rec(ov)
		n.Ops[i64(o["id"])] = Op{ID: i64(o["id"]), Kind: OpKind(str(o["kind"])), Sess: o["sess"].(string),
			Gen: i64(o["gen"]), Arg: i64(o["arg"]), St: OpSt(str(o["st"])), SentAt: i64(o["sentAt"]),
			Attempts: i64(o["attempts"]), Inc: i64(o["inc"]), Force: o["force"].(bool)}
	}
	for s, dv := range rec(y["drivers"]) {
		ds := []string{}
		for _, d := range set(dv) {
			ds = append(ds, d.(string))
		}
		sort.Strings(ds)
		n.Drivers[s] = ds
	}
	for s, ov := range rec(y["obs"]) {
		o := rec(ov)
		n.Obs[s] = Obs{Pending: o["pending"].(bool), ReqAt: i64(o["reqAt"]), Seq: i64(o["seq"]),
			SeenAt: i64(o["seenAt"]), AnsReqAt: i64(o["ansReqAt"])}
	}
	return n
}

func ctlNorm(c *Ctl) norm {
	n := norm{Clock: c.Clock, Inc: c.Inc, NextOp: c.NextOp, NextToken: c.NextToken, Up: c.Up,
		Rows: map[string]Row{}, Ops: map[int64]Op{}, Drivers: map[string][]string{}, Obs: map[string]Obs{},
		Projects: map[string]Proj{}, Probes: map[string]Probe{}}
	for id, r := range c.Rows {
		r.Class, r.ConsumedAt, r.Project = "", 0, "" // Go-only fields
		n.Rows[id] = r
	}
	for id, p := range c.Projects {
		n.Projects[id] = p
	}
	for id, o := range c.Ops {
		o.Bytes = 0
		n.Ops[id] = o
	}
	for s := range c.Rows {
		n.Drivers[s] = append([]string{}, c.DriverSet(s)...)
		n.Obs[s] = c.Obs[s]
		n.Probes[s] = c.Probes[s]
	}
	return n
}

// --------------------------------------------- the model's environment

func (q qState) world(s string) map[string]any { return rec(rec(q.y["world"])[s]) }

func (q qState) hasInst(s string, name int64) bool {
	for _, i := range set(q.world(s)["insts"]) {
		if i64(rec(i)["name"]) == name {
			return true
		}
	}
	return false
}

func (q qState) instRunning(s string, name int64) bool {
	for _, i := range set(q.world(s)["insts"]) {
		if i64(rec(i)["name"]) == name && str(rec(i)["st"]) == "Running" {
			return true
		}
	}
	return false
}

// anyAwake is Quint awake: an instance running and not frozen.
func (q qState) anyAwake(s string) bool {
	for _, i := range set(q.world(s)["insts"]) {
		if str(rec(i)["st"]) == "Running" && !rec(i)["frozen"].(bool) {
			return true
		}
	}
	return false
}

// frozen: instance name exists and is frozen (Quint OPause observation).
func (q qState) frozen(s string, name int64) (exists, frozen bool) {
	for _, i := range set(q.world(s)["insts"]) {
		if i64(rec(i)["name"]) == name {
			return true, rec(i)["frozen"].(bool)
		}
	}
	return false, false
}

func (q qState) settled(id int64) bool {
	for _, c := range set(q.y["copies"]) {
		if i64(rec(c)["op"]) == id {
			return false
		}
	}
	return true
}

func (q qState) ckptOk(s string, ckpt int64) bool {
	for _, a := range set(q.y["artifacts"]) {
		a := rec(a)
		if a["sess"].(string) == s && i64(a["ckpt"]) == ckpt && a["ok"].(bool) {
			return true
		}
	}
	return false
}

func (q qState) hasArtifact(s string, ckpt int64) bool {
	for _, a := range set(q.y["artifacts"]) {
		a := rec(a)
		if a["sess"].(string) == s && i64(a["ckpt"]) == ckpt {
			return true
		}
	}
	return false
}

func (q qState) holdsEpoch(s string, e int64) bool {
	for _, c := range set(q.world(s)["creds"]) {
		if i64(rec(c)["epoch"]) == e {
			return true
		}
	}
	return false
}

// replayProject is the model's PROJECT const of the trace being replayed
// (session -> project; set by replayInit).
var replayProject map[string]string

func (q qState) mounted(s string) bool { return q.world(s)["mounted"].(bool) }

func (q qState) keyLoaded(p string) bool { return rec(q.y["keys"])[p].(bool) }

// observedDone is Quint observedDone: the backend's resolving observation.
func (q qState) observedDone(o Op) bool {
	switch o.Kind {
	case OLoadKey:
		return q.keyLoaded(replayProject[o.Sess])
	case OUnmount:
		for s, p := range replayProject {
			if p == o.Sess && q.mounted(s) {
				return false
			}
		}
		return true
	case OUnloadKey:
		return !q.keyLoaded(o.Sess)
	case OQuiesce:
		return !q.instRunning(o.Sess, o.Arg)
	case OUnquiesce:
		_, fr := q.frozen(o.Sess, o.Arg)
		return q.instRunning(o.Sess, o.Arg) && !fr
	case OPause:
		ex, fr := q.frozen(o.Sess, o.Arg)
		return ex && fr
	case OUnpause:
		ex, fr := q.frozen(o.Sess, o.Arg)
		return ex && !fr
	case ODestroy:
		return !q.hasInst(o.Sess, o.Arg)
	case OCheckpoint:
		return q.ckptOk(o.Sess, o.ID)
	case ORestore:
		return q.hasInst(o.Sess, o.Gen)
	case OMint:
		return q.holdsEpoch(o.Sess, o.Arg)
	case ODelete:
		return !q.hasArtifact(o.Sess, o.Arg)
	}
	panic(o.Kind)
}

// ------------------------------------------------------------ the replay

// replayCfg mirrors the constants of the design instances (lifecycle.qnt
// modules design, design2, designPause and designKeys): the class of a
// session is its id.
func replayCfg(rows map[string]Row) Config {
	cfg := Config{OpTimeout: 2, MaxAttempts: 2, Clients: []string{"msg", "timer"},
		Policies: map[string]Policy{
			"s1": {KeepWarm: false, IdleAfter: 2, MaxAge: 3},
			"s2": {KeepWarm: true, IdleAfter: 2, MaxAge: 3},
			"p1": {KeepWarm: false, IdleAfter: 2, MaxAge: 3, Pause: true, SuspendHold: 1},
			"k1": {KeepWarm: false, IdleAfter: 2, MaxAge: 3},
			"k2": {KeepWarm: false, IdleAfter: 2, MaxAge: 3},
		}, MaxGen: 2, MaxOps: 16, MaxTokens: 4}
	if _, keys := rows["k1"]; keys {
		cfg.MaxOps = 20
	}
	return cfg
}

// projectsOf is the PROJECT const of the instance the sessions belong to:
// designKeys (k1, k2 share "pa"), design2 (s1 has "w1", s2 none), others none.
func projectsOf(rows map[string]Row) map[string]string {
	p := map[string]string{}
	for id := range rows {
		p[id] = ""
	}
	for _, k := range []string{"k1", "k2"} {
		if _, ok := rows[k]; ok {
			p[k] = "pa"
		}
	}
	if _, ok := rows["s2"]; ok {
		p["s1"] = "w1"
	}
	return p
}

func replayInit(t *testing.T, first qState) *Ctl {
	m := modelNorm(first.y)
	c := NewCtl(replayCfg(m.Rows))
	replayProject = projectsOf(m.Rows)
	for id, r := range m.Rows {
		c.AddSession(id, id, r.Kind, replayProject[id])
	}
	if got := ctlNorm(c); !reflect.DeepEqual(got, m) {
		t.Fatalf("init differs:\n go    %+v\n model %+v", got, m)
	}
	return c
}

// step applies the model's action at pre -> post to c. It returns the
// Effects (sends must match the copies the model created).
func step(c *Ctl, pre, post qState) ([]Effect, error) {
	p := post.picks
	s, _ := p["s"].(string)
	d, _ := p["d"].(string)
	pj, _ := p["p"].(string)
	var id, tok int64
	if v, ok := p["id"]; ok {
		id = i64(v)
	}
	if v, ok := p["tok"]; ok {
		tok = i64(v)
	}
	r := c.Rows[s]
	switch post.action {
	// environment: nothing for yard-ctl, or only an answer / event
	case "Tick":
		c.Tick()
		return nil, nil
	case "Activity", "WriteIssue", "WriteLand", "WriteLandAckLost", "InstanceCrash",
		"OpLandAnswerLost", "OpLandPartial", "OpLose", "WorkspaceEdit", "ProbeExec":
		return nil, nil
	case "OpLand":
		cp := rec(p["c"])
		op := c.Ops[i64(cp["op"])]
		out := AnsError
		if post.observedDone(op) {
			out = AnsDone
		} else if str(rec(rec(post.y["ops"])[strconv.FormatInt(op.ID, 10)])["st"]) == "Refused" {
			out = AnsRefused
		}
		c.OpAnswer(op.ID, i64(cp["inc"]), out, 0)
		return nil, nil
	case "ProbeAnswer":
		return nil, c.ProbeAnswer(s, rec(rec(post.y["probe"])[s])["alive"].(bool))
	case "ProbeReq":
		return nil, c.ProbeReq(s)
	case "ProbeTimeout":
		return nil, c.ProbeTimeout(s)
	case "LostDetect":
		return c.LostDetect(s)
	case "ResumeConsumeForce":
		return c.ResumeConsume(s, d, tok, true)
	case "ResumeLoadKey":
		return c.ResumeLoadKey(s, d)
	case "ResumeKeyDone":
		return c.ResumeKeyDone(s, d)
	case "KeyUnloadBegin":
		return c.KeyUnloadBegin(pj)
	case "KeyUnmountDone":
		return c.KeyUnmountDone(pj)
	case "KeyUnloadDone":
		effs, err := c.KeyUnloadDone(pj)
		return effs, err
	case "KeyUnloadAbort":
		return nil, c.KeyUnloadAbort(pj)
	case "RecoverProjOps":
		return nil, c.RecoverProjOps(pj)
	case "Remove":
		// stepRemove picks the session as rs (its own nondet; s is ctlStep's)
		if rs, ok := p["rs"].(string); ok {
			s, r = rs, c.Rows[rs]
		}
		return c.Remove(s, pre.hasInst(s, r.Inst))
	case "MessageArrive":
		return nil, c.MessageArrive(s)
	case "ObsAnswer":
		return nil, c.ObsAnswer(s, i64(pre.world(s)["actSeq"]))
	case "CtlCrash":
		return nil, c.CtlCrash()
	case "CtlRestart":
		return nil, c.CtlRestart()
	// controller
	case "OpTimeout":
		return nil, c.OpTimeout(id)
	case "OpResolve":
		return nil, c.OpResolve(id, pre.settled(id), pre.observedDone(c.Ops[id]))
	case "OpRetry":
		return c.OpRetry(id)
	case "RecoverOps":
		return nil, c.RecoverOps(s)
	case "Adopt":
		return nil, c.Adopt(s)
	case "ObsReq":
		return nil, c.ObsReq(s)
	case "GoIdle":
		return nil, c.GoIdle(s)
	case "Touch":
		return nil, c.Touch(s)
	case "Deliver":
		return nil, c.Deliver(s, pre.hasInst(s, r.Inst) && pre.anyAwake(s))
	case "CredRefresh":
		return c.CredRefresh(s)
	case "SuspendBegin":
		return c.SuspendBegin(s)
	case "SuspendCheckpoint":
		return c.SuspendCheckpoint(s)
	case "SuspendCheckpointRetry":
		return c.SuspendCheckpointRetry(s)
	case "SuspendDestroy":
		return c.SuspendDestroy(s)
	case "SuspendCommit":
		return c.SuspendCommit(s)
	case "SuspendAbort":
		return c.SuspendAbort(s)
	case "SuspendAbortDone":
		return c.SuspendAbortDone(s)
	case "SuspendFail":
		return c.SuspendFail(s, pre.hasInst(s, r.Inst))
	case "PauseBegin":
		return c.PauseBegin(s)
	case "PauseDone":
		return nil, c.PauseDone(s)
	case "UnpauseBegin":
		return c.UnpauseBegin(s)
	case "UnpauseDone":
		return nil, c.UnpauseDone(s)
	case "UnpauseFail":
		return c.UnpauseFail(s, pre.hasInst(s, r.Inst))
	case "ResumeConsume":
		return c.ResumeConsume(s, d, tok, false)
	case "ResumeReject":
		before := ctlNorm(c)
		_, err := c.ResumeConsume(s, d, tok, false)
		if err != ErrTokenRejected {
			return nil, fmt.Errorf("ResumeReject: Go answered %v", err)
		}
		if !reflect.DeepEqual(before, ctlNorm(c)) {
			return nil, fmt.Errorf("ResumeReject changed the state")
		}
		return nil, nil
	case "ResumeMint":
		return c.ResumeMint(s, d, pre.hasInst(s, r.Gen))
	case "ResumeComplete":
		return c.ResumeComplete(s, d, pre.hasInst(s, r.Gen))
	case "ResumeAbort":
		return c.ResumeAbort(s, d)
	case "ResumeFail":
		return c.ResumeFail(s, d, pre.hasInst(s, r.Gen))
	case "Expire":
		return c.Expire(s)
	}
	return nil, fmt.Errorf("action %q has no Go counterpart in the design", post.action)
}

// sentCopies are the (op, attempt) copies the model added in this step.
func sentCopies(pre, post qState) []string {
	have := map[string]bool{}
	for _, c := range set(pre.y["copies"]) {
		have[fmt.Sprint(c)] = true
	}
	var out []string
	for _, c := range set(post.y["copies"]) {
		if !have[fmt.Sprint(c)] {
			out = append(out, fmt.Sprintf("%d/%d", i64(rec(c)["op"]), i64(rec(c)["attempt"])))
		}
	}
	slices.Sort(out)
	return out
}

func TestReplayQuintTraces(t *testing.T) {
	files, _ := filepath.Glob("testdata/traces/*.itf.json*")
	if len(files) == 0 {
		t.Fatal("no traces in testdata/traces (run spec/sr0/gen_traces.sh)")
	}
	steps, actions := 0, map[string]int{}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			tr := loadTrace(t, f)
			c := replayInit(t, tr[0])
			st, err := OpenStore(filepath.Join(t.TempDir(), "yard.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			if err := st.Commit(NewCtl(c.Cfg), c); err != nil {
				t.Fatal(err)
			}
			// Explicit per-model binding; no Skip list. Unknown actions fail in
			// quintgo, including newly added environment transitions.
			driver := connect.Driver{Actions: map[string]connect.Handler{}}
			handle := func(s *connect.Step) error {
				pre := qState{y: itfProjection(s.Before["y"]).(map[string]any)}
				post := qState{y: itfProjection(s.After["y"]).(map[string]any), action: s.Action, picks: map[string]any{}}
				for k, v := range s.Picks {
					post.picks[k] = itfProjection(v)
				}
				prev := c.Clone()
				effs, err := step(c, pre, post)
				if err != nil {
					return err
				}
				var sends []string
				for _, e := range effs {
					if e.Kind == EffSend {
						sends = append(sends, fmt.Sprintf("%d/%d", e.Op, c.Ops[e.Op].Attempts))
					}
				}
				slices.Sort(sends)
				if want := sentCopies(pre, post); !slices.Equal(sends, want) {
					return fmt.Errorf("Go sends %v, model sent %v", sends, want)
				}
				if err := st.Commit(prev, c); err != nil {
					return fmt.Errorf("commit: %w", err)
				}
				if post.action == "CtlCrash" {
					// the process is gone: everything comes back from SQLite
					c2, err := st.Restore(c.Cfg)
					if err != nil {
						return err
					}
					c2.Clock = c.Clock
					if !durableEqual(c, c2) {
						return fmt.Errorf("SQLite lost durable state")
					}
					c = c2
				}
				steps++
				actions[post.action]++
				return nil
			}
			for _, action := range []string{
				"Tick", "Activity", "WriteIssue", "WriteLand", "WriteLandAckLost", "InstanceCrash",
				"OpLandAnswerLost", "OpLandPartial", "OpLose", "WorkspaceEdit", "ProbeExec", "OpLand",
				"ProbeAnswer", "ProbeReq", "ProbeTimeout", "LostDetect", "ResumeConsumeForce", "ResumeLoadKey",
				"ResumeKeyDone", "KeyUnloadBegin", "KeyUnmountDone", "KeyUnloadDone", "KeyUnloadAbort", "RecoverProjOps",
				"Remove", "MessageArrive", "ObsAnswer", "CtlCrash", "CtlRestart", "OpTimeout", "OpResolve", "OpRetry",
				"RecoverOps", "Adopt", "ObsReq", "GoIdle", "Touch", "Deliver", "CredRefresh", "SuspendBegin",
				"SuspendCheckpoint", "SuspendCheckpointRetry", "SuspendDestroy", "SuspendCommit", "SuspendAbort",
				"SuspendAbortDone", "SuspendFail", "PauseBegin", "PauseDone", "UnpauseBegin", "UnpauseDone", "UnpauseFail",
				"ResumeConsume", "ResumeReject", "ResumeMint", "ResumeComplete", "ResumeAbort", "ResumeFail", "Expire",
			} {
				driver.Actions[action] = handle
			}
			driver.Check = func(s *connect.Step) error {
				want := modelNorm(itfProjection(s.After["y"]).(map[string]any))
				if got := ctlNorm(c); !reflect.DeepEqual(got, want) {
					return fmt.Errorf("Go state differs from model\n go %+v\n model %+v", got, want)
				}
				return nil
			}
			generic := &itf.Trace{}
			for i, q := range tr {
				state := itf.State{Index: i, Action: q.action, Vars: q.vars, Picks: map[string]itf.Value{}}
				for k, v := range q.picks {
					pick, err := driverPick(v)
					if err != nil {
						t.Fatal(err)
					}
					state.Picks[k] = pick
				}
				generic.States = append(generic.States, state)
			}
			if err := driver.Replay(generic); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Logf("replayed %d steps over %d traces; actions: %v", steps, len(files), actions)
}
