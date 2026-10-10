package service

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/casselc/observability/quintgo/qobs"
	"github.com/casselc/observability/quintgo/qtrace"
	"github.com/casselc/observability/quintgo/validate"
	"yard/internal/lifecycle"
)

// Observe real backend calls against the fake OS; effects come from its state,
// not a synthesized good event list. No global recorder/OTel sink is installed.
type loadOrderZFS struct {
	ZFS
	model *fakeZFS
	rec   *qobs.Recorder
}

func (z loadOrderZFS) Zfs(ctx context.Context, lock *os.File, args ...string) (string, error) {
	mount := len(args) > 0 && args[0] == "mount"
	if mount {
		z.rec.Record(ctx, "mount_request", nil)
	}
	out, err := z.ZFS.Zfs(ctx, lock, args...)
	if mount && err == nil {
		z.model.mu.Lock()
		n, readErr := z.model.prop(projDS+"/web", "written@ysr1-web-g1-c2")
		z.model.mu.Unlock()
		if readErr != nil {
			return "", readErr
		}
		written, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64)
		if err != nil {
			return "", err
		}
		z.rec.Record(ctx, "mount_effect", nil, "written", written, "obs.mounted", true, "obs.physical", written)
		z.rec.Record(ctx, "mount_answer", nil)
	}
	return out, err
}

type loadOrderOS struct {
	OS
	rec   *qobs.Recorder
	force bool
}

func (o loadOrderOS) Zfs(ctx context.Context, lock *os.File, args ...string) (string, error) {
	out, err := o.OS.Zfs(ctx, lock, args...)
	if err == nil && strings.Contains(strings.Join(args, " "), "written@") {
		n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		if err != nil {
			return "", err
		}
		o.rec.Record(ctx, "observe", nil, "written", n, "force", o.force)
	}
	return out, err
}

func loadOrderSteps(t *testing.T, oldOrder, edited, force bool) []qtrace.Step {
	t.Helper()
	r, wr := newProjRig(t, behavior{listens: true})
	r.up()
	suspendBackend(t, r)
	if edited {
		if err := wr.z.write(projDS+"/web", 512); err != nil {
			t.Fatal(err)
		}
	}
	ctx := qobs.Thread(opCtx(6))
	if err := wr.w.Unmount(ctx, nil, "app"); err != nil {
		t.Fatal(err)
	}
	if err := wr.w.UnloadKey(ctx, nil, "app"); err != nil {
		t.Fatal(err)
	}
	wr.z.ds[projDS+"/web"].mountWrites = 8192
	sink := &qobs.MemorySink{}
	rec := qobs.NewRecorder(sink, qobs.WithActor("web"), qobs.WithProcess("test"))
	r.b.WS.Z = loadOrderZFS{ZFS: wr.z, model: wr.z, rec: rec}
	r.b.OS = loadOrderOS{OS: r.b.OS, rec: rec, force: force}
	var err error
	if oldOrder {
		// Positive control: the previous composite key-load/mount API order.
		err = r.b.WS.LoadKey(ctx, nil, "app", "web")
	} else {
		err = r.b.LoadKey(ctx, "web")
	}
	if err != nil {
		t.Fatal(err)
	}
	loaded, mounted := wr.z.state(projDS + "/web")
	rec.Record(ctx, "key_ready", nil, "loaded", loaded, "mounted", mounted)
	err = r.b.Restore(ctx, "web", 1, 2, force)
	if (oldOrder || edited) && !force {
		if !errors.Is(err, lifecycle.ErrRefused) {
			t.Fatalf("expected strict refusal: %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	return sink.Steps()
}

func TestLoadOrderRuntimeConformance(t *testing.T) {
	quint, err := exec.LookPath("quint")
	if err != nil {
		t.Skip("quint CLI required for runtime conformance; ordinary backend regression tests still run")
	}
	binding, err := filepath.Abs("../../spec/sr0/load_order_binding.yaml")
	if err != nil {
		t.Fatal(err)
	}
	checker, err := validate.NewChecker(binding, validate.Options{Quint: quint, Backend: "typescript", Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name                     string
		old, edited, force, pass bool
	}{
		{"metadata-only", false, false, false, true},
		{"real-edit-refused", false, true, false, true},
		{"explicit-override", false, true, true, true},
		{"old-load-mount-order", true, false, false, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			steps := loadOrderSteps(t, scenario.old, scenario.edited, scenario.force)
			checker.Options.Dir = t.TempDir() // preserve each scenario's generated modules independently
			report, err := checker.Check(context.Background(), steps)
			if err != nil {
				t.Fatal(err)
			} // a tool error never counts as a caught bug
			if report.OK() != scenario.pass {
				t.Fatal(report.Summary())
			}
			if !scenario.pass && (len(report.Actors) != 1 || report.Actors[0].Conforms != validate.Fail || report.Actors[0].Failure == nil || report.Actors[0].Failure.Kind != "disabled") {
				t.Fatalf("expected illegal early mount, not an unrelated failure: %s", report.Summary())
			}
		})
	}
	// Missing observations must not become a validated partial trace.
	steps := loadOrderSteps(t, false, false, false)
	steps = append(steps[:1:1], steps[2:]...)
	checker.Options.Dir = t.TempDir()
	report, err := checker.Check(context.Background(), steps)
	if err != nil {
		t.Fatal(err)
	}
	issues := len(report.Issues)
	for _, actor := range report.Actors {
		issues += len(actor.Issues)
	}
	if report.OK() || issues == 0 {
		t.Fatalf("missing step accepted: %s", report.Summary())
	}
}
