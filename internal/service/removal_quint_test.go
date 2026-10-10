package service

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/casselc/observability/quintgo/qobs"
	"github.com/casselc/observability/quintgo/validate"
	"yard/internal/lifecycle"
)

func TestOperatorRemovalRuntimeConformance(t *testing.T) {
	quint, err := exec.LookPath("quint")
	if err != nil {
		t.Skip("quint CLI required for removal order monitor")
	}
	binding, err := filepath.Abs("../../spec/sr0/operator_remove_binding.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, old := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup-before-key-wait", true: "old-key-wait-before-cleanup"}[old], func(t *testing.T) {
			r, wr := newProjRig(t, behavior{listens: true})
			r.up()
			m, _ := machine(t, r, lifecycle.Policy{KeepWarm: true, IdleAfter: 1 << 50, MaxAge: 3_600_000})
			if err := m.AddSession("web", "svc", lifecycle.KindService, "app"); err != nil {
				t.Fatal(err)
			}
			jid, err := r.f.JID(r.name(0))
			if err != nil {
				t.Fatal(err)
			}
			if err := r.f.RemoveJail(jid); err != nil {
				t.Fatal(err)
			}
			ctx := qobs.Thread(context.Background())
			sink := &qobs.MemorySink{}
			rec := qobs.NewRecorder(sink, qobs.WithActor("web"), qobs.WithProcess("test"))
			stages := RemovalStages{
				Fence: func() error {
					if err := m.Remove(ctx, "web"); err != nil {
						return err
					}
					rec.Record(ctx, "fence", nil, "removed", m.State().Rows["web"].State == lifecycle.Removed)
					return nil
				},
				SessionSettled: func() error {
					m.Wait()
					done := lifecycle.SessionOpsSettled(m.State(), "web")
					rec.Record(ctx, "session_settled", nil, "done", done)
					if !done {
						return errors.New("session effects unresolved")
					}
					return nil
				},
				Cleanup: func() error {
					rec.Record(ctx, "cleanup_request", nil)
					if err := r.b.CleanupSession(ctx, "web", 0); err != nil {
						return err
					}
					wr.z.mu.Lock()
					views := wr.z.busy[projDS+"/web"]
					wr.z.mu.Unlock()
					rec.Record(ctx, "cleanup_effect", nil, "views", views)
					rec.Record(ctx, "cleanup_answer", nil)
					return nil
				},
				ProjectSettled: func() error {
					rec.Record(ctx, "project_wait_request", nil)
					if err := wr.w.Unmount(ctx, nil, "app"); err != nil {
						rec.Record(ctx, "project_wait_failed", nil)
						return err
					}
					if err := wr.w.UnloadKey(ctx, nil, "app"); err != nil {
						rec.Record(ctx, "project_wait_failed", nil)
						return err
					}
					loaded, _ := wr.z.state(projDS + "/web")
					rec.Record(ctx, "project_settled", nil, "loaded", loaded)
					return nil
				},
			}
			if old {
				stages.Cleanup, stages.ProjectSettled = stages.ProjectSettled, stages.Cleanup
			}
			err = stages.Run()
			if old && err == nil {
				t.Fatal("busy project unexpectedly completed before cleanup")
			}
			if !old && err != nil {
				t.Fatal(err)
			}
			checker, err := validate.NewChecker(binding, validate.Options{Quint: quint, Backend: "typescript", Dir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			report, err := checker.Check(ctx, sink.Steps())
			if err != nil {
				t.Fatal(err)
			}
			if report.OK() == old {
				t.Fatal(report.Summary())
			}
			if old && (len(report.Actors) != 1 || report.Actors[0].Failure == nil || report.Actors[0].Failure.Kind != "disabled") {
				t.Fatal("expected illegal pre-cleanup project wait: " + report.Summary())
			}
		})
	}
}
