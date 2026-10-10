package service

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestRemovalProjectFailureRetainsRecordForRetry(t *testing.T) {
	r, wr := newProjRig(t, behavior{listens: true})
	r.up()
	suspendBackend(t, r)
	ctx := context.Background()
	failed := errors.New("project wait interrupted")
	first := true
	stages := RemovalStages{
		Fence: func() error { return nil }, SessionSettled: func() error { return nil },
		Cleanup: func() error { return r.b.CleanupSession(ctx, "web", 1) },
		ProjectSettled: func() error {
			if first {
				first = false
				return failed
			}
			if err := wr.w.Unmount(ctx, nil, "app"); err != nil {
				return err
			}
			if err := wr.w.UnloadKey(ctx, nil, "app"); err != nil {
				return err
			}
			return r.b.Down(ctx, "web", 1)
		},
	}
	if err := stages.Run(); !errors.Is(err, failed) {
		t.Fatalf("first removal: %v", err)
	}
	if _, err := r.b.LoadSession("web"); err != nil {
		t.Fatalf("retry metadata lost: %v", err)
	}
	// An outstanding lifecycle delete/observation must still resolve after
	// physical cleanup, before the interrupted project wait is retried.
	if err := r.b.Delete(ctx, "web", 2); err != nil {
		t.Fatal(err)
	}
	if exists, err := r.b.Exists(ctx, "web", 2); exists || err != nil {
		t.Fatalf("cleaned checkpoint: exists=%v err=%v", exists, err)
	}
	if err := stages.Run(); err != nil {
		t.Fatalf("retry removal: %v", err)
	}
	if _, err := r.b.LoadSession("web"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("settled metadata not retired: %v", err)
	}
}

func TestRemovalCleansOrphansBeforeAwaitingProject(t *testing.T) {
	removed, settled, views, key := false, false, true, true
	stages := RemovalStages{
		Fence: func() error { removed = true; return nil },
		SessionSettled: func() error {
			if !removed {
				return errors.New("not fenced")
			}
			settled = true
			return nil
		},
		Cleanup: func() error {
			if !settled {
				return errors.New("session effects unresolved")
			}
			views = false
			return nil
		},
		ProjectSettled: func() error {
			if views {
				return errors.New("busy: orphan views block key unload")
			}
			key = false
			return nil
		},
	}
	if err := stages.Run(); err != nil {
		t.Fatal(err)
	}
	if views || key {
		t.Fatal("resources not cleaned")
	}
	// Positive control for the exact old operator order: waiting on project
	// cleanup first is blocked, not evidence that the key can be released.
	views = true
	if err := stages.ProjectSettled(); err == nil {
		t.Fatal("busy project unexpectedly completed")
	}
}

func TestRemovalFailureDoesNotReleaseProjectKey(t *testing.T) {
	failed := errors.New("cleanup unknown")
	released := false
	err := (RemovalStages{
		Fence: func() error { return nil }, SessionSettled: func() error { return nil },
		Cleanup: func() error { return failed }, ProjectSettled: func() error { released = true; return nil },
	}).Run()
	if !errors.Is(err, failed) || released {
		t.Fatalf("unknown cleanup: %v, released=%v", err, released)
	}
}
