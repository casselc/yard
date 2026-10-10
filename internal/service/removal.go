package service

import "fmt"

// RemovalStages is the manual operator path around the lifecycle's Removed
// fence. Session effects settle before backend leftovers are cleaned, and
// project key cleanup is awaited only AFTER those leftovers disappear.
// Callbacks must be idempotent; errors never imply cleanup was completed.
type RemovalStages struct {
	Fence, SessionSettled, Cleanup, ProjectSettled func() error
}

func (s RemovalStages) Run() error {
	for _, stage := range []struct {
		name string
		run  func() error
	}{
		{"fence", s.Fence}, {"session", s.SessionSettled},
		{"cleanup", s.Cleanup}, {"project", s.ProjectSettled},
	} {
		if stage.run == nil {
			return fmt.Errorf("removal: missing %s stage", stage.name)
		}
		if err := stage.run(); err != nil {
			return fmt.Errorf("removal %s: %w", stage.name, err)
		}
	}
	return nil
}
