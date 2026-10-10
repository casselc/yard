package lifecycle

// SessionOpsSettled excludes the project's key-unload work. The operator must
// clean a terminal session's leftover mounts before awaiting that work: a
// missing jail is not evidence that its nullfs views disappeared.
func SessionOpsSettled(c *Ctl, sess string) bool {
	r, ok := c.Rows[sess]
	if !ok {
		return false
	}
	for _, op := range c.Ops {
		if op.Sess == sess && (op.St == Pending || op.St == Unknown) {
			return false
		}
	}
	// Never bypass the removed row's actual destroy-done fence.
	if r.State == Removed && r.Op != 0 && c.opSt(r.Op) != Done {
		return false
	}
	return true
}
