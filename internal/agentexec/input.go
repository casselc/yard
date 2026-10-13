package agentexec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

var inputMu sync.Mutex // one build at a time: concurrent submits of one (commit, change) share the image

// BuildInput builds (once) the read-only ext4 input image: the commit's tree with the change applied, and the change
// itself in .yard-review/change.diff (section 9). It returns the image and the commit it resolved.
func BuildInput(repo, commit, change, imageDir string) (string, string, error) {
	c, err := exec.Command("git", "-C", repo, "rev-parse", "--verify", commit+"^{commit}").Output()
	if err != nil {
		return "", "", fmt.Errorf("commit %q: %v", commit, err)
	}
	commit = strings.TrimSpace(string(c))
	ch := sha256.Sum256([]byte(change))
	path := filepath.Join(imageDir, commit[:16]+"-"+hex.EncodeToString(ch[:8])+"-applied.ext4")
	inputMu.Lock()
	defer inputMu.Unlock()
	if _, err := os.Stat(path); err == nil {
		return path, commit, nil
	}
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		return "", "", err
	}
	tree, err := os.MkdirTemp(imageDir, "tree-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(tree)
	sh := fmt.Sprintf("git -C %q archive %s | tar -x -C %q", repo, commit, tree)
	if out, err := exec.Command("sh", "-c", sh).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("archive: %v: %s", err, out)
	}
	if change != "" {
		ap := exec.Command("git", "apply", "--whitespace=nowarn", "-")
		ap.Dir, ap.Stdin = tree, bytes.NewReader([]byte(change))
		if out, err := ap.CombinedOutput(); err != nil {
			return "", "", fmt.Errorf("the change does not apply to %s: %v: %s", commit[:12], err, out)
		}
	}
	if err := os.MkdirAll(filepath.Join(tree, ".yard-review"), 0o755); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(filepath.Join(tree, ".yard-review", "change.diff"), []byte(change), 0o644); err != nil {
		return "", "", err
	}
	du, _ := exec.Command("du", "-sb", tree).Output()
	var size int64
	fmt.Sscan(string(du), &size)
	size = size*3/2 + 64<<20
	tmp := path + ".tmp"
	if out, err := exec.Command("truncate", "-s", fmt.Sprint(size), tmp).CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("truncate: %v %s", err, out)
	}
	mkfs := "mkfs.ext4"
	if _, err := exec.LookPath(mkfs); err != nil {
		mkfs = "/usr/sbin/mkfs.ext4"
	}
	if out, err := exec.Command(mkfs, "-q", "-F", "-L", "input", "-d", tree, tmp).CombinedOutput(); err != nil {
		os.Remove(tmp)
		return "", "", fmt.Errorf("mkfs: %v %s", err, out)
	}
	return path, commit, os.Rename(tmp, path)
}
