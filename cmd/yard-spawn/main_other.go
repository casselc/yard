//go:build !freebsd

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "yard-spawn: FreeBSD only")
	os.Exit(1)
}
