#!/bin/sh
# Mandatory host-side conformance gate; optional native test binaries can skip
# Quint if it is unavailable, but this entry point must never silently skip.
set -eu
R=$(cd "$(dirname "$0")/.." && pwd)
. "$R/env.sh"
cd "$R"
command -v quint >/dev/null || { printf '%s\n' 'quint is required for the load-order conformance gate' >&2; exit 1; }
go test -race -count=1 ./internal/service -run 'TestLoadOrderRuntimeConformance|TestResumeChecksDriftBeforeMountMetadataWrites|TestChangedUnmountedCloneIsRefusedBeforeMount|TestFailedRestore.*RequiresExplicitOverride|TestRemoval|TestOperatorRemovalRuntimeConformance|TestDownCleansViewsAfterExternalJailRemoval'
go test -race -count=1 ./internal/lifecycle -run 'TestReplayQuintTraces|TestSessionPolicy|TestSessionSettlement'
