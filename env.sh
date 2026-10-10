# yard Go build environment (Halo). Source it: `. ./env.sh`.
# Reuses the shared go1.27.1 GOROOT read-only and the NUC stream's module cache.
export Y=/work/platform/yard
export GOROOT=/work/platform/go/go
export PATH=$GOROOT/bin:/usr/local/bin:/usr/bin:/bin
export GOPATH=$Y/.go/gopath
export GOCACHE=$Y/.go/cache
export GOMODCACHE=/work/platform/nuc/go/modcache
export GOTOOLCHAIN=local
export GOTELEMETRY=off
export GOFLAGS=-modcacherw
export TMPDIR=$Y/.go/tmp
export GOTMPDIR=$Y/.go/tmp
export HOME=$Y/.go/home
export XDG_CACHE_HOME=$Y/.go/cache
export GOPROXY=off
export GOSUMDB=sum.golang.org
mkdir -p "$GOCACHE" "$TMPDIR" "$HOME" "$GOPATH"
