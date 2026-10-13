package agentexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"yard/internal/node"
)

// NodeAPI is yard-node as the executor sees it. An error that is not ErrTombstoned means the node did not answer
// (unreachable): the executor never reads it as "not running".
type NodeAPI interface {
	Start(ctx context.Context, id string, s node.Spec) (node.State, error)
	Get(ctx context.Context, id string) (node.State, error)
	Stop(ctx context.Context, id string) (node.State, error)
	Tombstone(ctx context.Context, id string) (node.State, error)
	Lease(ctx context.Context, id string, ms int64) error
	Result(ctx context.Context, id string) ([]byte, error)
	List(ctx context.Context) ([]node.State, error)
	Forget(ctx context.Context, id string) error
}

var ErrTombstoned = errors.New("node: allocation tombstoned")

// NodeClient talks to yard-node over its Unix socket.
type NodeClient struct{ hc *http.Client }

func NewNodeClient(sock string) *NodeClient {
	return &NodeClient{hc: &http.Client{Timeout: 40 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", sock)
		}}}}
}

func (c *NodeClient) do(ctx context.Context, method, path string, body any, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://node"+path, rd)
	if err != nil {
		return 0, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if out != nil {
		if b, ok := out.(*[]byte); ok {
			*b = raw
		} else if err := json.Unmarshal(raw, out); err != nil && resp.StatusCode < 300 {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func (c *NodeClient) Start(ctx context.Context, id string, s node.Spec) (node.State, error) {
	var st node.State
	code, err := c.do(ctx, "POST", "/v1/allocs/"+id+"/start", s, &st)
	switch {
	case err != nil:
		return st, err
	case code == 410:
		return st, ErrTombstoned
	case code != 200:
		return st, fmt.Errorf("node: start answered %d", code)
	}
	return st, nil
}

func (c *NodeClient) state(ctx context.Context, method, path string) (node.State, error) {
	var st node.State
	code, err := c.do(ctx, method, path, nil, &st)
	if err == nil && code != 200 {
		err = fmt.Errorf("node: %s %s answered %d", method, path, code)
	}
	return st, err
}

func (c *NodeClient) Get(ctx context.Context, id string) (node.State, error) {
	return c.state(ctx, "GET", "/v1/allocs/"+id)
}
func (c *NodeClient) Stop(ctx context.Context, id string) (node.State, error) {
	return c.state(ctx, "POST", "/v1/allocs/"+id+"/stop")
}
func (c *NodeClient) Tombstone(ctx context.Context, id string) (node.State, error) {
	return c.state(ctx, "POST", "/v1/allocs/"+id+"/tombstone")
}
func (c *NodeClient) Lease(ctx context.Context, id string, ms int64) error {
	_, err := c.do(ctx, "POST", "/v1/allocs/"+id+"/lease", map[string]int64{"ms": ms}, nil)
	return err
}
func (c *NodeClient) Result(ctx context.Context, id string) ([]byte, error) {
	var b []byte
	code, err := c.do(ctx, "GET", "/v1/allocs/"+id+"/result", nil, &b)
	if err == nil && code != 200 {
		err = fmt.Errorf("node: no result (%d)", code)
	}
	return b, err
}
func (c *NodeClient) List(ctx context.Context) ([]node.State, error) {
	var l []node.State
	_, err := c.do(ctx, "GET", "/v1/allocs", nil, &l)
	return l, err
}
func (c *NodeClient) Forget(ctx context.Context, id string) error {
	_, err := c.do(ctx, "DELETE", "/v1/allocs/"+id, nil, nil)
	return err
}
