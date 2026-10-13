// Package driver turns a task into a harness's non-interactive run (design/AGENT-OPERATIONS.md section 9), and
// finds the harness's structured output in what the run printed. The guest runs what the driver composes; the
// guest itself knows no harness.
package driver

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// Task is the guest's task frame (cmd/yard-guest).
type Task struct {
	Argv      []string          `json:"argv"`
	Env       map[string]string `json:"env"`
	Dir       string            `json:"dir"`
	OutputCap int64             `json:"output_cap"`
}

// Claude is the claude driver: a review with read and search tools only.
//
//   - --restricted: no command-running tools, no user, project or local settings files, file tools confined to the
//     working directory;
//   - --safe-mode: no CLAUDE.md, skills, plugins, hooks, MCP servers or custom agents;
//   - --tools Read,Grep,Glob, so no Task tool: no subagent can run;
//   - --exclude-dynamic-system-prompt-sections: a stable prompt prefix across reviewers (halo's prefix cache);
//   - --json-schema: the structured output, validated again by yard (structure only).
//
// --bare is not used: its simple mode keeps only the minimal tool set (no Grep or Glob; design/AG1.md).
func Claude(prompt, schema, model string, outputCap int64) Task {
	var b bytes.Buffer
	if err := json.Compact(&b, []byte(schema)); err == nil {
		schema = b.String()
	}
	return Task{
		Argv: []string{"/usr/local/bin/claude", "-p", prompt,
			"--restricted", "--safe-mode", "--strict-mcp-config", "--disable-slash-commands",
			"--tools", "Read,Grep,Glob",
			"--exclude-dynamic-system-prompt-sections",
			"--output-format", "stream-json", "--verbose",
			"--json-schema", schema,
			"--model", model,
			"--no-session-persistence",
		},
		Env: map[string]string{
			"ANTHROPIC_BASE_URL":                       "http://127.0.0.1:4000",
			"ANTHROPIC_API_KEY":                        "yard-placeholder", // the broker holds the route; the VM holds no key
			"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
			"DISABLE_AUTOUPDATER":                      "1",
			"DISABLE_TELEMETRY":                        "1",
			"DISABLE_ERROR_REPORTING":                  "1",
			"USE_BUILTIN_RIPGREP":                      "0",
		},
		Dir:       "/workspace",
		OutputCap: outputCap,
	}
}

// ClaudeResult finds the final structured output in a stream-json transcript: the last result event's
// structured_output, or its result text when that is JSON. It returns why when there is none.
func ClaudeResult(transcript []byte) (json.RawMessage, string) {
	var last map[string]json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(transcript))
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	for sc.Scan() {
		var ev map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		if string(ev["type"]) == `"result"` {
			last = ev
		}
	}
	if last == nil {
		return nil, "no result event in the transcript"
	}
	if so, ok := last["structured_output"]; ok && string(so) != "null" {
		return so, ""
	}
	var text string
	if json.Unmarshal(last["result"], &text) == nil && json.Valid([]byte(strings.TrimSpace(text))) {
		return json.RawMessage(strings.TrimSpace(text)), ""
	}
	return nil, "the result event has no structured output"
}
