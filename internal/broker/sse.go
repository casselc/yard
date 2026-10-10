package broker

import "bytes"

// sseKind says which terminal events end a route's stream.
type sseKind int

const (
	sseNone      sseKind = iota
	sseResponses         // OpenAI Responses (halo and OpenAI): event response.completed / .cancelled / .failed / .incomplete / error
	sseChat              // Chat Completions: data: [DONE]
	sseMessages          // Anthropic Messages (halo and Anthropic): event message_stop / error
)

func sseKindFor(path string) sseKind {
	switch path {
	case "/v1/responses":
		return sseResponses
	case "/v1/chat/completions":
		return sseChat
	case "/v1/messages":
		return sseMessages
	}
	return sseNone
}

// Terminal results.
const (
	termNone int32 = iota
	termDone
	termCancelled
	termError
)

// sseParser is a bounded SSE (text/event-stream) parser that looks only at
// event names and the first bytes of data. A terminal result is recorded
// only when a complete event is dispatched (at its blank line). A line
// longer than sseMaxLine poisons its whole event: a truncated prefix can
// never match. Nothing is kept beyond the current line and event.
type sseParser struct {
	kind     sseKind
	line     []byte
	overlong bool // the current line exceeded sseMaxLine
	poisoned bool // the current event had an overlong line
	event    []byte
	data     []byte // first sseMaxData bytes of the event's data
	dataLong bool   // data longer than kept
	hasData  bool
	result   int32
}

const (
	sseMaxLine = 4096
	sseMaxData = 32
)

func (p *sseParser) feed(b []byte) {
	for _, c := range b {
		if c == '\n' {
			p.endLine()
			continue
		}
		if len(p.line) >= sseMaxLine {
			p.overlong = true
			continue
		}
		p.line = append(p.line, c)
	}
}

func (p *sseParser) endLine() {
	line := bytes.TrimSuffix(p.line, []byte("\r"))
	overlong := p.overlong
	p.line, p.overlong = p.line[:0], false
	if overlong {
		p.poisoned = true
		return
	}
	if len(line) == 0 {
		p.dispatch()
		return
	}
	if line[0] == ':' {
		return // comment (keep-alive)
	}
	field, value := line, []byte(nil)
	if i := bytes.IndexByte(line, ':'); i >= 0 {
		field, value = line[:i], line[i+1:]
		value = bytes.TrimPrefix(value, []byte(" "))
	}
	switch string(field) {
	case "event":
		p.event = append(p.event[:0], value...)
	case "data":
		if p.hasData {
			p.dataLong = true // multi-line data: not a bare marker
		}
		p.hasData = true
		if len(value) > sseMaxData {
			p.dataLong = true
			value = value[:sseMaxData]
		}
		p.data = append(p.data[:0], value...)
	}
}

func (p *sseParser) dispatch() {
	defer func() {
		p.event, p.data, p.hasData, p.dataLong, p.poisoned = p.event[:0], p.data[:0], false, false, false
	}()
	if p.poisoned || !p.hasData { // MUTANT:sseDispatchWithoutData
		return // an event without data is not dispatched (WHATWG SSE)
	}
	ev := string(p.event)
	switch p.kind {
	case sseResponses:
		switch ev {
		case "response.completed":
			p.result = termDone
		case "response.cancelled":
			p.result = termCancelled
		case "response.failed", "response.incomplete", "error":
			p.result = termError
		}
	case sseMessages:
		switch ev {
		case "message_stop":
			p.result = termDone
		case "error":
			p.result = termError
		}
	case sseChat:
		if ev == "" && !p.dataLong && string(p.data) == "[DONE]" {
			p.result = termDone
		}
	}
}
