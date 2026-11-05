package enforce

import (
	"bytes"
	"encoding/json"
	"mime"
	"strings"
)

// tools/list response filtering (M-D33 item 5, THREATS #13).
//
// The agent must never see a tool its role cannot call. The proxy does not
// edit the upstream bytes: it reads the response, then writes a new one built
// from the parts it understood. Anything it cannot read becomes an empty tool
// list (fail closed), so a hostile or odd upstream can hide a tool from the
// filter only by hiding it from the agent too.
//
// Both forms an MCP server may answer with are handled:
//
//   - application/json: one JSON-RPC response whose id is the request's id;
//   - text/event-stream: events whose data is a JSON-RPC message. The first
//     response with the request's id is filtered. Server notifications and
//     requests (they carry "method" and no result or error) pass through.
//     Every other event (second responses, other ids, batches, junk) is
//     dropped, so tools cannot be smuggled in beside the real answer. If no
//     response with the request's id survives, an empty list is appended.
//
// Inside a response, a key that only differs by case from result, tools or
// name is not trusted: a tool with such a key is dropped, and a case-variant
// "tools" is removed from the result. Duplicate keys collapse to the last one
// and are written once, so the name the filter judged is the name the agent
// reads.

// filterList returns the tools/list reply for the agent and whether it is an
// event stream. visible says whether the agent's role may see a tool name.
// id is the request's id (raw). It never fails: the worst case is an empty
// list as application/json.
func filterList(visible func(string) bool, id json.RawMessage, contentType string, body []byte) (out []byte, sse bool) {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return emptyList(id), false
	}
	switch mt {
	case "application/json":
		if msg, ok := filterMessage(visible, id, body); ok {
			return msg, false
		}
		return emptyList(id), false
	case "text/event-stream":
		return filterEvents(visible, id, body), true
	}
	return emptyList(id), false
}

// emptyList is the fail-closed answer.
func emptyList(id json.RawMessage) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + string(id) + `,"result":{"tools":[]}}`)
}

// foldGet returns the member called name, and ok=false if the object also has
// a member whose key differs from name only by case folding (an ambiguity the
// proxy will not resolve).
func foldGet(m map[string]json.RawMessage, name string) (raw json.RawMessage, present, ok bool) {
	for k, v := range m {
		if k == name {
			raw, present = v, true
		} else if strings.EqualFold(k, name) {
			return nil, false, false
		}
	}
	return raw, present, true
}

// hasFold reports whether any key of m is name under case folding.
func hasFold(m map[string]json.RawMessage, name string) bool {
	for k := range m {
		if strings.EqualFold(k, name) {
			return true
		}
	}
	return false
}

func marshal(v any) ([]byte, bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, false
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), true
}

// filterMessage filters one JSON-RPC response (not a batch). ok=false means
// the message is not an answer to the request that the proxy can vouch for.
func filterMessage(visible func(string) bool, id json.RawMessage, data []byte) ([]byte, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return nil, false
	}
	gotID, hasID, ok := foldGet(top, "id")
	if !ok || !hasID || !sameID(gotID, id) {
		return nil, false
	}
	result, hasResult, ok1 := foldGet(top, "result")
	errRaw, hasErr, ok2 := foldGet(top, "error")
	if !ok1 || !ok2 || hasResult == hasErr {
		return nil, false
	}
	reply := map[string]json.RawMessage{
		"jsonrpc": json.RawMessage(`"2.0"`),
		"id":      id,
	}
	if hasErr {
		reply["error"] = errRaw
		return marshal(reply)
	}

	var res map[string]json.RawMessage
	if err := json.Unmarshal(result, &res); err != nil || res == nil {
		return nil, false
	}
	toolsRaw, hasTools, ok := foldGet(res, "tools")
	if !ok || !hasTools {
		return nil, false
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(toolsRaw, &tools); err != nil {
		return nil, false
	}
	kept := make([]json.RawMessage, 0, len(tools))
	for _, t := range tools {
		var obj map[string]json.RawMessage
		if json.Unmarshal(t, &obj) != nil || obj == nil {
			continue
		}
		nameRaw, hasName, ok := foldGet(obj, "name")
		if !ok || !hasName {
			continue
		}
		var name string
		if json.Unmarshal(nameRaw, &name) != nil || !visible(name) {
			continue
		}
		b, ok := marshal(obj)
		if !ok {
			continue
		}
		kept = append(kept, b)
	}
	for k := range res { // case variants of "tools" are not passed on
		if k != "tools" && strings.EqualFold(k, "tools") {
			delete(res, k)
		}
	}
	kb, ok := marshal(kept)
	if !ok {
		return nil, false
	}
	res["tools"] = kb
	rb, ok := marshal(res)
	if !ok {
		return nil, false
	}
	reply["result"] = rb
	return marshal(reply)
}

// sameID compares two raw JSON-RPC ids: strings by value, everything else by
// its text. A string and a number are never the same id.
func sameID(a, b json.RawMessage) bool {
	a, b = bytes.TrimSpace(a), bytes.TrimSpace(b)
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	if a[0] == '"' || b[0] == '"' {
		var x, y string
		return a[0] == '"' && b[0] == '"' && json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && x == y
	}
	return bytes.Equal(a, b)
}

// filterEvents rewrites a text/event-stream body (see the package comment).
func filterEvents(visible func(string) bool, id json.RawMessage, body []byte) []byte {
	var out bytes.Buffer
	emit := func(msg []byte) {
		out.WriteString("event: message\ndata: ")
		out.Write(msg)
		out.WriteString("\n\n")
	}
	answered := false
	for _, data := range sseData(body) {
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil || top == nil {
			continue // junk or a batch
		}
		isAnswer := hasFold(top, "result") || hasFold(top, "error")
		switch {
		case isAnswer && hasFold(top, "method"):
			continue // neither a request nor a response
		case isAnswer:
			if answered {
				continue
			}
			if msg, ok := filterMessage(visible, id, data); ok {
				answered = true
				emit(msg)
			}
		case hasFold(top, "method"):
			var c bytes.Buffer
			if json.Compact(&c, data) == nil {
				emit(c.Bytes())
			}
		}
	}
	if !answered {
		emit(emptyList(id))
	}
	return out.Bytes()
}

// sseData returns the data of each event in an event stream, following the
// SSE line rules: lines end in LF, CR or CRLF; a blank line ends an event;
// "data" lines of one event are joined with LF; other fields and comments are
// ignored; a leading BOM is dropped; an event cut off by the end of the
// stream is kept.
func sseData(body []byte) [][]byte {
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf"))
	var (
		events [][]byte
		cur    [][]byte
		have   bool
	)
	flush := func() {
		if have {
			events = append(events, bytes.Join(cur, []byte("\n")))
		}
		cur, have = nil, false
	}
	for len(body) > 0 {
		i := bytes.IndexAny(body, "\r\n")
		var line []byte
		if i < 0 {
			line, body = body, nil
		} else {
			line = body[:i]
			skip := 1
			if body[i] == '\r' && i+1 < len(body) && body[i+1] == '\n' {
				skip = 2
			}
			body = body[i+skip:]
		}
		if len(line) == 0 {
			flush()
			continue
		}
		if line[0] == ':' {
			continue
		}
		field, value := line, []byte(nil)
		if c := bytes.IndexByte(line, ':'); c >= 0 {
			field, value = line[:c], line[c+1:]
			value = bytes.TrimPrefix(value, []byte(" "))
		}
		if string(field) == "data" {
			cur = append(cur, value)
			have = true
		}
	}
	flush()
	return events
}
