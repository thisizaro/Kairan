package policy

// Matching (docs/ARCHITECTURE.md section 10.0, decision M-D32):
//
//   - an exact rule wins;
//   - otherwise the longest prefix rule that matches wins;
//   - otherwise the tool is denied;
//   - matching is byte-exact and case-sensitive;
//   - the matched rule's class is the tool's class. Any matched rule allows
//     the tool in normal mode; the class only matters in safe mode, where
//     class R alone is allowed (decision M-D33).
//
// A tool name outside section 10.0's alphabet and length (1-128 characters
// of [A-Za-z0-9_.-]) is denied before any rule is looked at, so a prefix rule
// can never grant a name that no rule could have spelled out (I3: unknown
// input means deny).
//
// Safe mode deny_all is not decided here: the proxy's state package refuses
// every call in that mode and does not ask the policy. Decide's safeMode
// flag is the read_only filter.

// Decision is the result of matching one tool for one role.
type Decision struct {
	Allowed bool
	Class   Class  // class of the matched rule; 0 when no rule matched
	Rule    string // matched pattern as written; "" when no rule matched
}

// Decide matches tool against the rules of role. Unknown role, invalid tool
// name and no matching rule all give the zero Decision (denied). With
// safeMode set, a matched rule allows the tool only if its class is R; the
// matched Class and Rule are still reported so the decision log can say why.
// Decide does not allocate and is safe for concurrent use. A nil or zero
// Policy denies everything.
func (p *Policy) Decide(role, tool string, safeMode bool) Decision {
	if p == nil || !validName(tool) {
		return Decision{}
	}
	r := p.roles[role]
	if r == nil {
		return Decision{}
	}
	if c, ok := r.exact[tool]; ok {
		return Decision{Allowed: !safeMode || c == ClassR, Class: c, Rule: tool}
	}
	if i := r.trie.longest(tool); i >= 0 {
		pr := &r.prefixes[i]
		return Decision{Allowed: !safeMode || pr.class == ClassR, Class: pr.class, Rule: pr.pattern}
	}
	return Decision{}
}

// Visible returns the tools that Decide allows for role, in their original
// order, in a new slice (never nil, the input is not modified). It is the
// tools/list filter: a tool is visible if and only if a call to it would be
// allowed.
func (p *Policy) Visible(role string, tools []string, safeMode bool) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if p.Decide(role, t, safeMode).Allowed {
			out = append(out, t)
		}
	}
	return out
}

// trie finds the longest prefix rule that is a prefix of a name. It is
// flattened into two slices after Parse so lookups walk the name once and
// allocate nothing. Node 0 is the root.
type trie struct {
	nodes []trieNode
	edges []trieEdge // children of a node are edges[first:end], sorted by byte
}

type trieNode struct {
	first, end int32
	rule       int32 // 1 + index into role.prefixes, 0 if no rule ends here
}

type trieEdge struct {
	b  byte
	to int32
}

// buildTrie compiles rules (index = rule number) into a trie.
func buildTrie(rules []prefixRule) trie {
	type build struct {
		kids map[byte]int32
		rule int32
	}
	nodes := []build{{}}
	for i, pr := range rules {
		n := int32(0)
		for j := 0; j < len(pr.prefix); j++ {
			c := pr.prefix[j]
			next, ok := nodes[n].kids[c]
			if !ok {
				next = int32(len(nodes))
				if nodes[n].kids == nil {
					nodes[n].kids = map[byte]int32{}
				}
				nodes[n].kids[c] = next
				nodes = append(nodes, build{})
			}
			n = next
		}
		nodes[n].rule = int32(i) + 1
	}
	var t trie
	t.nodes = make([]trieNode, len(nodes))
	for i, b := range nodes {
		t.nodes[i] = trieNode{first: int32(len(t.edges)), rule: b.rule}
		var keys [256]bool
		for c := range b.kids {
			keys[c] = true
		}
		for c := 0; c < 256; c++ { // byte order, so the layout is deterministic
			if keys[c] {
				t.edges = append(t.edges, trieEdge{b: byte(c), to: b.kids[byte(c)]})
			}
		}
		t.nodes[i].end = int32(len(t.edges))
	}
	return t
}

// longest returns the index of the longest rule whose prefix is a prefix of
// name, or -1.
func (t *trie) longest(name string) int {
	if len(t.nodes) == 0 {
		return -1
	}
	best := int32(0)
	n := int32(0)
	for i := 0; i < len(name); i++ {
		c := name[i]
		next := int32(-1)
		for _, e := range t.edges[t.nodes[n].first:t.nodes[n].end] {
			if e.b == c {
				next = e.to
				break
			}
			if e.b > c {
				break
			}
		}
		if next < 0 {
			break
		}
		n = next
		if r := t.nodes[n].rule; r != 0 {
			best = r
		}
	}
	return int(best) - 1
}
