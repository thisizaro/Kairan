package policy

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Render returns the policy as plain text for a human approver (M-D32): what
// will be enforced, as the parser understood it, never the raw document. The
// output is deterministic (roles and patterns in byte order) and contains
// only validated fields, so it holds no control characters. A nil policy
// renders as a short notice.
func (p *Policy) Render() string {
	if p == nil {
		return "(no policy)\n"
	}
	var b strings.Builder
	b.WriteString("tenant:  " + string(p.Tenant) + "\n")
	b.WriteString("version: " + strconv.FormatUint(p.Version, 10) + "\n")
	b.WriteString("issued:  " + p.IssuedAt.UTC().Format(time.RFC3339) + "\n")
	b.WriteString("expires: " + p.ExpiresAt.UTC().Format(time.RFC3339) + "\n")
	b.WriteString("default: deny\n")
	if len(p.roles) == 0 {
		b.WriteString("(no roles: every call is denied)\n")
		return b.String()
	}
	names := make([]string, 0, len(p.roles))
	for n := range p.roles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := p.roles[n]
		b.WriteString("role " + n + "\n")
		type rule struct {
			pattern string
			class   Class
		}
		rules := make([]rule, 0, len(r.exact)+len(r.prefixes))
		width := 0
		for pat, c := range r.exact {
			rules = append(rules, rule{pat, c})
		}
		for _, pr := range r.prefixes {
			rules = append(rules, rule{pr.pattern, pr.class})
		}
		sort.Slice(rules, func(i, j int) bool { return rules[i].pattern < rules[j].pattern })
		for _, ru := range rules {
			width = max(width, len(ru.pattern))
		}
		for _, ru := range rules {
			b.WriteString("  " + ru.pattern + strings.Repeat(" ", width-len(ru.pattern)+2))
			b.WriteString(string(ru.class) + " (" + className(ru.class) + ")\n")
		}
	}
	return b.String()
}

func className(c Class) string {
	switch c {
	case ClassR:
		return "read"
	case ClassW:
		return "write"
	case ClassX:
		return "execute"
	}
	return "?"
}
