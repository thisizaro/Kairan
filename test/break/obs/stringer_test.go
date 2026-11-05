package obsbreak

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// I4: a URL with a query string is a classic carrier of call data. *url.URL is a fmt.Stringer, which
// the doc says is rendered; the doc also says pointers are replaced. Awaiting the Overseer's ruling.
func TestStringerURLQueryIsNotLogged(t *testing.T) {
	t.Skip("doc ambiguity: Q-D14")
	u, _ := url.Parse("https://user:" + canary + "@example.test/mcp?q=" + canary)
	req, _ := http.NewRequest("GET", u.String(), strings.NewReader(""))
	for name, v := range map[string]any{"url-ptr": u, "url-value": *u, "request-url": req.URL} {
		b, l := newBuf()
		l.Info("m", "k", v)
		noCanary(t, name, b.String())
	}
}
