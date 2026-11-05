package policy

import "testing"

func TestRender(t *testing.T) {
	p, err := Parse([]byte(good(nil)))
	if err != nil {
		t.Fatal(err)
	}
	want := `tenant:  bank-a
version: 8
issued:  2026-11-05T09:00:00Z
expires: 2026-11-08T09:00:00Z
default: deny
role engineer
  ci.rerun  X (execute)
  github.*  R (read)
role sales
  crm.read_*       R (read)
  crm.update_deal  W (write)
`
	if got := p.Render(); got != want {
		t.Errorf("Render:\n%s\nwant:\n%s", got, want)
	}
}

// The rendering must not depend on the order of keys in the document.
func TestRenderIgnoresKeyOrder(t *testing.T) {
	a, err := Parse([]byte(good(map[string]string{"roles": `{"b":{"x.*":"R","a.y":"W"},"a":{"z":"X"}}`})))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(good(map[string]string{"roles": `{"a":{"z":"X"},"b":{"a.y":"W","x.*":"R"}}`})))
	if err != nil {
		t.Fatal(err)
	}
	if a.Render() != b.Render() {
		t.Errorf("different renderings:\n%s\n%s", a.Render(), b.Render())
	}
}

func TestRenderNoRoles(t *testing.T) {
	p, err := Parse([]byte(good(map[string]string{"roles": `{}`})))
	if err != nil {
		t.Fatal(err)
	}
	want := "tenant:  bank-a\nversion: 8\nissued:  2026-11-05T09:00:00Z\nexpires: 2026-11-08T09:00:00Z\ndefault: deny\n(no roles: every call is denied)\n"
	if got := p.Render(); got != want {
		t.Errorf("Render:\n%q\nwant:\n%q", got, want)
	}
}

func TestRenderNil(t *testing.T) {
	var p *Policy
	if got := p.Render(); got == "" {
		t.Error("nil policy rendered as empty text")
	}
}
