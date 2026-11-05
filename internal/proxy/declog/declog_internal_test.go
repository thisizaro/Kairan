package declog

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"kairan/internal/policy"
	"kairan/internal/proxy/enforce"
	"kairan/internal/wire"
)

var (
	hashA = wire.Hash(strings.Repeat("a", 64))
	t0    = time.Date(2026, 11, 5, 10, 0, 0, 123456789, time.UTC)
)

func sample() enforce.Record {
	return enforce.Record{Time: t0, Role: "reader", Tool: "notes.read", Allowed: true, Class: policy.ClassR,
		Version: 7, Hash: hashA, State: wire.StateEnforcing}
}

// The on-disk schema is fixed: these eight fields and no others. If someone
// adds a field to enforce.Record (a place free text could creep in) or to the
// line, this fails and the new field must be argued for (THREATS #7, I4).
func TestSchemaIsExactlyTheEightFields(t *testing.T) {
	want := []string{"allowed", "class", "hash", "role", "state", "time", "tool", "version"}

	var got []string
	typ := reflect.TypeOf(line{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")[0]
		got = append(got, tag)
		switch f.Type.Kind() {
		case reflect.String, reflect.Bool, reflect.Uint64:
		default:
			t.Errorf("field %s has kind %s: only string, bool and uint64 are allowed", f.Name, f.Type.Kind())
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("line fields = %v, want %v", got, want)
	}

	if n := reflect.TypeOf(enforce.Record{}).NumField(); n != 8 {
		t.Fatalf("enforce.Record has %d fields, the log schema has 8: update declog deliberately", n)
	}
}

func TestEncodeGolden(t *testing.T) {
	b, err := encode(sample())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"time":"2026-11-05T10:00:00.123456789Z","role":"reader","tool":"notes.read","allowed":true,"class":"R","version":7,"hash":"` +
		string(hashA) + `","state":"enforcing"}` + "\n"
	if string(b) != want {
		t.Fatalf("line =\n%s want\n%s", b, want)
	}
}

func TestEncodeRejectsFreeText(t *testing.T) {
	long := strings.Repeat("x", maxRoleLen+1)
	for name, mut := range map[string]func(*enforce.Record){
		"tool with space":       func(r *enforce.Record) { r.Tool = "notes read" },
		"tool with quote":       func(r *enforce.Record) { r.Tool = `a"b` },
		"tool with newline":     func(r *enforce.Record) { r.Tool = "a\nb" },
		"tool too long":         func(r *enforce.Record) { r.Tool = strings.Repeat("a", policy.MaxToolNameLen+1) },
		"tool arguments pasted": func(r *enforce.Record) { r.Tool = `notes.read{"q":"secret"}` },
		"role too long":         func(r *enforce.Record) { r.Role = long },
		"bad class":             func(r *enforce.Record) { r.Class = 'Z' },
		"hash not hex":          func(r *enforce.Record) { r.Hash = "free text here" },
		"hash too short":        func(r *enforce.Record) { r.Hash = "abcd" },
		"unknown state":         func(r *enforce.Record) { r.State = "because I said so" },
	} {
		t.Run(name, func(t *testing.T) {
			r := sample()
			mut(&r)
			if _, err := encode(r); err == nil {
				t.Fatal("encode accepted it")
			}
		})
	}
}

func TestEncodeAcceptsLegitimateEdges(t *testing.T) {
	for name, mut := range map[string]func(*enforce.Record){
		"tools/list": func(r *enforce.Record) { r.Tool = "tools/list"; r.Class = 0 },
		"empty tool": func(r *enforce.Record) { r.Tool = "" },
		"no policy at all": func(r *enforce.Record) {
			r.Hash = ""
			r.Version = 0
			r.State = wire.StateDenyAll
			r.Allowed = false
			r.Class = 0
		},
		"max tool":          func(r *enforce.Record) { r.Tool = strings.Repeat("a", policy.MaxToolNameLen) },
		"tool with symbols": func(r *enforce.Record) { r.Tool = "a_B-c.9" },
	} {
		t.Run(name, func(t *testing.T) {
			r := sample()
			mut(&r)
			b, err := encode(r)
			if err != nil {
				t.Fatal(err)
			}
			back, err := Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			if !back.Time.Equal(r.Time) || back.Role != r.Role || back.Tool != r.Tool || back.Allowed != r.Allowed ||
				back.Class != r.Class || back.Version != r.Version || back.Hash != r.Hash || back.State != r.State {
				t.Fatalf("round trip:\n got %+v\nwant %+v", back, r)
			}
		})
	}
}

func TestDecodeIsStrict(t *testing.T) {
	good, _ := encode(sample())
	g := strings.TrimSuffix(string(good), "\n")
	for name, in := range map[string]string{
		"extra field":   strings.TrimSuffix(g, "}") + `,"args":"x"}`,
		"missing field": strings.Replace(g, `"role":"reader",`, "", 1),
		"duplicate key": strings.Replace(g, `"role":"reader"`, `"role":"reader","role":"boss"`, 1),
		"not json":      `hello`,
		"two objects":   g + g,
		"empty":         ``,
		"time not UTC":  strings.Replace(g, "Z\"", "+02:00\"", 1),
		"bad class":     strings.Replace(g, `"class":"R"`, `"class":"RW"`, 1),
		"negative ver":  strings.Replace(g, `"version":7`, `"version":-7`, 1),
		"capitalised":   strings.Replace(g, `"role"`, `"Role"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(in)); err == nil {
				t.Fatalf("Decode accepted %q", in)
			}
		})
	}
	if _, err := Decode([]byte(g)); err != nil {
		t.Fatalf("good line without newline: %v", err)
	}
	if _, err := Decode(good); err != nil {
		t.Fatalf("good line with newline: %v", err)
	}
}

func FuzzDecode(f *testing.F) {
	good, _ := encode(sample())
	f.Add(good)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := Decode(b)
		if err != nil {
			return
		}
		// Anything Decode accepts must re-encode and decode to the same record.
		again, err := encode(r)
		if err != nil {
			t.Fatalf("accepted but cannot re-encode: %v", err)
		}
		r2, err := Decode(again)
		if err != nil || !r2.Time.Equal(r.Time) || r2.Role != r.Role || r2.Tool != r.Tool || r2.Allowed != r.Allowed ||
			r2.Class != r.Class || r2.Version != r.Version || r2.Hash != r.Hash || r2.State != r.State {
			t.Fatalf("round trip differs: %+v vs %+v (%v)", r, r2, err)
		}
	})
}
