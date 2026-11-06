package agent

import (
	"sort"
	"sync"

	"kairan/internal/wire"
)

// Counter names the agent itself increments (Stats.Inc).
const (
	MetricApplyOK       = "agent_apply_ok"        // an envelope was applied
	MetricApplyRejected = "agent_apply_rejected"  // an envelope was rejected or could not be persisted
	MetricPollErrors    = "agent_poll_errors"     // a poll failed (network, bad status, unreadable body)
	MetricStatusErrors  = "agent_status_errors"   // a status report was not delivered
	MetricExpired       = "agent_policy_expired"  // Enforcing -> SafeMode at effective_now
	MetricBootTampered  = "agent_boot_tampered"   // boot ended in Tampered
	MetricLogReset      = "agent_apply_log_reset" // a broken apply log was kept aside and a new chain started (P-13)
)

// Names the enforce package increments; the agent turns them into the call
// counters of the status report.
const (
	enforceAllow = "enforce_allow"
	enforceDeny  = "enforce_deny"
)

// Stats is a small counter set. It implements enforce.Metrics and
// declog's Metrics hook (both are Inc(name)), so one Stats can be handed to
// the MCP handler, the decision log and the agent. The status report's
// counters are read from it, and the local metrics listener (P-09) can list
// every name with Names and Count. It is safe for concurrent use.
type Stats struct {
	mu sync.Mutex
	m  map[string]uint64
}

// Inc adds one to the named counter.
func (s *Stats) Inc(name string) {
	s.mu.Lock()
	if s.m == nil {
		s.m = make(map[string]uint64)
	}
	s.m[name]++
	s.mu.Unlock()
}

// Count returns the named counter (0 if never incremented).
func (s *Stats) Count(name string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[name]
}

// Names lists every counter that has been incremented, sorted.
func (s *Stats) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Counters is the status-report view: calls allowed and denied (counted by
// enforce) and envelopes rejected (counted by the agent), since process start.
func (s *Stats) Counters() wire.Counters {
	return wire.Counters{
		CallsAllowed:      s.Count(enforceAllow),
		CallsDenied:       s.Count(enforceDeny),
		EnvelopesRejected: s.Count(MetricApplyRejected),
	}
}
