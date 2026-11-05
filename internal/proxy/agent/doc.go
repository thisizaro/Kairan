// Package agent is the proxy's control-plane client (ARCHITECTURE section 10,
// proxy/agent): boot, long-poll, status reports, and the clock guard that
// bounds expiry against clock rollback.
//
// This directory currently holds the clock guard (P-10, clockguard.go); the
// poll loop and boot code arrive with P-05.
package agent
