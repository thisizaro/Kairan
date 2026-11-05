// Package enforce is the MCP-facing handler of kairan-proxy: it checks the
// agent's API key, reads each request strictly, decides tools/call, filters
// tools/list and forwards everything else to the MCP server
// (ARCHITECTURE section 3 and section 10 proxy/enforce).
//
// # What a request goes through
//
//  1. Authentication, before any body is read. The key is "Authorization:
//     Bearer <key>" or "X-Api-Key: <key>" (both present must agree). It is
//     compared in constant time against every configured key and maps to one
//     role. An unknown or missing key is 401 with no role and no decision
//     record (there is no role to record).
//  2. POST bodies must be application/json (charset utf-8 only), not
//     Content-Encoded, at most 1 MiB. The body is read whole, then scanned
//     strictly (scan.go): one object, no batch, no duplicate keys, no
//     non-lowercase or escaped keys at the envelope and in params, exact
//     method spelling. Anything else is a logged deny (HTTP 400, 413 or 415);
//     nothing reaches the upstream.
//  3. tools/call is judged against the one Active policy loaded for the call
//     and recorded (role, tool, verdict, version, hash) before it is
//     forwarded. A deny is an MCP tool error "blocked by policy vN". If the
//     decision cannot be recorded the call is denied.
//  4. tools/list is forwarded and the answer rebuilt with only the tools the
//     role could call (filter.go), as application/json or text/event-stream;
//     what cannot be read becomes an empty list. In DenyAll, Tampered and
//     Booting, and in SafeMode deny_all, the list is empty and the upstream
//     is not contacted.
//  5. Every other POST (initialize, ping, notifications, client responses)
//     and GET and DELETE pass through. They carry no decision.
//
// The proxy forwards exactly the bytes it inspected, with the agent's own
// credentials removed. Requests always go to the configured upstream URL; the
// path and query of the agent's request are not used.
//
// # What is logged
//
// Record carries the role, the tool name, the verdict, the class and the
// policy version and hash. Never arguments or results (invariant I4,
// THREATS #7). A tool name that is not a valid tool name is logged as "".
//
// # Limits of this version
//
//   - Policy expiry is not checked here. The agent loop stores a new Active
//     with State SafeMode when the policy expires at effective_now (M-D30).
//   - A GET stream is relayed without the per-call timeout (it is meant to
//     stay open); it ends when either side closes it.
//   - SSE event ids and retry fields are dropped from a rebuilt tools/list
//     stream, so such a stream cannot be resumed.
//   - The agent's credentials are not forwarded, so an upstream that needs
//     its own credentials is not supported yet.
package enforce
