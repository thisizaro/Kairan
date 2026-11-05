// Package declog is the proxy's local decision log: one JSON line for every
// decision enforce makes, stamped with the policy version and hash it was made
// under (invariant I5, PRD J5).
//
// What a line holds, and nothing else: time (UTC), role, tool, allowed, class,
// version, hash, state. Tool is a validated tool name, "tools/list" or "";
// role is bounded; class, hash and state are checked against their alphabets.
// There is no free-text field, so arguments, results and prompts cannot get
// in (THREATS #7, I4). Record refuses a record that does not fit this shape.
//
// Failure is loud. Record returns an error when the line was not stored; the
// enforce package then denies the call (fail closed, M-D33 item 3). Each
// Record is one write of a whole line to an O_APPEND file; there is no
// buffer that could hold a lie about success. A failed or short write is cut
// off again so no half line is left behind, and the Log keeps working once
// space is back. Writes are not fsynced unless Options.Sync is set (a
// crash can lose the last lines the OS had not flushed, and the next Open
// starts a fresh line after any torn tail).
//
// Rotation is by size: when the next line would push the file over MaxBytes,
// decisions.log becomes decisions.log.1, .1 becomes .2, and so on, keeping
// Keep rotated files. A rotation that fails is a failed Record (deny), is
// counted, and is tried again on the next call.
//
// The files are created 0600 and a symlink at the log path is refused.
// Failures are counted through the Metrics hook: MetricWriteErrors and
// MetricRotateErrors.
package declog
