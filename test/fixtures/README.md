# Test fixtures (TEST-ONLY)

Golden envelopes and keys for `trust` unit tests (lane T) and chaos scenario S5 (lane Q). **Nothing here is a real secret**: keys come from fixed public seeds (`sha256("kairan TEST-ONLY <name>")`), so anyone can regenerate them. Never use them outside tests.

- `TEST-ONLY-<name>.pub` / `.seed`: hex ed25519 public key / seed. `admin-a`, `admin-b` and `admin-c` are trusted for `bank-a` (threshold 2); `outsider` is not.
- `envelopes/*.json`: one `wire.Envelope` per case.
- `cases.json`: the trust root, the reference time (`now`, skew 120s), the check order, and for each case the proxy's current version (`have`) and the expected result (`want`; `""` = accepted).

Regenerate after changing the generator (CI fails if these files are stale):

    go run ./test/fixtures/gen -out test/fixtures

The generator signs independently of `internal/trust`, so these files are test vectors that `trust.Accept` must agree with. After Gate G0 the Overseer adds `.frozen` and lane T can no longer edit this folder.
