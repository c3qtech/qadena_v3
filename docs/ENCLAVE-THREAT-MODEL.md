# Enclave threat model: what the enclave defends, and what it does not

The enclave's guarantee is that a **hostile host cannot extract sealed secrets** — the jar and
regulator private keys, the SS interval shares, the sealed table secret. It has never been able to
stop that host from running a broken node: the host picks the binaries, owns the store, and is the
only client on the enclave's socket.

This document records where that boundary actually falls after the trust split
(`5f9b7dda..94650e9f`), including one limit that is **accepted rather than fixed**. It exists so
that limit is a decision somebody made, not a gap somebody assumes is covered.

## Trust is separate from storage

Two things used to be one bit, and separating them is the whole of the change:

| | what it is |
|---|---|
| the mirrored `EnclaveIdentity` store | the **chain's** opinion. Accumulated and audited, stored verbatim, byte-identical to the chain's own write. |
| the **trusted set** (`ActiveEnclaveIdentities`, sealed params) | **this enclave's** judgement about which measurements may receive secrets. |

Before the split, `getEnclaveIdentity` read trust straight off the mirrored row's `Status`. Mirrored
rows arrive from the node, so **minting trust in a build that was never legitimate took a single
mirror push**. That is closed: `SetEnclaveIdentity` now stores without trusting.

### The four ways trust is gained, and there are no others

| route | anchor it rests on |
|---|---|
| **self** | the measurement equals ours — the one fact an enclave can check with no external help |
| **attested** | `UpdateEnclaveIdentity` carrying a remote report from an enclave we already trust |
| **quorum** | our own `validateEnclaveIdentities` reaching threshold among peers we trust |
| **bootstrap** | sync-enclave from a seed running **our own MRENCLAVE**, or an upgrade handover from the measurement the operator named in `--upgrade-from-enclave-unique-id` |

All four require the measurement to have been genuinely active at some real point. **None can mint
trust in a build that never had it.**

A mirror push may **remove** trust (the chain reports `inactive`) but never add it. The asymmetry is
deliberate: a hostile node can then only ever *reduce* what it is trusted with, which costs
availability, never disclosure.

**MRSIGNER anchors nothing here.** The signing key ships in the repo, so anyone can build a leaky
enclave whose attestation is genuine and whose MRSIGNER matches. Only MRENCLAVE distinguishes builds.

## Accepted residual: rollback-freeze

**Sealing gives confidentiality and tamper-detection, not freshness.**
`enclave_config/enclave_params_<uid>.json` is an ordinary host file, with a `_backup.json` beside it.
So a host can:

1. keep a copy of the sealed params from a time when a since-retired build `M` was legitimately
   trusted;
2. restore it, having wiped or rolled back the node;
3. report `isLive=true`;
4. run `M` and ask the enclave for secrets — which it serves, from its own frozen past.

Nothing detects this. Verified: there is **no monotonic counter, no peer-anchored height, and no
freshness challenge** anywhere in the enclave; `preparedHeight` (`enclave_height.go`) is
crash-consistency between the enclave and its own node, and the height it reconciles against is
host-supplied.

**This predates the trust split, and the split narrowed it.** Before, the same outcome needed only a
written mirror row and worked for a build that was never legitimate. Now it requires restoring an
*authentic past state* in which that specific build was genuinely trusted. Narrower, still open.

### Why the obvious defences do not close it

- **The accumulator is not a backstop.** The per-block chain-vs-enclave check
  (`comparePerBlockAccumulators`) logs at ERROR and *continues*, deliberately, pending backlog item
  46. The check that panics (`auditStoreAccumulators`) compares the chain against **its own rows** —
  self-consistency, blind to the enclave. Confirmed at runtime: a joiner logged ~900 blocks of
  cross-party divergence and went on to become a healthy validator that passed peer agreement.
- **A height high-water-mark does not either.** It closes *injection into current state* (see
  below), but it lives inside the very blob being rolled back, so a restored state restores an
  older watermark with it.
- **Asking peers "what height are you at?" is replayable** by the host it defends against: it
  returns a genuine but stale attested answer captured earlier, and the frozen victim believes it.

### What would close it

A **victim-nonce-bound, fail-closed freshness challenge** before releasing any secret:

1. the releasing enclave generates a fresh random nonce;
2. the answering peer binds `(nonce | its current height)` inside its remote report, exactly as
   `validateEnclaveIdentities` already binds identity fields today;
3. release proceeds only on a threshold of fresh answers within a window of the highest height seen,
   and is **refused** if none arrive.

The host cannot forge an attested peer height, cannot replay a stale one past a fresh nonce, and
isolating the victim produces refusal — the safe direction. The cost is real: secret release then
depends on live peer reachability. `QueryEnclaveValidateEnclaveIdentity` is the existing building
block; the only addition is the nonce, without which the question is about the past.

**Status: accepted residual.** Not scheduled. Backlog item 58.

## Claim scoping

When describing these defences, keep the claims to what they cover:

- the sealed height high-water-mark removes the **`isLive` lever for injection** into a node's
  current state. It does **not** address rollback.
- `refuseIfCatchingUp` refuses secret release while replaying, on a liveness signal that is
  host-supplied. It is defence in depth, not a guarantee.
- **debug builds have none of these properties.** `DebugVerifyRemoteReport` is a no-op and the
  measurement is an embedded string, so every check here is forgeable by editing a text file. Debug
  runs prove logic; only SGX runs prove security.
