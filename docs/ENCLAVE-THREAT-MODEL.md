# Enclave threat model: what the enclave defends, and what it does not

The enclave's guarantee is that a **hostile host cannot extract sealed secrets** — the jar and
regulator private keys, the SS interval shares, the sealed table secret. It has never been able to
stop that host from running a broken node: the host picks the binaries, owns the store, and is the
only client on the enclave's socket.

**That sentence was FALSE until 2026-10-19, and the reason is worth keeping.** Everything was sealed
with the SGX **product** key, derived from MRSIGNER + productID — and the signing key ships in this
repo. So any binary signed with it could open any node's sealed state, whatever its own measurement.
That was not a theory: `cmd/sealprobe`, a standalone ego enclave with a different MRENCLAVE signed
with `cmd/qadenad_enclave/private.pem`, opened a live node's `enclave_params_<uid>.json` on real SGX
hardware and recovered `EnclavePrivK`, `PioneerPrivK`, `SealedTableSharedSecret`, `JarPrivK` and
`RegulatorPrivK`, plus real SS share and cached-privK rows from `enclave_secrets`.

It is true now because sealing no longer depends on MRSIGNER at all:

| what | sealed with |
|---|---|
| `enclave_params_<uid>.json` | the SGX **unique** key (MRENCLAVE) — the only SGX seal left |
| store and secrets **values** | AES-256-GCM under a subkey of `SealedTableSharedSecret`, which lives in those params |
| store and secrets **keys** | unchanged: `MustSealStable`, AES under the same secret, fixed nonce |

A foreign build cannot derive the unique key, so it cannot open the params, so it never learns the
shared secret, so the stores stay shut. Re-running the same probe against the fixed build is refused
on the params (`cipher: message authentication failed`) and reads `0 OPENED` on the SS rows — the
exact inversion of the pre-fix run. Keep `cmd/sealprobe` working: it is the regression test for this
paragraph, and it is the only thing that caught the original claim being wrong.

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

### The five ways trust is gained, and there are no others

| route | anchor it rests on |
|---|---|
| **self** | the measurement equals ours — the one fact an enclave can check with no external help |
| **attested** | `UpdateEnclaveIdentity` carrying a remote report from an enclave we already trust |
| **quorum** | our own `validateEnclaveIdentities` reaching threshold among peers we trust |
| **bootstrap** | sync-enclave from a seed running **our own MRENCLAVE** |
| **handover** | an upgrade carrying the previous measurement's sealed params, trusted set included, authenticated against the measurement the operator named in `--upgrade-from-enclave-unique-id` (`verifyUpgradeSourceIsExpected`) |

All five require the measurement to have been genuinely active at some real point. **None can mint
trust in a build that never had it.**

`bootstrap` and `handover` were one row here while they were one idea — "the chain of trust needs a
root". They are listed apart because their anchors differ, and the difference is what somebody
debugging an upgrade needs: bootstrap checks *our own* measurement, handover checks *the one the
operator stated*. `verifyUpgradeSourceIsExpected` refuses an unnamed source, a missing report, a
report that does not verify or does not cover the state sent, and a report whose measurement is not
the expected one.

**Trust is not the chain's `active` flag, and an upgrade does not wait for it.** A new measurement
is registered `unvalidated` (the chain accepts no other status for a new row) and is promoted to
`active` later, by enclave quorum. The swap at the plan height does not consult that row at all — it
is authorised by `handover`. What `active` gates is the *chain's* own verification of
enclave-signed messages (`ClientVerifyRemoteReport`), so a measurement promoted after the swap
leaves a window in which those are rejected, not a fleet that fails to start. Observed on M1–M4,
2026-10-20: swap at height 8732 with the identity still `unvalidated`, promotion completing some
minutes later, the fleet healthy throughout.

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

## Not a residual, a definition: membership is irreversible

**An owner keeps what it learned. There is no mechanism that takes a key back from a machine we do
not control, and none is possible.**

This is recorded here because the SS departure work invites the opposite reading. Dropping a
pioneer from an owner set and re-sharing the key *looks* like revocation, and a re-share does draw
a new Shamir polynomial so the old fragment no longer combines. But a departed owner is not left
holding a dead fragment:

- **Below four owners nothing is split at all.** `getThreshold` returns 1 for 0–3 owners and
  `addSSShare` short-circuits there, handing every owner a copy of `privK`. On a chain that grows
  organically from one node, every key minted before the fourth pioneer became addressable was
  distributed whole.
- **Receiving a share of a split key triggers a reconstruction.** `SetPublicKey`'s threshold-≥2
  branch calls `scheduleSSReconstruct`, which gathers shares and caches the rebuilt key. This is
  deliberate: gathering lazily would put network I/O inside deterministic block execution, where a
  node that cannot reach its peers computes a different result from one that can — a fork.
- **Re-sharing requires reconstructing first**, so any proposer that heals a key holds it.

The result sits in `EnclaveSSIntervalPrivKKeyPrefix`, keyed by pubKID, in the unversioned
`SecretsDB`, with no eviction — `removePrivKCache` is reached only from the debug
`RemovePrivateKey` endpoint and the escrow path. Measured on M1–M6: three nodes, 21 entries each
for 21 interval keys, every value a whole 32-byte key.

**None of that is a defect, and clearing the cache would not fix it.** An owner that can gather
threshold-many shares can rebuild the key whenever it likes; caching only saves the round trip.
Holding the key and being entitled to obtain it are the same capability, so an owner learning the
key is what ownership MEANS. A node that has departed is outside our control by definition: code
that clears a cache runs only on a node still cooperating with us, which is not the node in
question, and an operator with a disk image from before the departure is unaffected regardless.

**What the departure machinery actually buys**, stated without overclaiming:

- the departed pioneer cannot participate in future reconstructions — its fragment is dead against
  the new polynomial, so it cannot serve shares or rebuild keys re-shared after it left;
- the chain stops reporting custody that does not exist, which is what the audit's `AT RISK` and
  `UNRECOVERABLE` warnings are measured against;
- surviving owners regain the margin a departed owner was silently consuming.

**The only real bound on what a departed node holds is ROTATION.** A key minted after it left is
one it never saw. That is the same conclusion the genesis-era exposure reaches, and it is why
retiring old interval keys matters more than re-sharing them.

**Scoping: this is an SGX claim.** The cached keys are sealed under `SealedTableSharedSecret`,
inside the unique-key-sealed params, so a departed operator holds ciphertext it cannot open without
breaking SGX on that machine — a long-horizon risk tied to retired hardware, not a disclosure. On a
debug enclave the sealing is nominal and the cache is simply readable.

## Claim scoping

When describing these defences, keep the claims to what they cover:

- the sealed height high-water-mark removes the **`isLive` lever for injection** into a node's
  current state. It does **not** address rollback.
- `refuseIfCatchingUp` refuses secret release while replaying, on a liveness signal that is
  host-supplied. It is defence in depth, not a guarantee.
- **an SS re-share drops a departed owner from the owner set; it does not revoke what that owner
  already knows.** Say "dropped from the owner set" or "cannot participate in future
  reconstructions", never "custody was removed" or "its access was revoked".
- **debug builds have none of these properties.** `DebugVerifyRemoteReport` is a no-op and the
  measurement is an embedded string, so every check here is forgeable by editing a text file. Debug
  runs prove logic; only SGX runs prove security.
