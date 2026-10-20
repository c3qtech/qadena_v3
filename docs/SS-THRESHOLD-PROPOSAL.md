# The SS threshold tracks the owner count, symmetrically — and why a stored threshold was rejected

**Status:** decided. The threshold-lowering refusal added in `4501f3b2` has been removed; the
threshold is `getThreshold(len(owners))` in both directions, as it was before that commit.
**Context:** `docs/SS-SHARES-BY-NODE-COUNT.md` (the curve), `docs/ENCLAVE-THREAT-MODEL.md`.
**Evidence:** M1–M6 debug fleet, 2026-10-20, with owner departure working end to end.

This document exists because the rejected alternative is attractive enough that someone will
propose it again. The reasoning against it is the non-obvious part.

---

## 1. The rule

An SS interval key's threshold is `getThreshold(len(owners))`, recalculated wherever it is needed.
It rises as the fleet grows and falls as the fleet shrinks. Nothing is stored, and no guard blocks
a fall.

| owners | 1 | 2 | 3 | 4 | 6 | 7 | 10 | 11 | 16+ |
|---|---|---|---|---|---|---|---|---|---|
| threshold | 1 | 1 | 1 | 2 | 2 | 3 | 3 | 4 | 5 |
| margin (owners − threshold) | 0 | 1 | 2 | 2 | 4 | 4 | 7 | 7 | 11+ |

A re-share is triggered by the **owner set changing** — a key is selected when it is deficient
(the fleet grew) or when any listed owner has departed (the fleet shrank) — not by the threshold
changing. So a 3→2 shrink re-shares even though the threshold stays at 1; at threshold 1 that
re-share revokes nothing, because `addSSShare` emits copies of the same key, and exists only to
stop the chain row naming an owner that has gone.

## 2. What was tried, and why it was wrong

`4501f3b2` refused any re-share that would lower the threshold. The motivation was real: threshold
1 is not a weak split but *no* split — `addSSShare` short-circuits and hands every owner the whole
private key — so a routine departure could un-split a key with nothing in the logs calling it a
downgrade.

The refusal was removed for three reasons.

**It could not prevent what it was aimed at.** Refusing does not hold a key at its old threshold.
The threshold is derived from the *listed* owner count, and departed owners stay listed, so it does
not fall as nodes leave — while the number that can actually answer does. A key reading "4 owners,
needs 2" can reach one live owner and be unrecoverable with the row still claiming four. Measured
on the fleet in exactly that state: the audit reported `selected=4 emitted=0` — it identified every
key as needing a re-share and then declined, four times.

**Refusing costs more than weakening.** Dropping to threshold 1 costs defence in depth: one enclave
compromise yields a whole key instead of a share. Under SGX the material is sealed and unreadable to
the operator (`enclave_value_seal.go`), so realising that cost requires an actual SGX break.
Refusing costs the key itself — permanently, along with everything encrypted to that interval — and
requires only that nodes retire. Trading certain, irreversible loss against reduced depth versus a
hypothetical break is the wrong way round.

**There is also a timing trap** that makes any "refuse now, act later" scheme unworkable:
re-sharing a key requires reconstructing it first, which requires `threshold` **live** owners
(`runSSReconstruct`: `if len(shares) < job.threshold` fails). The window for corrective action
closes the moment `live < threshold`. A rule that defers the drop until the owner count forces it
defers past the point where the drop can be performed at all.

## 3. The stored threshold, and why it was rejected

The natural repair is to give each key its own threshold — ratcheted up by growth, never lowered by
shrinkage — so 4→3 keeps a 2-of-3 key instead of collapsing to 1-of-3. Shamir has no objection;
2-of-3 is ordinary. It was rejected anyway.

**It buys one state.** For a 4-owner key the difference is a single row:

| owners | symmetric | stored/ratcheted |
|---|---|---|
| 4 | 2-of-4 | 2-of-4 |
| 3 | 1-of-3 | **2-of-3** ← the entire gain |
| 2 | 1-of-2 | 1-of-2 |
| 1 | 1-of-1 | 1-of-1 |

One step, in a regime the curve already classifies as too small to split, in exchange for a new
proto field, a migration, a ratchet rule, a clamp for the floor, a decision about when the clamp
fires, and three call sites (`addSSShare`, `planSSReconstruct`, the escrow path) that must agree or
a key is split one way and gathered another.

**On larger fleets it does not buy more — it does harm.** An 11-owner key ratchets to threshold 4.
Shrunk to 5 owners it would *hold* 4, leaving margin 1: one node loss from unrecoverable. The curve
says 2 there, surviving three losses. Keeping a threshold sized for a fleet that no longer exists
is not conservative, it is fragile.

**The curve is the policy.** `getThreshold` already encodes the availability/confidentiality
balance at each fleet size. Overriding it with history means a key is held at a setting chosen for
different circumstances. Symmetry is not merely simpler; it is the more correct reading of what the
threshold is for.

**And symmetry cannot strand a key.** Margin is ≥1 at every owner count from 2 upward, so the
reconstruction window of §2 never closes. The failure mode that made the repair seem necessary does
not arise under the rule being repaired.

## 4. What symmetry costs, stated once

When a fleet dips to three owners, those three enclaves receive the key whole. Growing back to four
re-splits it, but the three that saw it keep it — **un-splitting is irreversible even though the
threshold recovers.** A fleet oscillating around four owners therefore spreads whole keys a little
further each time it dips.

Under SGX that is erosion of depth rather than disclosure: the enclaves hold it, the operators
cannot read it. The mitigation is operational — do not run below four owners — and the audit now
reports when custody is getting thin (`AT RISK` / `UNRECOVERABLE` at ERROR, `atRisk=N` on the audit
summary), plus an `UNSPLIT` error at the moment a key stops being split.

## 5. What remains unfixed

**Genesis-era keys.** A chain grows from one node, so every key minted before four pioneers were
addressable was handed out whole and each early enclave holds the key itself. Re-sharing changes
how a secret is split, not what it is; no later re-share can un-know it. What bounds this is
interval key **rotation** — once the fleet is ≥4, newly minted keys are split from birth — so
retiring genesis-era keys matters more than re-sharing them.

**Nothing enforces any of this chain-side.** The keeper validates attestation, generation and
departure eligibility; the threshold rule lives entirely in the enclave. If it ever needs to be
enforced rather than trusted, that is a validation change and a coordinated upgrade.
