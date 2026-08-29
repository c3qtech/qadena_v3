# QADENA Token Launch — Master Brief

**The single source for the token launch.** Supersedes the earlier CosmWasm-custody master brief,
`qadena-genesis-brief.md`, `qadena-build-brief.md`, and the genesis portions of
`qadena-dev-mode-brief.md`. There is no separate native brief — this is it.

Custody, vesting, staking, delegated authority and fee sponsorship are **all core Cosmos SDK**. No
smart contracts, no licensed modules.

Every capability claim is marked **TESTED** with its evidence or flagged untested. Transaction
hashes, heights and result codes live in `gating-findings.md`; harnesses are
`testscripts/test_token_gating.sh` (A1–A8) and `testscripts/test_native_custody.sh` (N1–N6).

---

## 1. CONFIRMED ENVIRONMENT (do not re-derive)

Established on devnet `qadena_4828-1`:

- Cosmos SDK v0.53.5 · CosmWasm present · Cosmos EVM v0.5.1 (pre-audit, v0.x)
- Base denom `aqdn`, 18 decimals. Display `qdn` — **never** in an on-chain amount.
- `x/bank` stores full-precision aqdn; `x/precisebank` is a passthrough. Ignore.
- Vesting: vanilla `cosmos-sdk/x/auth/vesting`.
- **Vesting locks hold against the EVM** — EVM balance reads resolve to `SpendableCoin()`. Verified
  at the exact boundary. Re-test if any precompile is activated (`active_static_precompiles` is `[]`).
- Locked tokens CAN be delegated; **unbonding returns them still locked** (N3). Staking rewards are
  LIQUID immediately (disclosure item).
- Backdated vesting `start_time` is accepted; elapsed periods become spendable.
- **A fully locked account cannot pay ANY fee** — see §4 limit 6.
- **AML gate (code 1159)** blocks Cosmos bank sends between unidentifiable parties but does NOT gate
  EVM transfers. The asymmetry is a separate workstream.
- Recipient keys: `--algo eth_secp256k1`, brand-new, never funded.

## 2. DESIGN SUMMARY

- **4,000,000,000 QDN initial supply** (uncapped — inflation on; never write "total/max/capped
  supply").
- **Inflation: 1.00% fixed** (`inflation_min == inflation_max == 0.01`). Provisions = rate × total
  supply paid to bonded stake only; bonded stake is ~504M, so 1% → ~7.9% staker APR. Higher rates
  pay absurd yield to a tiny bonded set. `goal_bonded` and `inflation_rate_change` become inert.
- **10 buckets** per `allocations.csv`. Genesis holds each in a native multisig of operator keys.
- **Zero external addresses at genesis** except genesis validator operators — **but see §16, this
  conflicts with `x/qadena`'s own requirements and is unresolved.**
- Consortium model: foundation delegates its locked 504M to member validators; validator commission
  is operator compensation; governance is foundation-controlled and disclosed as such.

---

## 3. WHY NATIVE — the two findings that closed off contracts

**cw-plus cannot do the job.** In `cosmwasm-std` the `CosmosMsg` variants are feature-gated:
`Bank`/`Wasm` always exist, `Staking`/`Distribution` sit behind `feature = "staking"`, `Any` behind
`feature = "cosmwasm_2_0"`. cw-plus has exactly two releases (v1.1.2, v2.0.0) and **both pin
`cosmwasm-std` with no features**. A stock `cw3-flex-multisig` can emit bank sends and nothing else —
no vesting grants (A1 FAIL), no delegation (A3 FAIL). That is also why A5 passed. The remedy would
be a **custom build of an unaudited contract** holding 4B QDN. (cw-plus is explicitly unaudited;
cw-vesting, from DAO DAO, is Oak-audited — the *unaudited* pair is what would custody everything.)

**`x/group` is licence-blocked.** It is the SDK's native cw3+cw4 equivalent, it works here, and it
solves membership cleanly — tested: proposals, votes, execution, delegation, vesting grants, and
membership changes that leave the policy address byte-identical (§14 of the findings). But in **SDK
v0.54.0 it moved to `enterprise/`** under a **Source Available Evaluation License** — production
requires a paid Cosmos Enterprise licence (`sales@cosmoslabs.io`, no public pricing) — and it is
outside the SDK Bug Bounty programme.

This chain runs v0.53.5 where `x/group` is still core and Apache-2.0, which is precisely the trap.
`config/launch-config.yml:437` already states the principle for `x/crisis`, and it binds harder here
because **`x/group` would hold the funds**: launching on it means that at the next SDK major upgrade
you either buy a licence or migrate every bucket on a live chain — including accounts that **cannot
be migrated at all** (§4 limit 3).

v0.54 moves for the record: **enterprise/** `x/group`, `x/poa`; **contrib/** (deprecated)
`x/circuit`, `x/nft`, `x/crisis`. Everything used here — `x/auth`, `x/auth/vesting`, `x/bank`,
`x/staking`, `x/distribution`, `x/gov`, `x/authz`, `x/feegrant` — **remains core**.

---

## 4. WHAT YOU CAN AND CANNOT DO

### CAN — all TESTED

| # | Capability | Evidence |
|---|---|---|
| 1 | n-of-m threshold custody: sign, combine, broadcast | A2 |
| 2 | A multisig **receives** a chain-enforced vesting grant | A2 |
| 3 | A multisig **spends**, once AML-whitelisted | code 0 @ 3732 |
| 4 | **Delegate genuinely LOCKED principal** from a multisig | N1 — `delegated_vesting` 8,000 QDN, `delegated_free` 0 |
| 5 | **Undelegate returns the principal STILL LOCKED** | N3 |
| 6 | Withdraw rewards on locked stake; immediately spendable | N2 |
| 7 | **Threshold-sign an authz `MsgGrant`**; an operator then spends | N4 — operator had no eKYC, no whitelist |
| 8 | **Delegate without granting spend power** (`StakeAuthorization`) | N5 |
| 9 | Pay a brand-new non-eKYC address from a whitelisted bucket | A5 |
| 10 | Issue a vesting grant to a recipient with **no eKYC** | A4 — allowed; AML gap #2 |
| 11 | A **zero-balance** account transacts on a sponsor's fee | A6 |
| 12 | Whitelist a plain address at genesis **or** by `x/gov` (`codeID: 0`) | genesis `config.yml`; proposals 17, 20 |
| 13 | Vesting locks hold against the EVM | `evm-vesting-handoff.md` |

Items 4–6 are the load-bearing set: threshold custody **plus** a real lock **plus** the ability to
stake it **plus** a lock that survives the round trip through staking. N3 closes the one path that
could have unwound everything — `evm-vesting-handoff.md` flagged delegate → undelegate → spend as the
remaining way locked principal might become spendable early. **It does not.**

### CANNOT

| # | Limit | Evidence / consequence |
|---|---|---|
| 1 | **No on-chain proposal or vote record for a bucket spend.** Signatures are collected OFF chain | The price of excluding `x/group`. Mitigation below |
| 2 | **A multisig's address derives from its member set + threshold** | Rotation costs a transfer and a new whitelist entry (§10) |
| 3 | **A vesting account can never be migrated** — locked coins cannot move | A vesting multisig's membership is **frozen for the schedule's duration** |
| 4 | **Never pre-fund an address destined to become a vesting account** | `account … already exists` (`x/auth/vesting/msg_server.go:192`). **Unrecoverable** |
| 5 | **No plain-key account can send until whitelisted or an eKYC wallet** | code **1159** — multisigs, contracts, group policies alike |
| 6 | **A fully locked account cannot pay ANY fee**, including the fee to delegate its own principal | N1's first run produced NO delegation, **silently**, at `spendable = 0` |
| 7 | **A multisig cannot be made an eKYC wallet via the supported path** | `create-wallet` mints from a fresh mnemonic and overrides `--from`. **Not proven impossible** — §11 |
| 8 | Staking rewards on locked stake are liquid **immediately** | N2. A "locked" bucket yields spendable income. Disclose deliberately |
| 9 | Every transfer is AML-scanned and threshold-reported even when whitelisted | Whitelisting removes the *identity* requirement, not the scan |
| 10 | A threshold, once chosen, cannot be changed | No native `update-decision-policy`. Choose for churn up front |

**Mitigating limit 1 — the audit trail.** Put the decision reference in the transaction memo
(`--note "<bucket>-<decision-id>"`) pointing at a published, numbered decision record; publish the
signer set and signed payloads; route anything constitutional through `x/gov`, which *is* on-chain.
**Do not describe this publicly as "on-chain multisig governance".** It is off-chain authorisation
with an on-chain audit reference, and the difference matters to anyone assessing the treasury.

---

## 5. THE THREE CUSTODY PATTERNS

Limits 3 and 4 force the choice: a lock must be created at a **fresh** address, and once created that
address can never change hands.

**Pattern A — chain-enforced lock.** `escrow → MsgCreatePeriodicVestingAccount → <fresh n-of-m
multisig>`. The chain enforces the schedule; the account can delegate (N1) and its lock survives
unbonding (N3). *Cost:* membership frozen for the schedule; needs its own whitelist entry; needs a
gas float (limit 6).

**Pattern B — liquid escrow.** A plain n-of-m holds liquid funds and issues Pattern-A grants.
Membership can rotate (§10). *Cost:* the bucket's own schedule is policy, not physics.

**Pattern C — community pool.** Funds move by `MsgCommunityPoolSpend` governance proposals. Fully
on-chain and permanent — the only native way to get real vote records. *Cost:* control passes to
stake-weighted governance, not a named council, and every payment waits a voting period. Untested.

| bucket | pattern |
|---|---|
| Long-Term Reserve (600M, 10yr) | **A** — its purpose is a credible lock; 4-of-7 or wider |
| Foundation locked tranche (504M, 6yr) | **A** — must be provably locked **and** delegated (N1, N3) |
| Foundation liquid (56M) | B |
| Adoption, Grants, Personnel, Backers, Founders, Contingency, PubSec, NodeOps | **B** — escrows that *issue* locked grants; the locks live in the grants |

Founder, backer and personnel **grants** are always Pattern A.

---

## 6. AML — read before funding anything

Code **1159** (`ErrBankSendNotScannable`) refuses a transfer where a party can be neither identified
nor whitelisted. The enclave has **no fallback for an unidentifiable sender**, deliberately —
otherwise holding no credential would be the cheapest way to get the most permissive threshold.

Despite the name the list takes **any address** with `codeID: 0`; treasury, a plain account, is
seeded that way at genesis. TESTED at genesis and at runtime via `x/gov`.

**Seed every address you know at genesis.** It costs nothing, is verifiable in the genesis hash, and
removes all launch-day governance.

---

## 7. HARD RULES

1. `allocations.csv` is human-owned. Never edit, never invent. Missing value → stop and ask.
2. `genesis.json` is a build artifact. Never hand-edit.
3. Integer arithmetic only (Python `int`). No floats near amounts.
4. Every JSON amount is a **string**.
5. Never generate or commit real keys or mnemonics. Addresses arrive as CSV strings.
6. Verification exits non-zero on first failure, naming the bucket.
7. Chain-ids must match `<name>_<eip155>-<epoch>` — the EVM chain ID is **parsed** from it and a
   mismatch **fails silently**. Devnet `qadena_4828-1`, testnet `qadena_4824-1`, mainnet
   `qadena_482-1`. (4444 is Htmlcoin Mainnet — a live replay risk, not a naming clash.)
8. A gating failure is reported, not designed around.
9. **Never pre-fund an address due to become a vesting account.** Unrecoverable.
10. **Every locked account needs a gas float or feegrant before it can act.** The failure is silent.
11. **Whitelist before funding, always.** The wrong order fails inside the block, having spent the fee.
12. **Choose thresholds for churn at creation.** They are immutable; for locked accounts so is the
    membership.
