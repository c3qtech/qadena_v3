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
- **Foundation-sponsored participation.** Nobody outside the foundation needs QDN to *use* the chain
  — only to hold value or bond stake. Node joins and operation, agency deployments and citizen
  wallets are all paid by fee grant from foundation sponsor accounts, funded by the buckets that
  already name that purpose. See §7; it makes three buckets recurring-cost lines rather than
  one-off grants.

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
| 2 | **A multisig's address derives from its member set + threshold** | Rotation costs a transfer and a new whitelist entry (LATE ARRIVAL §B1) |
| 3 | **A vesting account can never be migrated** — locked coins cannot move | A vesting multisig's membership is **frozen for the schedule's duration** |
| 4 | **Never pre-fund an address destined to become a vesting account** | `account … already exists` (`x/auth/vesting/msg_server.go:192`). **Unrecoverable** |
| 5 | **No plain-key account can send until whitelisted or an eKYC wallet** | code **1159** — multisigs, contracts, group policies alike |
| 6 | **A fully locked account cannot pay ANY fee**, including the fee to delegate its own principal | N1's first run produced NO delegation, **silently**, at `spendable = 0` |
| 7 | **A multisig cannot be made an eKYC wallet via the supported path** | `create-wallet` mints from a fresh mnemonic and overrides `--from`. **Not proven impossible** — LATE ARRIVAL §A |
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
Membership can rotate (LATE ARRIVAL §B1). *Cost:* the bucket's own schedule is policy, not physics.

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

## 7. THE SPONSORSHIP MODEL — how the foundation pays for everyone else

Built and in the tree (`scripts/foundation_sponsor_node.sh`, `veritas_scripts/foundation_authorise_sec.sh`,
`grant_as_foundation` in `scripts/setup_env.sh`). It changes what several buckets are actually
spending on, so it belongs in the token design and not only in the runbooks.

**The principle: nobody outside the foundation needs to hold QDN in order to USE the chain.** They
need it only to hold value or to bond stake. Everything else — joining as a node, onboarding a
citizen wallet, signing a document — is a fee, and fees can be sponsored.

### Three sponsorship domains, each funded by the bucket that already names it

| domain | sponsor identity | funded from | pays for |
|---|---|---|---|
| User onboarding incentives | the **`incentive-pool`** genesis identity | **Adoption Programs (01)** — *"DID onboarding, gas subsidies"* | `create_wallet` incentives. The chain debits this directly; it is not a fee grant |
| Agency deployments (SEC PH / VERITAS) | `foundation-appsvr` + `foundation-users` | **Public Sector Programs (10)** — *"Funds feegrant sponsor account"* | gas for agency operations and for citizen wallets |
| Node joins and operation | `foundation-nodes` (or `treasury` on a test fleet) | **Node Operations (12)** | gas for the join and for SS rotation / re-share, for the life of the node |

The CSV already anticipated all three. What changed is the *shape*: fee grants from a sponsor
account, not bank sends to each recipient.

### Two properties that change how you budget

**Sponsorship is a recurring operating cost, not a grant.** The allowances are `PeriodicAllowance`s
that refill every period, forever. So the *authorised* total is unbounded over time and only the
*per-period* spend is capped. **Budget these buckets by burn rate, not by a one-off figure** — and
the burn rate is not yet measured (see WHAT IS STILL NOT TESTED).

**Fee grants cannot be modified.** `x/feegrant` has only Grant, Revoke and Prune; re-granting over a
live allowance is rejected with *"fee allowance already exists"*. Changing a budget means
revoke-then-regrant, and the gap between them is a window in which the grantee is unsponsored. For a
node that window can cost a full SS rotation interval (~555 blocks), silently. **Size generously up
front** — an over-sized period limit costs nothing, because the money is authorised, not spent.

### Two accounts per agency, not one

For an agency deployment the sponsor is split, and the split is worth the extra account:

- **`foundation-appsvr`** — the agency's own operational wallets. A *fixed* set, known at
  deployment, granted directly and once.
- **`foundation-users`** — citizen wallets, which appear continuously (every onboarding, QR scan and
  key rotation mints one), so the app-server issues their grants at runtime via `x/authz`.

That delegation is unbounded by nature, and keeping it on a separate account confines it to the user
float. It also makes usage independently observable: appsvr burn tracks the agency's processing,
users burn tracks citizen activity, and a divergence between them is a real anomaly signal.

### The agency never holds a foundation key

A fee grant is signed by its **granter**, so a grant drawn on the foundation must be signed by the
foundation. `x/authz` closes that gap: the foundation authorises the agency's admin key ONCE for
`/cosmos.feegrant.v1beta1.MsgGrantAllowance`, and the agency then wraps each grant in a `MsgExec`.
The allowance is the foundation's, the signature is the agency's, and the agency holds a **revocable
permission rather than a key**. Same pattern serves node sponsorship.

### What sponsorship CANNOT cover

- **In-message transfers.** `create_credential_fee` (30php; bulk 10php) is debited from the creator
  *inside* the message (`msg_server_create_credential.go`), not taken as gas. A fee grant pays gas
  and not this, so an identity provider must genuinely hold QDN. It is redistributed to the eKYC app
  and identity owner, so where the agency owns both it largely circulates back — size the float for
  throughput, not cumulative spend.
- **Validator self-bonds.** A stake, not a fee. Deliberately unsponsored: slashing is keyed to the
  infraction height, so a foundation that sponsored the bond would absorb every penalty while the
  operator risked nothing.

### Consequence for `allocations.csv`

Bucket 12's note reads *"1000 self-bond + 100 gas per node"*. Under sponsorship **the 100 gas is no
longer sent** — it is covered by the node's fee grant — and the 1,000 self-bond is a *policy* number,
not a technical floor: the chain enforces only `MinSelfDelegation > 0`. Bucket 12 now funds a
**sponsor float plus whatever self-bond policy requires**, which is a different and probably smaller
shape. Flagged, not edited (HARD RULE 1).

---

## 8. HARD RULES

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

---

# PHASE A — GATING TESTS (COMPLETE)

Run on devnet `qadena_4828-1`. Full evidence in `gating-findings.md`.

**A1–A8, the CosmWasm design: 4 PASS, 3 FAIL, 1 NOT-EXERCISED — it does not pass.**

| # | Test | Verdict |
|---|---|---|
| A1 | cw3-flex carrying `MsgCreatePeriodicVestingAccount` | **FAIL** — the released binary cannot represent the message (§3) |
| A2 | Native 2-of-3 multisig receives a grant, then withdraws | **FAIL** — receives fine, **cannot spend** without a whitelist entry; fix verified |
| A3 | cw3 delegating; rewards withdrawal | **FAIL** — same artifact cause |
| A4 | Vesting grant to a non-eKYC recipient vs the AML ante | **PASS** — allowed; this is **AML gap #2** |
| A5 | Whitelisted cw3 → non-whitelisted recipient | **PASS** |
| A6 | Feegrant, zero-balance account, non-zero gas price | **PASS** — sponsor really paid 122,466,500,000,000 aqdn |
| A7 | AML ante on fee payment vs execution | **PASS** — does not gate a sponsored tx |
| A8 | Genesis balance to a wasm contract address | NOT-EXERCISED — informational |

**N1–N6, the native design: 5 PASS, 1 NOT-EXERCISED, 0 FAIL.** N1 locked-principal delegation;
N2 rewards liquid; N3 unbonding returns locked; N4 threshold-signed authz grant; N5
`StakeAuthorization` delegates without spend power; N6 multisig-eKYC unsettled (LATE ARRIVAL §A).

**Also record:** wasmd exposes `iterator, staking, stargate, cosmwasm_1_1…2_2`
(`wasmkeeper.BuiltInCapabilities()`); cw-plus v2.0.0 **unaudited**; DAO DAO cw-vesting v2.7.1
**Oak-audited**, and ships as `-staking` / `-no_staking` variants differing by exactly
`requires_staking`.

---

# PHASE B — GENESIS PIPELINE

## Deliverables — none of these exist yet

```
tokenomics/
  allocations.csv          # human-owned
  build_genesis.py         # CSV -> genesis.json
  verify_genesis.py        # assertions, exit 1 on failure
  export_unlock_schedule.py
  README.md                # SHA256, conventions, findings refs
```

## allocations.csv

Columns: `bucket_id,bucket_name,pct,tokens_qdn,genesis_type,genesis_address,permanent_home,
cliff_days,vest_months,cliff_release_pct,stakes,circulating,custody_final,notes`

- `tokens_qdn` is whole QDN. Convert ONCE at load: `aqdn = qdn * 10**18`.
- Rows sharing a `bucket_id` are one bucket (Node Ops = reserve + N validator rows). Percentages are
  per-bucket; token sums are per-row.
- `genesis_type`: `native_msig` → plain BaseAccount at the multisig address; `base` → plain
  BaseAccount (validator operators).
- **No vesting accounts and no contracts exist at genesis.** All schedules are applied post-launch.
  `cliff_days`/`vest_months` describe the terms grants must carry.
- Never emit module accounts.
- `bucket_id` **08 and 11 are intentionally absent.** Ten buckets, not twelve.

> **The `permanent_home` and `custody_final` columns still describe the superseded cw3/cw-vesting
> design.** Under this brief the destinations are native multisigs (Patterns A/B, §5). The CSV is
> human-owned (HARD RULE 1), so it is flagged here rather than edited.

## Genesis contents

1. 10 bucket BaseAccounts at **native multisig addresses** + 1 validator BaseAccount (**10,100 QDN**:
   10,000 gentx self-bond + 100 gas). The self-bond matches the `min-self-delegation` floor, so the
   genesis validator and every later joiner share one number. **It is NOT sponsored** — it
   bootstraps the chain, so both halves are real.
2. One gentx — single genesis validator; the set grows one by one post-launch via D2.
3. **`scannedContractWhitelistList` entries for all ten buckets plus the validator:**
   ```yaml
   scannedContractWhitelistList:
     - address: <bucket address>
       codeID: 0
       reason: "<bucket name> genesis custody"
   ```
   Without these the chain launches with buckets that **cannot move a single token** until ten
   governance proposals run.
4. Denom metadata (exponents explicit, symbol uppercase):
   ```json
   { "description": "The native token of the Qadena network",
     "base": "aqdn", "display": "qdn",
     "name": "Qadena Token", "symbol": "QDN",
     "denom_units": [ {"denom":"aqdn","exponent":0},
                      {"denom":"qdn","exponent":18} ] }
   ```
5. Mint params: `mint_denom: aqdn`, `inflation_min = inflation_max = "0.010000000000000000"`,
   `inflation_rate_change: "0"`, `blocks_per_year` from **measured** block time.
6. **`intervalPublicKeyIDList` must carry an `incentive-pool` entry** whose `nodeID` and `nodeType`
   are both exactly `incentive-pool`, pointing at the Adoption Programs bucket address. The lookup
   constants are hardcoded and the chain **panics on the first wallet creation** without it.
7. **No contract addresses, no code IDs, no cw-* anything, no `x/group` state.**

## verify_genesis.py — hard assertions

1. distinct-bucket pct sum == 100 (integer)
2. all-row `tokens_qdn` sum == 4_000_000_000
3. per bucket: row sum == `4_000_000_000 * pct // 100`
4. total aqdn across accounts == `4000000000000000000000000000` == bank.supply
5. no duplicate addresses; all bech32-valid with the chain prefix
6. no module-account names present
7. denom metadata: base aqdn, display qdn, symbol QDN, exponents 0 and 18 explicit
8. no amount field anywhere uses `qdn` as denom
9. every amount is a JSON string
10. mint: `inflation_min == inflation_max == 0.01`, `blocks_per_year` non-default
11. no second emission path (grep for epoch hooks / BeginBlocker transfers to `fee_collector`)
12. exactly one validator row of exactly **10,100 QDN**, matching exactly one gentx, and its
    self-bond portion (10,000 QDN) equal to the `min-self-delegation` policy floor
13. every `native_msig` row has a non-placeholder address before a mainnet build (placeholder
    allowed in dev builds; an assert flag distinguishes)
14. **every bucket address and the genesis validator address appears in
    `scannedContractWhitelistList` with `codeID: 0`**
15. **`intervalPublicKeyIDList` contains an entry with `nodeID == nodeType == "incentive-pool"`**,
    and its `pubKID` is the Adoption Programs bucket address and is bech32-valid (the PubKID *is*
    the address). Without it wallet creation panics.
16. **chain_id matches `<name>_<eip155>-<epoch>`** and the numeric part is the intended EIP-155 ID
    (HARD RULE 7 — the parse fails silently otherwise)

Then `qadenad validate-genesis`, then boot a throwaway devnet from the file and assert: every
account spendable == its genesis balance (nothing locked at genesis), `q bank total` matches
assertion 4, the single validator produces blocks, and `eth_chainId` returns the expected value.

## export_unlock_schedule.py

Monthly CSV from TGE to month 120: per-bucket unlocked amounts (from the terms columns, as if grants
are issued at TGE — label this assumption), cumulative circulating (driven by the `circulating`
column), and projected minted supply at 1%. State circulating % against the moving total. TGE
circulating should be ~56.0M + validator floats (~1.4%); if far off, report, don't adjust.

---

# PHASE C — WEEK 1

No code deployment, no instantiation, no migrate admins, no code IDs.

If Phase B step 3 was done, **there is nothing to do for the eight Pattern-B buckets** — already
funded, already whitelisted, already spendable by their thresholds.

1. Verify each bucket balance to the aqdn against `allocations.csv`.
2. Verify each bucket address is on the whitelist:
   `qadenad query qadena scanned-contract-whitelist`.
3. For the two Pattern-A locked buckets (LTR 600M, Foundation 504M), **in this order**:
   a. create the fresh custody multisig (4-of-7 recommended);
   b. AML-whitelist it by `x/gov`;
   c. `MsgCreatePeriodicVestingAccount` from the genesis escrow to it.
   **Never fund the address first** (HARD RULE 9).
4. **Send each locked account a gas float**, then delegate the locked 504M across member validators
   (N1). Record per-validator amounts.

   > A fully locked account has `spendable = 0` and cannot pay the fee to submit its own delegation.
   > Without a float or standing feegrant **the 504M never bonds and the ~7.9% staker APR behind the
   > 1% inflation rate does not materialise.**
5. Split Foundation: 56M liquid in its genesis multisig, 504M to step 3.
6. Optionally issue `StakeAuthorization` grants (N5) so a delegation manager can run the validator
   programme with no spending power.
7. Publish: address map, thresholds and signer sets, the unlock schedule, genesis SHA256, and the
   decision-record scheme (§4).

Pattern-A genesis escrows are now empty scaffolding. **Pattern-B bucket multisigs are not** — they
remain the live custody accounts.

---

# PHASE D — OPERATING RUNBOOKS

### D1. Vesting grant
1. Recipient supplies a **brand-new** `eth_secp256k1` address, never funded. For a large grant, a
   personal n-of-m multisig — but settle the custody choice in LATE ARRIVAL §A first.
2. Owning bucket: collect threshold signatures on `MsgCreatePeriodicVestingAccount`.
   `start_time` = TGE for founders/backers (backdated); grant date for personnel/partners. First
   period is the cliff; the final period absorbs the rounding remainder; periods sum EXACTLY.
3. **Whitelist the recipient by `x/gov`** — required for a multisig, not required for an eKYC wallet.
4. THEN send the gas float. Never before (limit 4), and never omit it (limit 6).
5. Log in the public grants register with the decision reference from §4.

### D2. Node onboarding — toll-free, and implemented

A node joining the network needs **no QDN and no treasury of its own**. Built and wired:

```sh
# on the joiner (or via the fleet driver)
add_full_node.sh --pioneer <name> --foundation-sponsored [<granter-addr>] ...

# on a box holding the foundation key, between the two runs
foundation_sponsor_node.sh --node <pioneer-address> [--granter <key>]

# whole fleet, one flag
fleet_bringup_with_tests.sh --foundation-sponsored ...
nth_node_bringup.sh        --foundation-sponsored ...   (phases 3 and 4)
```

Instead of waiting for a balance, `add_full_node.sh` waits for a **fee grant** and passes
`--fee-granter` to `sync-enclave`. `nth_node_bringup` phase 3 issues that grant in place of its
bank send, so the fleet path is automated end to end with no manual foundation step.

**The grant covers the node's whole life, not just the join.** `sync-enclave` broadcasts three
messages, but `UpdateHeight` runs per block and drives SS rotation and re-share, which broadcast two
more:

```
MsgPioneerAddPublicKey                join + SS rotation
MsgPioneerUpdateIntervalPublicKeyID   join + SS rotation + InitEnclave
MsgPioneerUpdatePioneerJar            join + InitEnclave
MsgPioneerUpdatePublicKey             SS RE-SHARE
MsgPioneerUpdateJarRegulator          InitEnclave
```

A join-only or expiring grant is a **trap**: the node joins, runs, and then fails its first SS
rotation — unable to pay for a message its grant does not list — while still looking healthy. SS
participation is consensus-relevant here. So the default is a recurring `PeriodicAllowance` over all
five, with no expiry, bounded by a per-period budget and the message allow-list.

**Why the join is still two runs.** `add_full_node.sh` mints the pioneer key with a plain
`keys add` — random, no mnemonic — so the address does not exist until the first run has happened
and nobody can grant to it beforehand. That predates sponsorship; it is why `--stop-for-funding`
exists. Supplying the operator's key instead of minting one would collapse it to a single run, at
the cost of moving key custody earlier.

**What is still the operator's own money: the self-bond.** `--stake` is unaffected.

There is **no chain floor** — x/staking checks only that the bond is positive, that the operator's
declared `MinSelfDelegation` is positive, and that the bond is not below that declaration; x/qadena
adds no gate. The chain would accept 1 aqdn.

**The floor that applies is policy: 10,000 QDN**, set as `validators.first().app.min-self-delegation`
in `config/config.yml` and read by `convert_to_validator.sh` for the genesis validator and every
joiner. Under `--foundation-sponsored` that script does not sponsor the bond — it *reduces* it to
exactly this floor (110,000 -> 10,000 QDN), because voting power comes from the foundation's
delegation and bonding eleven times the minimum buys nothing.

Leaving it unset is not neutral: `convert_to_validator.sh` falls back to **1 aqdn**, says so, and
proceeds. The decision is now recorded in `config/launch-config.yml` alongside the staking params.

It is a **promise, not an entry fee** — fall below it and the validator is permanently unbonded.

#### Undelegation and slashing — the timing rule that matters

**The foundation can undelegate at any time.** `MsgUndelegate` has no timing gate. Three practical
limits:

- `max_entries` (7 on this chain) concurrent unbonding entries per (delegator, validator) pair — the
  8th is refused until one matures;
- tokens take the full `unbonding_time` (21 days at mainnet settings) to become liquid;
- for the locked 504M this is safe: **unbonding returns the principal still locked** (N3, TESTED).

**But undelegating does NOT escape a slash.** This corrects the natural reading of "misbehaving node
→ foundation redelegates away". Slashing is keyed to the **infraction height**, and
`x/staking/keeper/slash.go` spares an unbonding entry only under two conditions:

```go
if entry.CreationHeight < infractionHeight { continue }  // you left BEFORE it happened
if entry.IsMature(now) && !entry.OnHold()  { continue }  // unbonding already completed
```

So:

| when the foundation leaves | slashed? |
|---|---|
| Undelegated **before** the infraction | **No** — that stake did not contribute |
| Undelegated **after** the infraction, still unbonding | **YES** — on `InitialBalance`, at the full slash factor |
| Unbonding already **matured** | No — and an infraction older than an unbonding period is not actionable (`Slash()` CONTRACT) |

**Redelegation is caught identically** — `SlashRedelegation` carries the same two conditions. Moving
the stake instantly to another validator does not move it out of reach.

The consequence for the member agreement: **redelegating away on the news is not a remedy.** A
double-sign is typically discovered after the fact, so the infraction height precedes the
foundation's reaction and the slash lands regardless. Redelegation limits *future* exposure only.
State this plainly — the operator's self-bond is small (see NODE ONBOARDING AT MINIMUM COST), so the foundation absorbs
substantially all of any penalty, and it cannot opt out after the event.

> **Untested and potentially significant.** The 504M is a **vesting account's** delegation. When a
> vesting account is slashed, `delegated_vesting` / `delegated_free` must be adjusted, and whether
> that accounting stays correct — i.e. whether a slash can leave locked tokens spendable, or
> over-lock the account — was not exercised here. Test before the 504M is delegated in anger.

### D3. Agency deployment economics (SEC PH / VERITAS) — how to minimise their tokens

Derived from `testscripts/setup_veritas.sh` and `veritas_scripts/step_1..3.sh`. The test deployment
funds, per run: `sec-treasury` **2,000,000 QDN**, plus `provideramount` / `signeramount` /
`createwalletsponsoramount` of **100,000 QDN each**, the last two split across `count+1` = 31
accounts. (The 10M pioneer stake and the 2×10M governance deposits in that script are test scaffolding
and refundable — not part of an agency's allocation.)

Almost all of that is reducible. There are exactly **four** cost categories, and only one of them
resists sponsorship.

#### 1. Wallet creation — ALREADY toll-free, but the grant is unbounded

`tx qadena create-wallet` issues a feegrant automatically. `tx_create_wallet.go:105` builds an
`AllowedMsgAllowance` from the `create-wallet-sponsor` to the newly minted wallet, restricted to:

```
/qadena.qadena.MsgAddPublicKey
/qadena.qadena.MsgCreateWallet
```

So a VERITAS-platform user never needs tokens to *get* a wallet. **Nothing to build here.**

> **Fix before mainnet.** The inner allowance is a bare `BasicAllowance{}` — **no spend limit and no
> expiration**. Every wallet ever created holds a permanent, unlimited claim on the sponsor for those
> two message types. One misbehaving client can drain the sponsor by re-sending them. Set a
> `SpendLimit` and an `Expiration` sized to one onboarding.

#### 2. Document signing — CAN be fully toll-free, and TODAY IT IS NOT

**VERITAS does not use CosmWasm.** Signing runs through the chain's own **`x/dsvs`** module
(Digital Signature Verification Service), which the appsvr imports directly as
`dsvstypes "github.com/c3qtech/qadena_v3/x/dsvs/types"` (`api/handlers/document.go:15`).

The message types (`proto/qadena/dsvs/tx.proto`, package `qadena.dsvs`):

```
/qadena.dsvs.MsgCreateDocument
/qadena.dsvs.MsgSignDocument
/qadena.dsvs.MsgRegisterAuthorizedSignatory
/qadena.dsvs.MsgRemoveDocument
```

**These are gas-only.** `bankKeeper` appears in `x/dsvs/keeper/keeper.go` as a struct field and is
never used by any dsvs message server — no `SendCoins`, no in-message fee. Unlike credentials (§3),
nothing is debited from the signer beyond the transaction fee. **So signing is fully sponsorable.**

**The gap.** The appsvr already issues feegrants (`api/handlers/fee_grant.go:50`), but its
`AllowedMessages` list is:

```
/qadena.qadena.MsgAddPublicKey          /qadena.qadena.MsgUpdateCredential
/qadena.qadena.MsgCreateWallet          /qadena.qadena.MsgClaimUpdatedCredential
/qadena.nameservice.MsgBindCredential   /qadena.nameservice.MsgUnbindCredential
```

**No dsvs message is on it.** So a wallet created through the VERITAS platform is toll-free to
onboard and to manage its credential — and then must hold QDN to sign anything. That is exactly the
step users actually perform, and it is the only one they pay for.

**The fix is three lines** in `api/handlers/fee_grant.go`. Add to `AllowedMessages`:

```go
"/qadena.dsvs.MsgCreateDocument",
"/qadena.dsvs.MsgSignDocument",
"/qadena.dsvs.MsgRegisterAuthorizedSignatory",   // only if signatories self-register
```

After that a VERITAS signing wallet needs **zero QDN, ever**. This is the single highest-value
change in this section, and it removes the reason to pre-fund signer accounts at all — the tested
layout funds 31 of them by direct bank send.

> A6 proved the mechanism end to end on this chain: a **zero-balance** account executed a sponsored
> transaction at a forced real gas price and the sponsor's balance fell. A6 used
> `MsgExecuteContract`; the allowance mechanism is message-type agnostic, so the same construction
> works for dsvs messages. **The dsvs case itself is untested** — verify before rollout.

#### 3. Credential issuance — CANNOT be made toll-free by feegrant

This is the one that resists, and it is worth understanding precisely.

`msg_server_create_credential.go:289`:

```go
k.bankKeeper.SendCoinsFromAccountToModule(ctx, creatorAddress, types.ModuleName, totalIncentivesCoin)
```

The fee is **debited from the creator's own balance inside the message**, then redistributed to the
eKYC app, the identity owner, and any reused identity provider. **A feegrant pays gas; it does not
pay this.** The account issuing credentials must actually hold QDN.

Current params (`config/config.yml:284`):

| param | value |
|---|---|
| `create_credential_fee` | `30php` |
| `create_bulk_credentials_fee` | `10php` |
| `update_credential_fee` | `30php` |

Fiat-denominated and converted through the pricefeed, so the QDN cost moves with `cn:qdn:php`.

Three levers, in order of preference:

1. **Use bulk issuance.** `10php` against `30php` is a 3× reduction for onboarding runs, which is
   what an agency deployment mostly does.
2. **Note that the fee largely returns.** It is an incentive redistribution, not a burn. Where the
   agency owns *both* the identity provider and the eKYC app, most of each fee circulates back to
   accounts it controls. Size the float for throughput, not for cumulative spend.
3. **Lower the params by governance** for a launch period, if the incentive flow is internal anyway.
   These are module params, so it is an `x/gov` proposal, not a code change.

**Do not** try to solve this with a feegrant. It will appear to work — the transaction succeeds —
while the fee comes from the creator regardless.

#### 3a. What is already BUILT for VERITAS

`setup_veritas.sh --fund-mode feegrant` (now the default) stands the deployment up with **no SEC
treasury at all**: two foundation accounts (`foundation-appsvr`, `foundation-users`),
`foundation_authorise_sec.sh` to authorise SEC's admin for `MsgGrantAllowance`, `step_4.sh` for the
app-server's sponsor pool, and `grant_as_foundation` doing the authz-wrapped grants. The old
`--fund-mode banksend` path is kept for a deployment mid-migration.

Note what that removed: the AML whitelist exemption `sec-treasury` needed. A treasury making direct
transfers looks exactly like the pattern the AML scanner exists to catch; fee grants are not bank
sends, so the hole is no longer needed and is no longer opened.

#### 4. Direct funding — replace with sponsorship

`step_3.sh` funds providers and users by `tx bank send` from `sec-treasury`, which is why that
treasury needs an AML whitelist entry (`setup_veritas.sh` whitelists it before step 3). Every one of
those sends is scanned and threshold-reported.

Replace with feegrants wherever the account only ever *executes* — that removes the transfer, the
scan, the report, and the balance.

#### Recommended minimal agency layout

| account | tested | recommended | why |
|---|---|---|---|
| `sec-treasury` | 2,000,000 QDN | **credential-fee float only** | Sized to expected credential volume × current `qdn:php`, not to a round number |
| identity / dsvs providers | 100,000 QDN each | **credential-fee float** | They are the `creator` that pays §3 |
| create-wallet-sponsor | 100,000 QDN | **small gas float** | Only pays gas for two message types; bound the allowance |
| signer accounts (×30) | 100,000 QDN split | **ZERO** | Feegrant the `x/dsvs` messages instead — §2 |
| end-user wallets | — | **ZERO** | Already covered by the built-in create-wallet feegrant |

**Only the credential-fee float is irreducible.** Everything else is gas, and gas is sponsorable.

> **VERITAS is not a CosmWasm application.** It is a Flutter client (`veritasff/`) plus a Go
> appsvr (`api/`) talking to the chain's native `x/dsvs`, `x/qadena` and `x/nameservice` modules.
> The original brief's D3 said "VERITAS must be built on the CosmWasm/native path"; the native half
> is what is actually built, and every message it sends is feegrantable. Feegrant still does not
> cover `MsgEthereumTx`, so an EVM rebuild would need a relayer or paymaster — out of scope.

**Untested:** a sponsored `x/dsvs` message (§2 — the mechanism is proven by A6, the message type is
not), the bounded-allowance fix in §1, bulk credential issuance, and a sponsored `create-credential`
(expected to pay gas but *not* the in-message fee — verify before relying on that distinction).

---

# NODE ONBOARDING AT MINIMUM COST

D2 grants **10,100 QDN** per node (10,000 self-bond + 100 gas). The gas half goes to zero under
sponsorship; the self-bond half is policy, and deliberately does not.

**There is no chain-wide minimum self-delegation.** The only checks are that the operator's declared
`MinSelfDelegation` is positive (`x/staking/types/msg.go:76`) and that the initial self-bond is not
below it (`ErrSelfDelegationBelowMinimum`). The operator chooses the number. A validator can
therefore self-bond an amount far below 1,000 QDN and still be created.

**Gas is sponsorable**, including validator creation. Grant an `AllowedMsgAllowance` covering:

```
/cosmos.staking.v1beta1.MsgCreateValidator
/cosmos.staking.v1beta1.MsgEditValidator
/cosmos.distribution.v1beta1.MsgWithdrawValidatorCommission
```

from a nodeops-funded native sponsor. The operator then needs **no gas float at all**.

**Voting power comes from the foundation's delegation, not the self-bond** — which is already how
D2 works. The self-bond's only real function is slashing exposure.

So a minimal onboarding is: **a token self-bond + a feegrant**, and the foundation delegates the
stake that actually matters. Sponsorship therefore removes the 100 QDN gas entirely and leaves the
10,000 QDN self-bond, which is the number the policy floor exists to set.

**The trade-off is a governance decision, not a technical one.** Self-bond is the operator's skin in
the game. At 1,000 QDN they have something to lose; at 1 QDN they have nothing, and D2 already notes
that **slashing hits foundation principal**. Driving the self-bond to the floor makes a consortium
validator entirely free to misbehave, with the foundation absorbing every penalty. Recommend setting
it by *intended* exposure and stating that intent in the member agreement — not by what the chain
will tolerate.

Note also `min_commission_rate` (5% on this chain): commission is the operator's income, so a node
is self-funding from month one regardless of how small the self-bond is.

**Untested:** a feegranted `MsgCreateValidator`, and validator creation at a self-bond below 1,000
QDN. Both are expected to work from the code above; neither was exercised.

---

---

# LATE ARRIVAL — founders, council members, operators

Almost nobody's address is known at genesis. This section is the complete answer to what that costs.

**There are two distinct problems and they have opposite answers.** Conflating them is the mistake
to avoid: one is routine and fully solved, the other contains the single irreversible decision in
the whole design.

---

## A. A GRANT RECIPIENT arrives late — solved, this is the designed case

Founders, backers, personnel, partners. `allocations.csv` already encodes it: the bucket exists at
genesis, the recipient does not.

**What happens:** the owning bucket collects threshold signatures on
`MsgCreatePeriodicVestingAccount` to the new address whenever it arrives. Backdate `start_time` to
TGE for founders and backers so everyone shares one clock regardless of when they actually appear.

**Four options for the recipient**, best first:

| option | whitelist needed? | trade |
|---|---|---|
| **Escrow now, grant later, whitelist at grant time** | yes — one `x/gov` proposal | The intended shape. TESTED |
| **Recipient uses an eKYC'd single-key wallet** | **no** | Spends immediately; single-key custody, total loss on key loss |
| **Sponsor them instead** (feegrant) | **no** | Only works if they never move value by bank send — an agency, not a holder. TESTED (A6/A7) |
| Pre-generate addresses into cold storage, seed at genesis | no — seeded | Forbidden by HARD RULE 5; concentrates key-generation risk. Small fixed sets only |

**Cannot:** add to the **genesis** whitelist after launch. Genesis is immutable; afterwards there is
only `x/gov`, one proposal per address.

### The custody choice you must settle before their address is generated

**Multisig custody and eKYC spending are currently mutually exclusive** (§4 limit 7), and this cannot
be changed afterwards.

| | multisig custody | eKYC single-key wallet |
|---|---|---|
| key loss | survivable (n-of-m) | **total loss** |
| can spend | only after a governance whitelist | immediately |
| foundation involvement | approves the whitelist once | none |
| rotation during vesting | **frozen** (§4 limit 3) | n/a |

**Not proven impossible.** `create-wallet` mints from a fresh mnemonic and overrides `--from`, so the
CLI cannot target an existing address — but `msg_server_create_wallet.go` sets
`walletID := msg.Creator`, i.e. the signer, so a hand-crafted `MsgCreateWallet` signed by a multisig
is untested. A separate obstacle may bite first: a credential encodes a **person's** residency and
citizenship, so attaching one to an n-of-m account asserts a group has a nationality. **Resolve this
before the consortium agreement fixes founder custody terms.**

---

## B. A COUNCIL MEMBER arrives late, or leaves — this is the hard one

Three sub-cases, by what the account is.

### B1. A Pattern-B liquid bucket — possible, costly, repeatable

The address derives from the member pubkeys and threshold, so any change yields a **new address**:

```
create new multisig -> x/gov whitelist it -> transfer the full balance
                    -> verify to the aqdn -> retire the old address
```

Cost per change, per bucket: one governance proposal, one large transfer, one AML report, and a
window where both addresses hold funds. Workable. Not something to do casually, and it is **per
bucket** — reseating one council across eight buckets is eight of these.

### B2. A Pattern-A locked vesting account — **IMPOSSIBLE**

Locked coins cannot be transferred, so the account can never be migrated (§4 limit 3). **The signer
set is frozen for the entire schedule: 10 years for the LTR, 6 for the Foundation tranche.**

There is no workaround. Not authz, not governance, not a migration. If a signer dies, leaves, or
loses a key, the remaining members must still meet the threshold for the rest of the term.

**This is the one irreversible decision in the design.** Everything else can be corrected later.

Mitigate at creation, because you cannot mitigate afterwards:
- **Wide thresholds.** 4-of-7 tolerates three simultaneous absences over a decade; 2-of-3 tolerates
  one. Never use 2-of-3 for a Pattern-A account.
- **Roles, not individuals**, where custody is institutional — a role's key can be handed on inside
  the organisation without touching the chain.
- **Put anything that might need to change behind `x/authz`** from the account, not in the signer set.

### B3. Operational authority only — free, and the address never moves

`x/authz` grant and revoke. The custody multisig stays fixed forever, so its address and whitelist
entry never change; operators come and go. TESTED (N4): the multisig's 2-of-3 signed a `MsgGrant`,
and a brand-new operator key — **no eKYC, no whitelist entry of its own** — then spent from the
multisig. Onboarding an operator costs nothing: no whitelist, no eKYC, no governance.

| authorization | bounds |
|---|---|
| `SendAuthorization` | spend limit (auto-decrementing) + recipient allow-list |
| `StakeAuthorization` | delegate / undelegate / redelegate, validator allow or deny list, max amount |
| `GenericAuthorization` | any message of one type URL — the blunt one; prefer the others |

All accept an **expiration**. Use it; an unexpiring grant is a standing key.

---

## What `x/authz` does NOT give you

It is the workhorse of B3, and it is **not** a substitute for `x/group`. Mapped against the six
things `x/group` demonstrably provided (all TESTED, findings §14):

| x/group property | x/authz |
|---|---|
| Execution from a stable account address | **yes** — the granter is the fixed multisig |
| Change who may **act** without moving the address | **partial** — changes who executes, not who approves |
| On-chain proposal object, recorded votes, tally | **no** — there is no proposal and no vote |
| Chain-enforced **threshold per action** | **no** — a grant is unilateral, effectively 1-of-1 |
| Change the threshold without moving the address | **no** — there is no decision policy to change |
| Weighted votes | **no** |

**N4 demonstrates the limitation without having been designed to:** a single operator key, acting
alone, moved funds out of a 2-of-3 multisig. That is authz working correctly, and it means

> **`x/authz` moves the threshold from "every action" to "granting the authority".**

Once granted, the operator acts alone within its bounds until revoked. You keep n-of-m over *who
gets authority* and lose it over *each use*. Spend limits, allow-lists and expiry are the
containment — not the multisig. Keep grant creation and revocation behind the threshold; that is
where the n-of-m still bites.

### The irreducible gap

**"Per-action threshold AND an on-chain record, for a named council" has no native answer.**

- Native multisig — per-action threshold, but signatures collected **off chain**
- `x/gov` / Pattern C — on-chain proposals and votes, but **stake-weighted**, not a named council
- `x/group` — both, and **licence-blocked** (§3)

If on-chain vote records for routine disbursement turn out to be a hard requirement — from a
regulator or the consortium agreement — native custody is not sufficient and there are three honest
routes: **Pattern C** (community pool); **buy the Cosmos Enterprise licence** for `x/group`, which
demonstrably works; or **DAO DAO contracts** (`dao-proposal-single` + `dao-voting-cw4`), Oak-audited
and built *with* the stargate feature so unlike cw-plus they can carry vesting grants — though they
do not declare `requires_staking`, so the 504M stays a native vesting multisig regardless.

Otherwise: **native, with the B3 mechanism and wide thresholds**, and the §4 limit-1 audit trail.

---

# OUT OF SCOPE — ask the human

- Any change to percentages, token counts, cliffs, vest durations, thresholds, or the inflation rate
- TGE date; genesis validator count/operators
- The AML/EVM asymmetry fix (separate workstream)
- Legal/securities questions (bucket wording, backer terms, Howey posture)
- Real keys, real addresses, any mainnet execution

---

# OPEN QUESTIONS — these block work

### 1. The genesis account-set conflict — RESOLVED for `treasury`, open for `pioneer1`

**What it was.** §2 says "zero external addresses at genesis except genesis validator operators" and
specifies 11 accounts. But `x/qadena` has a **built-in incentive account** it panics without:

```go
// x/qadena/keeper/helpers.go
incentivePoolIntervalPubKID, found := k.GetIntervalPublicKeyID(ctx, types.IncentivePoolNodeID, types.IncentivePoolNodeType)
if !found { panic(types.ErrGenericIncentivePool.Error()) }   // not an error return
```

`MsgCreateWallet` debits it on **every wallet creation** — 500 + 500 per wallet, 50 per ephemeral
wallet, so ~100M QDN per 100k users (`launch-config.yml`). The PubKID **is** the bech32 address, so
the genesis entry literally names the paying account. It was never an optional bootstrap identity.

**Resolution — no eleventh account is needed.** It now points at the **Adoption Programs bucket**,
whose stated purpose in `allocations.csv` is exactly this: *"Merchant incentives, DID onboarding,
loyalty, gas subsidies."* The onboarding budget therefore comes from the bucket that was always
meant to fund it, rather than from an allocation nobody sized. The pool **never signs** — the keeper
debits it via `SendCoinsFromAccountToModule` — so a native multisig serves.

**Also renamed, because it had to happen before genesis.** `nodeID`/`nodeType` are **state key
bytes** (`IntervalPublicKeyIDKey` concatenates them), so the value was changeable only while genesis
was still unwritten. `treasury` → **`incentive-pool`**, naming the ROLE rather than the funder:
"treasury" collided three ways — this account, the Foundation Treasury bucket (03, 560M), and a
deployment's `sec-treasury`. Naming it `adoption` was rejected as it would couple a chain constant
to the token design and become a lie if funding ever moved.

Changed: `types.IncentivePoolNodeID` / `IncentivePoolNodeType`, `ErrGenericIncentivePool`,
`getIncentivePoolPubKID` / `getIncentivePoolAddress`, and the `intervalPublicKeyIDList` entries in
both `config/config.yml` and `config/launch-config.yml`. The `Treasury` **query RPC keeps its proto
name** — renaming that is a breaking API change and a separate decision.

**Consequences to action:**
- **Every existing chain must be re-genesised** — the state key moved. Devnet `qadena_4828-1` and the
  M1–M4 / SGX fleet. An old-genesis chain on a new binary **panics on the first wallet creation**.
- **UNTESTED:** that a multisig actually serves as this identity. The code says it must (keeper-side
  debit, no signature), but that is a read, not a run. **Verify before mainnet genesis.**

**Still open: `pioneer1`.** It needs `publicKeyList` entries (transaction *and* credential pubK) and
an `intervalPublicKeyIDList` entry with nodeType `pioneer`. It is a node identity with credential
keys, not a funding account, so it does not resolve the same way — but it is arguably **already in
scope** under §2's "except genesis validator operators" exception. Confirm that reading, or decide
otherwise.

### 2. `allocations.csv` end-states are stale

`permanent_home` and `custody_final` still name `cw3-*` and `cw-vesting` destinations from the
superseded design. Under this brief they are native multisigs (§5). The file is human-owned
(HARD RULE 1) so it has not been edited.

### 3. Whether a multisig can hold an eKYC credential

Unsettled — see the custody-choice note above. Worth resolving **before** the consortium agreement
fixes founder custody terms.

---

# WHAT IS STILL NOT TESTED

1. **A full bucket lifecycle end to end** — genesis multisig, fund, pay out, rotate, whitelist,
   transfer, pay out again. Each leg is tested; the sequence is not.
2. **Multisig rotation as one operation** (§9 mechanism 1) against a funded bucket.
3. **Slashing a vesting account's delegation** — whether `delegated_vesting`/`delegated_free`
   accounting survives a slash correctly. Directly affects the 504M. See D2.
4. **`authz revoke`** — never exercised, and it is the half of mechanism 2 that matters when someone
   leaves. **Items 2 and 3 together are the highest-value remaining work**: they are the two halves
   of "how does a council actually change".
4. **A hand-crafted `MsgCreateWallet` signed by a multisig** (LATE ARRIVAL §A). Would overturn limit 7 if it
   works.
5. **Thresholds beyond 2-of-3.** The design uses 3-of-5 to 5-of-7 and recommends 4-of-7 for locked
   accounts; nothing suggests they differ, but they were not exercised.
6. **Grants from a locked vesting account over only its vested tranche** — N4's granter had a gas
   float.
7. **`MsgWithdrawDelegatorReward` across multiple validators** — N2 used one; the 504M spans many.
8. **Pattern C** (community pool) entirely.
9. **A3's rewards leg via a contract**, and the cw-vesting contracts, were never instantiated —
   irrelevant if native is adopted, but the original brief's Phase C depends on them.
10. **Sponsored node join and operation, end to end.** `--foundation-sponsored` is wired through
    `fleet_bringup_with_tests.sh` -> `nth_node_bringup.sh` -> `add_full_node.sh` and passes syntax
    and help checks, but has never run against a live chain: the fleet is wiped and
    `foundation_sponsor_node.sh` is not yet in the installed package. **The first sponsored bringup
    should also MEASURE GAS BURN** — the 1000qdn/30-day default is judgement, not evidence, and §7
    says these buckets must be budgeted by burn rate.
11. **A sponsored `x/dsvs` message.** Adding the three dsvs types to the appsvr's feegrant allow-list
    is the change that makes VERITAS signing toll-free; A6 proves the mechanism for a different
    message type, not for these.
12. **Revoke-then-regrant of a live node grant**, and whether the gap costs a rotation interval in
    practice.
13. Single chain, single run, single validator, no SGX. `unbonding_time` was reduced to 120s by
    governance for N3; mainnet's 21 days is untested at that duration.
