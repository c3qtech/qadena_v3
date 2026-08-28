# QADENA Token Launch — ALL-NATIVE Custody Brief

Supersedes the CosmWasm custody design in `qadena-master-brief.md`. **No smart contracts, and no
licensed modules.** Custody, vesting, staking, delegated authority and fee sponsorship are all core
Cosmos SDK.

Token economics are UNCHANGED. `allocations.csv` remains the authoritative, human-owned source:
4,000,000,000 QDN initial supply, ten buckets, 1% fixed inflation. Only the *custody mechanism*
changes.

Every capability claim below is marked **TESTED** with its evidence, or explicitly flagged as
untested. Transaction hashes, heights and result codes are in `gating-findings.md` (§1–§15);
harnesses are `testscripts/test_token_gating.sh` (A1–A8) and `testscripts/test_native_custody.sh`
(N1–N6).

---

## 1. WHY NATIVE

Two independent findings closed off the contract route.

**cw-plus cannot do the job.** In `cosmwasm-std` the `CosmosMsg` variants are feature-gated:
`Bank`/`Wasm` always exist, but `Staking`/`Distribution` sit behind `feature = "staking"` and `Any`
behind `feature = "cosmwasm_2_0"`. cw-plus has exactly two releases (v1.1.2, v2.0.0) and **both pin
`cosmwasm-std` with no features**. So a stock `cw3-flex-multisig` can emit bank sends and nothing
else — no vesting grants (A1 FAIL), no delegation (A3 FAIL). The remedy would be a **custom build of
an unaudited contract** holding 4,000,000,000 QDN.

**`x/group` is licence-blocked.** It is the SDK's own cw3+cw4 equivalent, it was tested here, and it
works — proposals, votes, execution, delegation, vesting grants, and membership changes that leave
the account address untouched (§14). But in **SDK v0.54.0 `x/group` moved to `enterprise/`** under a
**Source Available Evaluation License**: evaluation, testing and education only, with production
requiring a paid Cosmos Enterprise licence. It is also outside the SDK Bug Bounty programme.

This chain runs v0.53.5, where `x/group` is still core and Apache-2.0 — which is precisely the trap.
`config/launch-config.yml:437` already states the principle for `x/crisis`, and it binds harder here
because **`x/group` would hold the funds, not just params**:

> *"dropping it from app wiring before genesis costs nothing. Dropping it from a LIVE chain is a
> coordinated upgrade with a migration handler … Launching with a module you have already decided to
> remove means signing up for that migration."*

Launching 4B QDN of custody on `x/group` means that at the next SDK major upgrade you either buy a
licence or migrate every bucket on a live chain — including accounts holding locked funds, **which
cannot be migrated at all** (§3 limit 3).

For the record, the v0.54 moves: **enterprise/** (licence) `x/group`, `x/poa`; **contrib/**
(deprecated, unmaintained) `x/circuit`, `x/nft`, `x/crisis`. Everything this brief uses —
`x/auth`, `x/auth/vesting`, `x/bank`, `x/staking`, `x/distribution`, `x/gov`, `x/authz`,
`x/feegrant` — **remains core**.

---

## 2. WHAT YOU CAN DO — all TESTED

| # | Capability | Evidence |
|---|---|---|
| 1 | n-of-m threshold custody: sign, combine, broadcast | A2 |
| 2 | A multisig **receives** a chain-enforced vesting grant | A2 — recipient is a `PeriodicVestingAccount` |
| 3 | A multisig **spends**, once AML-whitelisted | code 0 @ height 3732 |
| 4 | **Delegate genuinely LOCKED principal** from a multisig | N1 — `delegated_vesting` = 8,000 QDN, `delegated_free` = 0 |
| 5 | **Undelegate returns the principal STILL LOCKED** | N3 — 8,000 QDN locked after unbonding completed |
| 6 | Withdraw rewards on locked stake; they are immediately spendable | N2 |
| 7 | **Threshold-sign an authz `MsgGrant`**, then an operator spends from the multisig | N4 — operator had no eKYC and no whitelist entry |
| 8 | **Delegate without granting spending power** (`StakeAuthorization`) | N5 — delegated yes, send refused |
| 9 | Issue a vesting grant **by proposal** from a governed account | A1-equivalent, code 0 @ 7882 (via `x/group`; the same message works from a multisig) |
| 10 | Pay a brand-new, non-eKYC address from a whitelisted bucket | A5 |
| 11 | Issue a vesting grant to a recipient with **no eKYC** | A4 — allowed; this is AML gap #2 |
| 12 | A **zero-balance** account transacts on a sponsor's fee | A6 — sponsor paid at a forced real gas price |
| 13 | Whitelist a plain (non-contract) address, at genesis **or** by `x/gov` | genesis `config.yml`; proposals 17, 20 |
| 14 | Vesting locks hold against the EVM | `evm-vesting-handoff.md` |

**Items 4–6 are the load-bearing set.** Threshold custody *plus* a real lock *plus* the ability to
stake it *plus* a lock that survives the round trip through staking. N3 in particular closes the one
path that could have unwound the whole design: `evm-vesting-handoff.md` flagged
delegate → undelegate → spend as the remaining way locked principal might become spendable early.
**It does not** — the principal returns under the lock.

**Items 7–8 are what make custody maintainable** without ever moving the account. See §9.

---

## 3. WHAT YOU CANNOT DO

| # | Limit | Evidence / consequence |
|---|---|---|
| 1 | **No on-chain proposal or vote record for a bucket spend.** Multisig signatures are collected OFF chain; the chain sees only a finished transaction | The real price of excluding `x/group`. Mitigation in §4 — process, not a chain guarantee |
| 2 | **A multisig's address derives from its member set + threshold.** Change either and the address changes | Rotation costs a transfer and a new whitelist entry. §9 |
| 3 | **A vesting account can never be migrated.** Locked coins cannot be transferred | A vesting multisig's membership is **frozen for the schedule's duration** |
| 4 | **Never pre-fund an address destined to become a vesting account** | `account … already exists: invalid request` (`x/auth/vesting/msg_server.go:192`). **Unrecoverable** — the lock can never be applied |
| 5 | **No plain-key account can send until AML-whitelisted or an eKYC wallet** | code **1159**. Applies to multisigs, contracts and group policies alike — not a CosmWasm issue |
| 6 | **A fully locked account cannot pay ANY fee** — including the fee to delegate its own principal | N1's first run produced NO delegation, **silently**, at `spendable = 0`. Delegating locked principal is permitted; paying for the transaction is not |
| 7 | **A multisig cannot be made an eKYC wallet through the supported path** | `create-wallet` mints a wallet from a fresh mnemonic and overrides `--from` with the derived key, so it never targets an existing address. **Not proven impossible** — see §10 |
| 8 | Staking rewards on locked stake are liquid **immediately** | N2. A "locked" bucket produces spendable income throughout its lock. Disclose deliberately |
| 9 | Every transfer is AML-scanned, measured and threshold-reported even when whitelisted | Whitelisting removes the *identity* requirement, not the scan |
| 10 | A threshold, once chosen, cannot be changed | Unlike `x/group`, a native multisig has no `update-decision-policy`. Choose for churn up front (§9) |

### 4. Mitigating limit 1 — the audit trail

Losing on-chain votes is the one genuine regression against the contract design. Recover most of it
by process:

- **Put the decision reference in the transaction memo.** Every bucket spend carries
  `--note "<bucket>-<decision-id>"` pointing at a published, numbered decision record. The chain then
  holds an immutable link between the movement and the decision that authorised it.
- **Publish the signer set and the signed payloads** alongside that record.
- **Route anything constitutional through `x/gov`**, which *is* on-chain: parameter changes, AML
  whitelist entries, enclave identities, software upgrades. Only routine disbursement lacks an
  on-chain vote.

Do not describe this publicly as "on-chain multisig governance". It is off-chain authorisation with
an on-chain audit reference, and the difference matters to anyone assessing the treasury.

---

## 5. THE THREE CUSTODY PATTERNS

Limit 3 and limit 4 together force the choice: a lock must be created at a **fresh** address, and
once created that address can never change hands.

**Pattern A — chain-enforced lock (locked vesting multisig).**
`escrow → MsgCreatePeriodicVestingAccount → <fresh n-of-m multisig>`. The chain enforces the
schedule; the account can still delegate (N1) and its lock survives unbonding (N3); spending needs
the threshold.
*Cost:* membership frozen for the schedule's duration; needs its own whitelist entry; needs a gas
float (limit 6).

**Pattern B — liquid escrow (plain multisig).**
The bucket holds liquid funds under an n-of-m and issues Pattern-A grants. Membership can rotate
(§9), every payout is a normal send.
*Cost:* no chain-enforced lock on the bucket itself — the schedule is policy, not physics.

**Pattern C — community pool (only if on-chain records are mandatory).**
Funds sit in the community pool and move by `MsgCommunityPoolSpend` governance proposals. Fully
on-chain, fully core-SDK, permanent, and every disbursement is voted and recorded.
*Cost:* control passes to **stake-weighted governance**, not a named council, and every payment
waits a voting period. Untested here.

Recommended assignment:

| bucket | pattern | why |
|---|---|---|
| Long-Term Reserve (600M, 10yr) | **A** | Its entire purpose is a credible lock. 10 years of frozen membership is the price — use 4-of-7 or wider |
| Foundation locked tranche (504M, 6yr) | **A** | Must be provably locked **and** delegated — both tested together (N1, N3) |
| Foundation liquid (56M) | B | Operational |
| Adoption, Grants, Personnel, Backers, Founders, Contingency, PubSec, NodeOps | **B** | These are escrows that *issue* locked grants; the locks live in the grants, not the bucket |

Founder, backer and personnel **grants** are always Pattern A — a fresh multisig vesting account per
recipient, which is what the original brief intended.

---

## 6. AML — read before funding anything

Code **1159** (`ErrBankSendNotScannable`, `x/qadena/types/errors.go:120`) refuses a transfer where a
party can be neither identified nor found on the scanned-contract whitelist. The enclave has **no
fallback for an unidentifiable sender**, deliberately — otherwise holding no credential would be the
cheapest way to obtain the most permissive threshold.

Despite its name the list takes **any address** with `codeID: 0` — treasury, a plain account, is
seeded into it at genesis. TESTED both ways: at genesis (`config.yml`) and at runtime by `x/gov`
(proposals 17 and 20, both PASSED, each followed by a successful transfer).

**Seed every address you know at genesis.** It costs nothing, is verifiable in the genesis hash, and
removes all launch-day governance.

---

## 7. PHASE B — GENESIS

Unchanged from the original brief except:

1. Ten bucket accounts are **native multisig addresses** (2-of-3 of operator keys).
2. **Add `scannedContractWhitelistList` entries for all ten**, plus the genesis validator:
   ```yaml
   scannedContractWhitelistList:
     - address: <bucket address>
       codeID: 0
       reason: "<bucket name> genesis custody"
   ```
3. No contract addresses, no code IDs, no cw-* anything, no `x/group` state.

All thirteen `verify_genesis.py` assertions stand, plus one:

> **14.** every bucket address and the genesis validator address appears in
> `scannedContractWhitelistList` with `codeID: 0`.

Without 14 the chain launches with buckets that cannot move a single token until governance runs.

---

## 8. PHASE C — WEEK 1

No code deployment, no instantiation, no migrate admins, no code IDs.

If Phase B step 2 was done, **there is nothing to do for the eight Pattern-B buckets** — already
funded, already whitelisted, already spendable by their thresholds. That is the point of seeding at
genesis.

1. Verify each bucket balance to the aqdn against `allocations.csv`.
2. Verify each bucket address is on the whitelist:
   `qadenad query qadena scanned-contract-whitelist`.
3. For the two Pattern-A locked buckets (LTR 600M, Foundation 504M), **in this order**:
   a. create the fresh custody multisig (4-of-7 recommended);
   b. AML-whitelist that address by `x/gov`;
   c. `MsgCreatePeriodicVestingAccount` from the genesis escrow to it.
   **Never fund the address first** — limit 4; the mistake is unrecoverable.
4. **Send each locked account a gas float**, then run the foundation delegation programme: delegate
   the locked 504M across member validators (N1). Record per-validator amounts.

   > A fully locked account has `spendable = 0` and **cannot pay the fee to submit its own
   > delegation** — N1's first run produced no delegation at all, silently. Coins sent from outside
   > are not part of `original_vesting`, so a plain bank send lands fully spendable and fixes it; a
   > standing feegrant works too. Without one, **the 504M never bonds and the ~7.9% staker APR
   > behind the 1% inflation rate does not materialise.**
5. Split the Foundation bucket: 56M liquid in its genesis multisig, 504M to step 3.
6. Optionally issue `StakeAuthorization` grants (N5) so a delegation manager can run the validator
   programme without spending power.
7. Publish: address map, thresholds and signer sets, unlock schedule, genesis SHA256, and the
   decision-record scheme from §4.

Pattern-A genesis escrows are now empty scaffolding. Pattern-B bucket multisigs are **not** —
they remain the live custody accounts.

---

## 9. MEMBERSHIP: adding and removing signers

`x/group` would have made this free — membership changes there leave the account address untouched
(TESTED, §14) — but it is licence-blocked. So native membership is expensive to change, and the
design should minimise how often it must. Four complementary mechanisms:

**1. Rotate the multisig** — the only way to truly change the signer set. The address derives from
the member pubkeys and threshold, so a change yields a *new address*:

```
create new multisig -> x/gov whitelist it -> transfer the full balance
                    -> verify to the aqdn -> retire the old address
```

Cost: one governance proposal, one large transfer, one AML report, and a window where both addresses
exist. **Impossible for a Pattern-A vesting account** (limit 3).

**2. Don't rotate — delegate authority with `x/authz`. TESTED, and the AML answer is favourable.**
The custody multisig stays fixed forever, so its address and whitelist entry never change. The open
question was whether the AML gate sees granter or grantee: **it sees the granter.** In N4 the
multisig's 2-of-3 threshold signed a `MsgGrant`, and a brand-new operator key — no eKYC, no whitelist
entry — then spent from the multisig:

```
exec to allow-listed recipient      -> code 0, recipient +100 QDN
exec to non-allow-listed recipient  -> "cannot send to qadena15fy… address: unauthorized"
spend limit after one send          -> 5,000 -> 4,000 QDN, decremented automatically
```

Operators cost **nothing** to onboard: no whitelist, no eKYC, no governance.

| authorization | bounds |
|---|---|
| `SendAuthorization` | spend limit (auto-decrementing) + recipient allow-list |
| `StakeAuthorization` | delegate / undelegate / redelegate, validator allow or deny list, max amount |
| `GenericAuthorization` | any message of one type URL — the blunt one; prefer the others |

All accept an **expiration**. Use it: an unexpiring grant is a standing key.

*What it does not do:* the grantee acts with the granter's authority, so a compromised operator key
can move funds up to the limit. Bounds and expiry are the containment. Keep **grant creation and
revocation** behind the threshold — that is where the n-of-m still bites.

**3. Choose the threshold for churn at creation — it is immutable** (limit 10). Free, and the
highest-leverage decision you will make. Size *m* for departures and *n* for key loss: 4-of-7
tolerates three simultaneous absences, 2-of-3 tolerates one. For Pattern-A accounts the set is
frozen for the whole schedule — **4-of-7 or wider, never 2-of-3**. Prefer roles to individuals where
custody is institutional.

**4. Structural — keep long-lived locks and changeable councils in different accounts.** Rotation
hurts only because it collides with locked funds, so separate them: Pattern A for locked and
unchanging, Pattern B for liquid and operational, `x/authz` for who may act day to day. The eight
escrow buckets already have this shape.

### If on-chain vote records are a hard requirement

Native custody is then not sufficient, and there are three honest routes: **Pattern C** (community
pool, stake-weighted governance); **buy the Cosmos Enterprise licence** for `x/group`, which
demonstrably works; or **DAO DAO contracts** (`dao-proposal-single` + `dao-voting-cw4`) — Oak-audited
and built *with* the stargate feature, so unlike cw-plus they can carry vesting grants, though they
do **not** declare `requires_staking`, so the 504M would remain a native vesting multisig regardless.

---

## 10. ADDRESSES NOT KNOWN AT GENESIS

Four options, best first.

1. **Escrow now, grant later, whitelist at grant time.** The bucket exists at genesis; the recipient
   address arrives whenever it arrives; one `x/gov` proposal accompanies the grant. This is what
   `allocations.csv` already encodes. **TESTED.**
2. **Recipient uses an eKYC'd single-key wallet.** No whitelist, no governance, spends immediately —
   at the cost of single-key custody. Best for smaller grants and anyone who transacts often.
3. **Pre-generate addresses into cold storage and seed them at genesis.** Removes later governance,
   but requires generating real keys before launch (HARD RULE 5 forbids it) and concentrates
   key-generation risk. Only for a small fixed set.
4. **Sponsor them instead.** A grantee who only ever *executes contracts* — an agency, not a holder —
   needs no whitelist at all; a feegrant covers it. **TESTED (A6/A7).**

You **cannot** add to the genesis whitelist later. Genesis is immutable; after launch there is only
`x/gov`.

### The custody choice you must put to every grantee — before their address is generated

| | multisig custody | eKYC single-key wallet |
|---|---|---|
| key loss | survivable (n-of-m) | **total loss** |
| can spend | only after a governance whitelist | immediately |
| foundation involvement | approves the whitelist once | none |
| rotation during vesting | **frozen** (limit 3) | n/a |

**These are currently mutually exclusive** (limit 7), and it cannot be changed afterwards.

**But the "impossible" is not proven.** `create-wallet` mints a wallet from a fresh mnemonic and
overrides `--from`, so the CLI cannot target an existing address — yet
`msg_server_create_wallet.go` sets `walletID := msg.Creator`, i.e. **the signer**. A hand-crafted
`MsgCreateWallet` signed by a multisig is therefore not obviously refused; it was never built.

A separate obstacle may be decisive first: an eKYC credential encodes a **person's** residency and
citizenship, which is what the AML scan decrypts to pick a threshold. Attaching one to an n-of-m
account asserts that a group has a nationality, and a report naming it names nobody.

**Run this experiment before the consortium agreement fixes founder custody terms** — it is the
difference between "founders need foundation approval to spend" and "founders are self-sufficient".

---

## 11. PHASE D — RUNBOOKS

### D1. Vesting grant
1. Recipient supplies a **brand-new** `eth_secp256k1` address, never funded. For a large grant, a
   personal n-of-m multisig — but settle §10's custody choice first.
2. Owning bucket: collect threshold signatures on `MsgCreatePeriodicVestingAccount`.
   `start_time` = TGE for founders/backers (backdated); grant date for personnel/partners. First
   period is the cliff; the final period absorbs the rounding remainder; periods sum EXACTLY.
3. **Whitelist the recipient by `x/gov`** — required for a multisig, not required for an eKYC wallet.
4. THEN send the gas float. Never before (limit 4), and never omit it (limit 6).
5. Log in the public grants register with the decision reference from §4.

### D2. Node onboarding

nodeops bucket grants the operator a token self-bond (see §11a), operator runs `MsgCreateValidator`,
foundation delegates a tranche, commission is operator compensation. `min_commission_rate` is 5%, so
a node is self-funding from month one.

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
State this plainly — the operator's self-bond is small (§11a), so the foundation absorbs
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

## 11a. NODE ONBOARDING AT MINIMUM COST

D2 as written grants **1,100 QDN** per node (1,000 self-bond + 100 gas). Both halves are reducible,
and one of them almost to zero.

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
stake that actually matters. That reduces the 1,100 QDN grant to near zero.

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

## 12. HARD RULES

1. `allocations.csv` is human-owned. Never edit, never invent. Missing value → stop and ask.
2. `genesis.json` is a build artifact. Never hand-edit.
3. Integer arithmetic only. No floats near amounts.
4. Every JSON amount is a string.
5. Never generate or commit real keys or mnemonics.
6. Verification exits non-zero on first failure, naming the bucket.
7. Chain-ids must match `<name>_<eip155>-<epoch>` — the EVM chain ID is parsed from it and a
   mismatch **fails silently**. Devnet `qadena_4828-1`, testnet `qadena_4824-1`, mainnet
   `qadena_482-1`. (4444 is Htmlcoin Mainnet — a live replay risk.)
8. A gating failure is reported, not designed around.
9. **Never pre-fund an address due to become a vesting account.** Unrecoverable.
10. **Every locked account needs a gas float or a feegrant before it can act.** `spendable = 0` means
    it cannot pay a fee, so it cannot delegate, vote or spend its own vested tranches. The failure is
    **silent** — no transaction lands at all.
11. **Whitelist before funding, always.** Both orders "work" at broadcast; the wrong one fails inside
    the block, having spent the fee.
12. **Choose thresholds for churn at creation.** They are immutable, and for locked accounts so is
    the membership.

---

## 13. WHAT IS STILL NOT TESTED

1. **A full bucket lifecycle end to end** — genesis multisig, fund, pay out, rotate, whitelist,
   transfer, pay out again. Each leg is tested; the sequence is not.
2. **Multisig rotation as one operation** (§9 mechanism 1) against a funded bucket.
3. **Slashing a vesting account's delegation** — whether `delegated_vesting`/`delegated_free`
   accounting survives a slash correctly. Directly affects the 504M. See D2.
4. **`authz revoke`** — never exercised, and it is the half of mechanism 2 that matters when someone
   leaves. **Items 2 and 3 together are the highest-value remaining work**: they are the two halves
   of "how does a council actually change".
4. **A hand-crafted `MsgCreateWallet` signed by a multisig** (§10). Would overturn limit 7 if it
   works.
5. **Thresholds beyond 2-of-3.** The design uses 3-of-5 to 5-of-7 and recommends 4-of-7 for locked
   accounts; nothing suggests they differ, but they were not exercised.
6. **Grants from a locked vesting account over only its vested tranche** — N4's granter had a gas
   float.
7. **`MsgWithdrawDelegatorReward` across multiple validators** — N2 used one; the 504M spans many.
8. **Pattern C** (community pool) entirely.
9. **A3's rewards leg via a contract**, and the cw-vesting contracts, were never instantiated —
   irrelevant if native is adopted, but the original brief's Phase C depends on them.
10. Single chain, single run, single validator, no SGX. `unbonding_time` was reduced to 120s by
    governance for N3; mainnet's 21 days is untested at that duration.
