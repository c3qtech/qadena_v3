# QADENA Token Launch — Master Brief

Single source for the token launch implementation. **Supersedes**
`qadena-genesis-brief.md`, `qadena-build-brief.md`, and the genesis portions of
`qadena-dev-mode-brief.md`.

Work in phase order. Phase A gates everything.

---

## CONFIRMED ENVIRONMENT (do not re-derive)

Established by testing on devnet `qadena_4444-1`:

- Cosmos SDK v0.53.5 · CosmWasm present · Cosmos EVM v0.5.1 (pre-audit, v0.x)
- Base denom `aqdn`, 18 decimals. Display `qdn` — never in an on-chain amount.
- `x/bank` stores full-precision aqdn; `x/precisebank` is a passthrough. Ignore.
- Vesting: vanilla `cosmos-sdk/x/auth/vesting`.
- **Vesting locks hold against the EVM** — EVM balance reads resolve to
  `SpendableCoin()`. Verified at the exact boundary. Re-test if any precompile
  is ever activated (`active_static_precompiles` currently `[]`).
- Locked tokens CAN be delegated; principal returns still-locked. Staking
  rewards are LIQUID immediately (disclosure item).
- Backdated vesting `start_time` is accepted; elapsed periods become spendable.
- A fully locked account cannot pay EVM gas at a real base fee.
- **AML gate (code 1159)** blocks Cosmos bank sends between non-eKYC parties,
  but does NOT gate EVM transfers. The asymmetry is a separate workstream; its
  interactions are tested in Phase A.
- Recipient keys: `--algo eth_secp256k1`, brand-new, never funded.

## DESIGN SUMMARY

- **4,000,000,000 QDN initial supply** (uncapped — inflation on; never write
  "total/max/capped supply").
- **Inflation: 1.00% fixed** (`inflation_min == inflation_max == 0.01`).
  Rationale: provisions = rate x total supply paid to bonded stake only;
  bonded stake is ~504M (foundation's locked tranche delegated), so 1% -> ~7.9%
  staker APR. Higher rates pay absurd yield to a tiny bonded set.
- **10 buckets** per `allocations.csv`. Genesis holds each bucket in a
  temporary native 2-of-3 multisig of the operator's own keys. Permanent
  custody (cw3/cw-vesting) is deployed in week 1 on the live chain.
- **Zero external addresses at genesis** except genesis validator operators.
  Founders and backers are escrowed; all individual grants are post-launch.
- Consortium model: foundation delegates its locked 504M to member validators;
  validator commission is operator compensation; governance is
  foundation-controlled and disclosed as such.

---

## HARD RULES

1. `allocations.csv` is human-owned. Never edit, never invent values. Missing
   value -> stop and ask.
2. `genesis.json` is a build artifact. Never hand-edit.
3. Integer arithmetic only (Python `int`). No floats anywhere near amounts.
4. Every JSON amount is a **string**.
5. Never generate/commit real keys or mnemonics. Addresses arrive as CSV strings.
6. Verification exits non-zero on first failure, naming the bucket.
7. Devnet/testnet chain-ids only (`qadena-dev-*`). Never a mainnet command.
8. If a Phase A test fails, STOP and report. Do not redesign around it.

---

# PHASE A — GATING TESTS

Run on a throwaway devnet. All results with pasted output into
`gating-findings.md`. **Phases B–D assume these pass.**

| # | Test | Why it gates |
|---|------|--------------|
| A1 | cw3-flex-multisig proposal carrying `MsgCreatePeriodicVestingAccount` (Stargate/Any msg), executed at threshold | Every escrow->grant flow (founders, backers, personnel) runs through this |
| A2 | Native 2-of-3 multisig address as RECIPIENT of `MsgCreatePeriodicVestingAccount`; then post-cliff 2-of-3 withdrawal | Founder custody recommendation depends on it |
| A3 | cw3 executing `StakingMsg::Delegate`; rewards withdrawal via proposal | Whether contract-held buckets can ever stake |
| A4 | `MsgCreatePeriodicVestingAccount` to a NON-eKYC recipient vs AML ante | If blocked: every grant needs eKYC first (workflow). If allowed: document as AML gap #2 |
| A5 | AML-whitelisted cw3 bank-send to non-whitelisted recipient | Exact shape of every future grant payout |
| A6 | Feegrant end-to-end: sponsor issues `PeriodicAllowance` + `AllowedMsgAllowance` to an account with ZERO balance; that account executes `MsgExecuteContract` at a **non-zero gas price** (set min-gas-price; devnet's ~0 base fee masks failures) | SEC PH toll-free architecture |
| A7 | AML vs sponsored tx: does the ante fire on fee payment or execution for non-eKYC signers? | Agency addresses may need whitelisting before any demo |
| A8 | Genesis balance assignment to a wasm contract address (InitGenesis ordering) — only if Phase C is ever moved into genesis | Currently informational; week-1 plan avoids it |

Also record: wasmd feature flags (staking, stargate), cw-plus / cw3 / cw4 /
cw-vesting versions and their audit status.

---

# PHASE B — GENESIS PIPELINE

## Deliverables

```
tokenomics/
  allocations.csv          # human-owned
  build_genesis.py         # CSV -> genesis.json
  verify_genesis.py        # assertions, exit 1 on failure
  export_unlock_schedule.py
  README.md                # SHA256, conventions, findings refs
```

## allocations.csv

Columns: `bucket_id,bucket_name,pct,tokens_qdn,genesis_type,genesis_address,
permanent_home,cliff_days,vest_months,cliff_release_pct,stakes,circulating,
custody_final,notes`

- `tokens_qdn` is whole QDN. Convert ONCE at load: `aqdn = qdn * 10**18`.
- Rows sharing a `bucket_id` are one bucket (Node Ops = reserve + N validator
  rows). Percentages are per-bucket; token sums are per-row.
- `genesis_type`: `native_msig` -> plain BaseAccount at the multisig address
  (2-of-3 of operator keys); `base` -> plain BaseAccount (validator operators).
- **No vesting accounts and no contracts exist at genesis.** All schedules are
  applied post-launch (Phase C/D). `cliff_days`/`vest_months` columns describe
  the terms grants must carry, for the schedule exporter and runbooks.
- Never emit module accounts.

## Genesis contents

1. 10 bucket BaseAccounts + 1 validator BaseAccount (1,100 QDN: 1,000 gentx
   self-bond + 100 gas)
2. One gentx — single genesis validator; the set grows one by one post-launch via D2
3. Denom metadata (exponents explicit, symbol uppercase):

```json
{ "description": "The native token of the Qadena network",
  "base": "aqdn", "display": "qdn",
  "name": "Qadena Token", "symbol": "QDN",
  "denom_units": [ {"denom":"aqdn","exponent":0},
                   {"denom":"qdn","exponent":18} ] }
```

4. Mint params: `mint_denom: aqdn`, `inflation_min = inflation_max =
   "0.010000000000000000"`, `inflation_rate_change: "0"`, `blocks_per_year`
   computed from MEASURED devnet block time (record the measurement).

## verify_genesis.py — hard assertions

1. distinct-bucket pct sum == 100 (integer)
2. all-row `tokens_qdn` sum == 4_000_000_000
3. per bucket: row sum == `4_000_000_000 * pct // 100`
4. total aqdn across accounts == `4000000000000000000000000000` == bank.supply
5. no duplicate addresses; all bech32-valid with chain prefix
6. no module-account names present
7. denom metadata: base aqdn, display qdn, symbol QDN, exponents 0 and 18 explicit
8. no amount field anywhere uses `qdn` as denom
9. every amount is a JSON string
10. mint: `inflation_min == inflation_max == 0.01`, `blocks_per_year` non-default
11. no second emission path (grep for epoch hooks / BeginBlocker transfers to
    `fee_collector`)
12. exactly one validator row of exactly 1,100 QDN, matching exactly one gentx
13. every `native_msig` row has a non-placeholder address before mainnet build
    (placeholder allowed in dev builds; assert flag distinguishes)

Then `qadenad validate-genesis`, then boot `qadena-dev-2` from the file and
assert: every account spendable == its genesis balance (nothing locked at
genesis), `q bank total` matches assertion 4, the single validator produces blocks.

## export_unlock_schedule.py

Monthly CSV from TGE to month 120: per-bucket unlocked amounts (from the terms
columns, as if grants are issued at TGE — label this assumption), cumulative
circulating (driven by the `circulating` column), and projected minted supply
at 1%. State circulating % against the moving total. TGE circulating should be
~56.0M + validator floats (~1.4%); if far off, report, don't adjust.

---

# PHASE C — WEEK-1 RUNBOOK (post-launch, human-executed; produce scripts + checklist)

Order matters.

1. Deploy code: `cw4-group`, `cw3-flex-multisig`, `cw-vesting`. Record code IDs.
2. Instantiate `cw4-group` (council; operator keys initially; admin = operator
   for now).
3. Instantiate cw3s against the one cw4, thresholds from `custody_final`:
   adoption 3/5, ltr 4/5, foundation 3/5, grants 3/5, personnel 3/5,
   backers 3/5, founders 3/5, contingency 2/5, pubsec 5/7, nodeops 3/5.
4. Instantiate cw-vesting instances: LTR 600M/10yr linear -> recipient
   cw3-ltr; Foundation 504M/6yr -> recipient cw3-foundation.
5. **Set every contract's migrate admin to governance or none.** A team-key
   migrate admin can swap code and drain the reserve.
6. **AML-whitelist every contract address** (scanned-contract whitelist) BEFORE
   any funding transfer, or the transfers bounce with code 1159.
7. Fund: one bank send per bucket from its genesis msig to its permanent home
   (foundation splits 56M -> cw3 liquid, 504M -> its cw-vesting). Verify each
   balance to the aqdn.
8. Foundation delegation program: delegate the locked 504M across member
   validators (locked delegation confirmed working). Record per-validator
   amounts.
9. Publish: contract address map, code checksums, thresholds, the unlock
   schedule, and the SHA256 of genesis.
10. Later, on council formation: `update_members` to seat real members, then
    `update_admin` on the cw4 to the appropriate cw3 (self-governing).

Genesis msigs are now empty scaffolding; note them as retired.

---

# PHASE D — OPERATING RUNBOOKS (produce as scripts + docs)

## D1. Vesting grant (founders, backers, team, advisors, partners)

1. Recipient supplies a **brand-new** `eth_secp256k1` address (personal 2-of-3
   multisig advised for large grants — A2 must have passed). No prior receipts.
2. If A4 showed AML gating: recipient completes eKYC FIRST.
3. Owning cw3: propose -> vote -> execute `MsgCreatePeriodicVestingAccount`.
   `start_time` = TGE for founders/backers (backdated; elapsed periods unlock
   immediately — same clock for everyone). `start_time` = grant date for
   personnel/partners. First period = cliff; final period absorbs rounding
   remainder; periods sum EXACTLY to total.
4. THEN send 100 QDN gas float (never before — breaks the fresh-address rule;
   and a fully locked account cannot pay EVM gas).
5. Log grant in the public grants register.

Worked example (founder, 100M, 18mo cliff @12.5%, 42mo):
cliff `12500000000000000000000000` (length 46656000), 41x monthly
`2083333333333333333333333` (length 2592000), final
`2083333333333333333333347`.

## D2. Node onboarding

1. cw3-nodeops grants 1,100 QDN liquid to operator's fresh address
   (A5 result governs AML handling).
2. Operator: `MsgCreateValidator`, self-bond 1,000, commission per consortium
   standard (e.g. 10%).
3. Foundation delegates its tranche (e.g. ~24M) to the new validator.
4. Operator income = commission on delegated stake (liquid, self-funding after
   month 1). Misbehaving/exiting node -> foundation redelegates away.
5. Note in member agreement: slashing hits foundation principal.

## D3. Agency toll-free (SEC PH / VERITAS)

1. Fund a **native** gas-sponsor multisig account from cw3-pubsec (keep the
   sponsor native — contract-issued feegrants are unverified).
2. Per agency address: `PeriodicAllowance` (e.g. 2,000 QDN/month) combined with
   `AllowedMsgAllowance` restricted to `MsgExecuteContract`.
3. If A7 showed AML gating sponsored txs: whitelist agency addresses first.
4. **VERITAS must be built on the CosmWasm/native path.** Feegrant does not
   cover `MsgEthereumTx`; an EVM app would need a relayer/paymaster (out of
   scope).
5. Revoke allowances on engagement end.

---

## OUT OF SCOPE — ask the human

- Any change to percentages, token counts, cliffs, vest durations, thresholds,
  or the inflation rate
- TGE date; genesis validator count/operators
- The AML/EVM asymmetry fix (separate workstream)
- Legal/securities questions (bucket wording, backer terms, Howey posture)
- Real keys, real addresses, any mainnet execution

## DEFINITION OF DONE

- `gating-findings.md` complete, every test with pasted output
- `verify_genesis.py` exit 0; `validate-genesis` passes; dev-2 boot checks pass
- Unlock schedule generated and sanity-checked
- Phase C and D delivered as reviewed scripts + checklists (not executed)
- README: regeneration steps, genesis SHA256, block-time measurement,
  period-length convention (30-day months, ~5 day/yr calendar drift)
- A second person reproduces an identical genesis SHA256 from the repo
