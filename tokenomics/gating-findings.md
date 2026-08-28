# Phase A — gating findings

Self-contained. The reader is assumed to have no context from the run that produced it.

Phase A of `qadena-master-brief.md` asks eight questions whose answers gate the token design. The
brief is explicit that a failure here means **stop and report**, not redesign — so this document
reports what the chain did, including where that contradicts the brief.

Harness: `testscripts/test_token_gating.sh`. Raw evidence: `logs/token-gating/` (one `*.tx.json`
per transaction, plus `environment.txt` and `summary.txt`).

---

## 0. Two findings that did not need a test

Both were found by reading the chain's own code and are load-bearing enough to lead with.

### 0.1 HARD RULE 7 is unusable on this chain, and fails silently

The brief mandates devnet chain-ids of the form `qadena-dev-*`. This chain derives its **EVM chain
ID by parsing the Cosmos chain-id** — `cmd/qadenad/cmd/commands.go`:

```go
// Parse numeric part from chain-id like "qadena_4828-1"
parts := strings.Split(cosmosChainID, "_")
if len(parts) != 2 {
    return                       // <-- silent
}
...
v.Set(evmsrvflags.EVMChainID, parsed)
```

`qadena-dev-2` contains no `_`, so `parts` has length 1 and the function **returns without ever
setting `EVMChainID`**. There is no error and no log line; the EVM simply runs on a fallback ID.
A rule intended to prevent a mainnet accident would instead have produced a chain whose EVM
identity was silently wrong.

Chain-ids are therefore assigned in `config/launch-config.yml` in the required
`<name>_<eip155>-<epoch>` form. Verified on the running devnet:

```
cosmos chain-id : qadena_4828-1
genesis chain_id: qadena_4828-1
eth_chainId     : 0x12dc   (= 4828)
```

### 0.2 EIP-155 chain ID 4444 was never available

`4444` — the previous devnet value, and the value proposed for production — is **registered to
Htmlcoin Mainnet** (shortName `html`, 8-decimal HTML) in `ethereum-lists/chains`, an active chain
with a live RPC and block explorer.

This is a live vulnerability, not a naming clash. EIP-155 replay protection *is* the chain ID, and
`eth_secp256k1` derives the same `0x` address on every EVM chain — so any address existing on both
chains would have its signed transactions replayable **in both directions**.

Checked for digits 4/2/8 (2026-08-27):

| | |
|---|---|
| **taken** | 428 Geso Verse · 248 Oasys Mainnet · 824 Daily Network · 842 Taraxa Testnet · 8428 THAT Mainnet · 4444 Htmlcoin |
| **free** | 482 · 284 · 4228 · 4288 · 4824 · 4828 · 2848 |

Assigned as a stem-plus-digit family so a misconfigured node is obvious at a glance:

| network | chain-id |
|---|---|
| mainnet | `qadena_482-1` |
| testnet | `qadena_4824-1` |
| devnet | `qadena_4828-1` |

A registry 404 proves absence from the list, not that nobody squats the number unregistered, and a
pending PR could claim one. **Re-check all three immediately before launch and reserve them by PR.**


---

## 1. Verdict table

| # | Question | Verdict | In one line |
|---|---|---|---|
| A1 | cw3-flex carrying `MsgCreatePeriodicVestingAccount` as Any/Stargate | **FAIL** | The released cw-plus binary cannot represent the message at all |
| A2 | Native 2-of-3 multisig receives a grant, then withdraws | **FAIL** (fix verified) | It can receive but **cannot spend** — refused 1159, and it pays the fee to fail |
| A3 | cw3 delegating; rewards withdrawal | **FAIL** | Same artifact cause: stock cw3-flex cannot emit staking messages |
| A4 | Vesting grant to a non-eKYC recipient vs the AML ante | **PASS** (allowed) | Allowed — and that is **AML gap #2** |
| A5 | Whitelisted cw3 → non-whitelisted recipient | **PASS** | Grant payouts work; recipients need no pre-listing |
| A6 | Feegrant, zero-balance account, non-zero gas price | **PASS** | Sponsor really paid 122,466,500,000,000 aqdn |
| A7 | AML ante on fee payment vs execution | **PASS** | The ante does not gate a sponsored tx |
| A8 | Genesis balance to a wasm contract address | NOT-EXERCISED | Informational; nothing depends on it |

**Three FAILs.** A1 and A3 share a single root cause, and it is the artifact rather than this chain
(§3). A2 is unrelated and is a property of this chain's AML gate (§4); its remediation is verified
but adds standing operational cost. Per HARD RULE 8 all three are reported, not designed around.

Reproduced end to end by `testscripts/test_token_gating.sh` — every verdict above is what the
harness now emits unaided, with no manual steps.

---

## 3. A1 and A3 — the released cw-plus binaries cannot do this

Both failures are one bug in the artifact, and it is worth stating precisely because the obvious
reading ("the chain refuses contract-driven vesting/staking") is wrong.

In `cosmwasm-std`, the `CosmosMsg` variants are **feature-gated**:

| variant | gate |
|---|---|
| `Bank(BankMsg)`, `Wasm(WasmMsg)` | none — always present |
| `Staking(StakingMsg)`, `Distribution(DistributionMsg)` | `#[cfg(feature = "staking")]` |
| `Any(AnyMsg)` | `#[cfg(feature = "cosmwasm_2_0")]` |
| `Ibc(IbcMsg)`, `Gov(GovMsg)` | `#[cfg(feature = "stargate")]` |

cw-plus v2.0.0's workspace pins `cosmwasm-std = "2.0.0"` with **no features array**. So the
released `cw3_flex_multisig.wasm` was compiled without those variants existing. The JSON payload
cannot deserialize, the contract errors during simulation, and the transaction is rejected by the
CLI **before it ever reaches the chain** — which is exactly what was observed:

```
variant 'any'      rejected (BROADCAST_REJECTED)
variant 'stargate' rejected (BROADCAST_REJECTED)
```

The artifacts' own capability declarations are the visible fingerprint, and they said so all along:

```
cw3_flex_multisig.wasm       requires_iterator
cw_vesting-staking.wasm      requires_cosmwasm_1_1 requires_cosmwasm_1_2 requires_iterator requires_staking requires_stargate
```

**This is also why A5 passed.** `BankMsg` is not gated, so the one message type the stock contract
*can* emit is precisely the one A5 exercises. The suite's three cw3 results are fully explained by
one mechanism.

### What it costs

- **Phase D1 (escrow → grant) does not work** on stock cw-plus. Every founder, backer, personnel
  and partner grant runs through a cw3 proposal carrying `MsgCreatePeriodicVestingAccount`.
- **cw3-held buckets cannot stake or claim rewards.**

### Remediation, and the risk it adds

Build `cw3-flex-multisig` from source with the `staking` and `cosmwasm_2_0` features enabled.

That is a **custom build of an already-unaudited contract**. It forfeits the one real assurance the
stock artifact carries — that it is the byte-identical, widely-run community release — and it does so
for the contract that custodies all 4,000,000,000 QDN. Deciding that is out of scope here; it needs
a human.

### A nuance that matters for the inflation model

A3 tests a **cw3**. The foundation's locked 504M is destined for **cw-vesting**, which DAO DAO
*does* build with `staking` (it declares `requires_staking`). So the 504M delegation programme and
the ~7.9% staker APR that the 1% inflation rate is justified against are **probably intact** — but
**that leg was not tested here**, and the brief's A3 as written does not cover it.

**Recommended addition to Phase A: test cw-vesting-staking delegating while locked, driven by its
cw3 recipient.** It is the single most load-bearing untested path in the design.

---

## 4. A2 — the founder custody recommendation, as written, strands the founder

The brief advises a "personal 2-of-3 multisig" for large founder grants (allocations.csv bucket 07,
200M QDN across two founders). Tested end to end:

| leg | result |
|---|---|
| multisig receives `MsgCreatePeriodicVestingAccount` | **works** — 5,000 QDN landed, fully spendable after the period elapsed |
| 2-of-3 sign + `multisign` + broadcast | **works** — valid signatures, tx reached block 3675 |
| the transfer itself | **REFUSED, code 1159** |

```
failed to execute message; message index: 0: rpc error: code = Unknown desc =
codespace qadena code 1159: This transfer cannot be AML-scanned; each party must be
a wallet with eKYC data or on the scanned-contract whitelist
```

A native multisig holds no eKYC credential — it is not a wallet created by `create-wallet` — and it
is not on the scanned-contract whitelist. **It paid the fee to fail**: the balance fell by exactly
200,000,000,000,000 aqdn while nothing moved.

Left unaddressed, a founder following the brief's own advice receives 100M QDN and can never move it.

### Verified remediation

`MsgAddScannedContractWhitelist` **accepts a non-contract address** with `codeID: 0` — treasury is
itself seeded into that list at genesis, so this is the intended shape, not a trick. Proposal 17
passed, and the identical withdrawal then settled:

```
before whitelist : code 1159, height 3675, nothing moved
after  whitelist : code 0,    height 3732, recipient +1000000000000000000 aqdn
```

### The operational consequence the brief does not mention

**Every personal custody address must get its own governance whitelist proposal before it can
spend.** That applies to both founders, and to any backer or team member advised into multisig
custody. Three things follow:

1. It is per-address governance work, on the critical path of every large grant.
2. The foundation must vote before a founder can move their own vested tokens — a real
   centralisation and optics issue for a design already disclosed as foundation-controlled
   governance. "Your tokens vested, but the foundation must approve before you can sell."
3. Sequence it in D1 **before** the gas float, alongside the existing eKYC step.

---

## 5. A4 — AML gap #2, confirmed

A vesting grant reached a brand-new, never-funded, non-eKYC `eth_secp256k1` address and created a
`PeriodicVestingAccount`, code 0.

The same value moved by `tx bank send` to the same address would be refused with 1159 — as A2
demonstrates from the other direction. **`MsgCreatePeriodicVestingAccount` is an unscanned route to
a non-eKYC party.**

This is the brief's own "AML gap #2" wording, now confirmed rather than hypothesised. It is a gap in
the *scan*, not an exploit of it: value reaches a party the AML system never assessed. It belongs in
the same workstream as the EVM asymmetry.

Good news for the workflow: recipients do **not** need eKYC before receiving a grant. The constraint
lands on **spending**, not receiving — which is precisely what A2 ran into.

---

## 6. A5 — contract custody works, once whitelisted

A whitelisted cw3 paid a brand-new, non-whitelisted, non-eKYC address 1,000 QDN, code 0.

This is the load-bearing confirmation for Phase C: `test_wasm.sh` states flatly that *"contracts
cannot custody funds on this chain"*, which would break Phase C step 7 (funding all ten buckets)
outright. The scanned-contract whitelist is what makes the design possible, and it works.

Two consequences for the runbook:

- **Whitelist entries are pinned to a code ID.** Migrating a bucket contract therefore **silently
  freezes its funds** until a new governance proposal re-whitelists the new code ID. Phase C steps 5
  and 6 are two halves of one mechanism, and the brief presents them as unrelated.
- Whitelisted sends are still **scanned, measured, and threshold-reported**. Every Phase C bucket
  transfer (960M QDN and friends) will exceed any sane `suspicious_transaction_threshold` and
  generate an AML report. Expected, but it should be expected *on purpose*.

---

## 7. A6 and A7 — the toll-free architecture works

A zero-balance account executed `MsgExecuteContract` with the sponsor paying, at a **forced** gas
price of `500000000aqdn`, and the sponsor's balance fell by **122,466,500,000,000 aqdn**. The
allowance was the exact combination the brief specifies — `AllowedMsgAllowance` wrapping a
`PeriodicAllowance`, restricted to `/cosmwasm.wasm.v1.MsgExecuteContract`.

A7 follows from it: the grantee holds no credential, yet its transaction settled, so **the AML ante
does not gate a sponsored transaction**. SEC PH agency addresses do **not** need whitelisting merely
to transact.

They *do* need it to move value by bank send — that is the A2/A5 boundary, and it is the sharper
statement of where the gate actually sits: **on transfers of value, not on transacting.**

---

## 8. Open questions

### 8.1 The 11-account genesis is incompatible with `x/qadena` — blocks Phase B

The brief specifies "zero external addresses at genesis except genesis validator operators" and
exactly 11 accounts. The `x/qadena` genesis stanza is *name-bound* to `pioneer1` and `treasury`:
`publicKeyList` needs `pioneer1PubKID` (transaction **and** credential), `intervalPublicKeyIDList`
needs both a `pioneer` and a `treasury` nodeType, and `bankSendWhitelistList` grants the AML
exemption to `treasuryPubKID`. `buildscripts/setPubKAndPubKID.sh` resolves `<name>PubKID` from the
keyring for a **named** account, so both must exist at genesis.

Resolving it means either accepting two bootstrap identities the brief excludes, or changing what
`x/qadena` requires — both OUT OF SCOPE per the brief. **Ask the human.** Does not block Phase A;
**blocks Phase B.**

### 8.2 Which cw-vesting build for which bucket

Not answerable from the brief, which says only "cw-vesting". Foundation (504M, delegated while
locked) needs **`-staking`**; Long-Term Reserve (600M, `stakes: no`) should use **`-no_staking`**.
Confirm before Phase C step 4.

### 8.3 Custom cw3 build, or a different custody design?

A1/A3 force the choice. Rebuilding cw-plus with features is straightforward engineering but yields
an unaudited, non-standard binary holding 4B QDN. The alternative is a custody design that only ever
needs `BankMsg`. This is a human decision.

---

## 9. What was NOT tested

Do not read these verdicts as broader than they are.

1. **cw-vesting was stored but never instantiated or driven.** Both `-staking` and `-no_staking`
   were uploaded (code id recorded) and their capabilities read, but no vesting contract was
   instantiated, funded, or made to delegate. Given §3, **this is the most valuable next test.**
2. **A3's rewards leg never ran** — the delegate step failed first, so `withdraw_delegator_reward`
   is untested.
3. **A custom-built cw3 was not produced or tested.** The remediation in §3 is reasoned from the
   feature gates and the capability strings, not demonstrated.
4. **Only one threshold shape** (2-of-3 absolute_count) was exercised; the real design uses 2/5
   through 5/7 against a cw4-group whose membership changes.
5. **No migration was performed**, so the "migrating freezes funds" consequence in §6 is read from
   the whitelist's code-ID pinning, not demonstrated.
6. **A8** — see the table.
7. Single chain, single run, single validator, no SGX.

---

## 10. Provenance

| what | reference |
|---|---|
| run id | `1787832410` |
| chain | `qadena_4828-1`, qadenad 1.1.28, `eth_chainId` 0x12dc |
| code ids | cw4-group 10 · cw3-flex 11 · cw-vesting 12 |
| A2 refused withdrawal | `E9E1903FEDBD16A73CDC0E1A1F514C0106102071DDF2A72C910CB6A78649D6DD`, height 3675, code 1159 |
| A2 whitelist proposal | id 17, `PROPOSAL_STATUS_PASSED` |
| A2 successful withdrawal | `47E2D43E64F0DDD46CB2B3F528C5E35AFB7D2B62B9B4BF0495497C99EE0B41A3`, height 3732, code 0 |
| A4 recipient account | `/cosmos.vesting.v1beta1.PeriodicVestingAccount`, code 0 |
| A6 fee actually paid | 122,466,500,000,000 aqdn at 500000000aqdn/gas |
| full evidence | `logs/token-gating/` |

The 25-suite regression (`--from-genesis`) passed in full on this chain-id, so the chain-id change
is not implicated in any result above.

---

## 11. Deviations from the brief

- **Chain-id.** HARD RULE 7 asks for `qadena-dev-*`; that form is unusable here and fails silently
  (§0.1). Ran on `qadena_4828-1`.
- **A6 forced its own gas price** rather than relying on the ambient base fee, which had decayed to
  ~0. Without this the test would have passed while proving nothing.
- **A2 was completed by hand** after the harness's `--generate-only` + `--gas auto` conflict left it
  NOT-EXERCISED. The harness is fixed; the results in §4 are from the manual run and are quoted with
  their transaction hashes.
- **Nothing was changed to make a test pass**, and nothing found here was fixed. Per HARD RULE 8,
  the two FAILs are reported as failures.

---

## 2. Environment

Devnet on macOS, built by `./testscripts/regression.sh --from-genesis` from `config/config.yml`.

Note the deliberate split: `config/config.yml` is the **test chain** and does not inherit from
`config/launch-config.yml`, which is the mainnet template. The live devnet therefore still reports
the test-only governance timings (`voting_period 5m0s`, `expedited 30s`) and the old 3%/10%
inflation band. That is correct — the 1%-fixed and launch-window governance values apply to the
mainnet template only.

| | |
|---|---|
| `active_static_precompiles` | `[]` |
| measured block time | 1.467 s/block (heights 3262 → 3282) |
| implied `blocks_per_year` | 21,496,932 — devnet only, see below |

### The base fee DECAYS on an idle devnet — this nearly made A6 vacuous

Worth recording because it is a trap for anyone re-running this, and because the brief warns about
exactly this condition without saying it is a moving target.

The feemarket base fee was measured **twice, on the same chain, hours apart**:

```
shortly after the regression's load : base_fee = 290062.265300966464318379 aqdn
after ~3000 idle blocks             : base_fee = 0.000000000000000007      aqdn
```

That is EIP-1559 behaving correctly — the base fee decays while blocks are under-full — but it
means `$minimum_gas_prices`, which `scripts/setup_env.sh` derives as
`max(min_gas_price, base_fee) × 1.1 + 1`, had fallen to **1.000000000000000007 aqdn/gas** by the
time the suite ran. At that price a broken feegrant is indistinguishable from a working one,
because the fee rounds to nothing.

**A6 therefore forces its own gas price** of `500000000aqdn` — the node's own configured
`minimum-gas-prices` from `config/config.yml`, so it is a price this chain is actually built to
charge rather than an arbitrary large number. The verdict then rests on the **sponsor's real
balance delta**, not on any parameter being nominally non-zero.

Do not read a passing A6 on a quiet devnet as evidence of anything unless the gas price was
forced. The brief's instruction to "set min-gas-price" is load-bearing.

### Block time

1.467 s/block on a single-validator devnet, which is bound by `timeout_commit` (1.5s) and has no
consensus round-trip. It is a floor, **not a mainnet prediction** — `config/launch-config.yml`
keeps its own 3s mainnet target and its own `blocks_per_year`, and the two must not be conflated.

### Contract artifacts

Fetched and checksum-verified against the publishers' own `checksums.txt` by
`testscripts/fetch_token_contracts.sh`:

```
8047bc30ed7129f24d4a89e7527c4926d3363a6ba038830a592a2041301553cf  cw3_flex_multisig.wasm
4604a284e209c2fe320f223b9fd29805a0e8f2cf8ea7b01fac28c3efc4ee63f0  cw4_group.wasm
16c7bde25eddf6860a232378efee3f92ae86d476d1aca0fdb3c3f70dd74c0adb  cw_vesting-staking.wasm
6277d16901ccae44b75edbdea7f96552d993eb461072fea3eb33ab11c9a9044a  cw_vesting-no_staking.wasm
```

| contract | source | version | audit |
|---|---|---|---|
| cw3-flex-multisig | CosmWasm/cw-plus | v2.0.0 | **UNAUDITED** |
| cw4-group | CosmWasm/cw-plus | v2.0.0 | **UNAUDITED** |
| cw-vesting | DA0-DA0/dao-contracts | v2.7.1 | Audited (Oak Security, multiple) |

cw-plus states it plainly: *"None of these contracts have been audited, and NO LIABILITY is assumed
for the use of this code."*

**Note the asymmetry before relying on it.** The audited contract holds the vesting schedules; the
unaudited pair is what actually custodies and moves all 4,000,000,000 QDN. This compounds Phase C
step 5 — an unaudited contract whose migrate admin can swap its code is the reserve-drain path the
brief already flags.

### wasmd feature flags

`wasmkeeper.BuiltInCapabilities()` (`app/non_dependency_inject.go`) returns
`iterator, staking, stargate, cosmwasm_1_1 … cosmwasm_2_2`. Every capability the four artifacts
declare is present:

```
cw3_flex_multisig.wasm       requires_iterator
cw4_group.wasm               requires_iterator
cw_vesting-no_staking.wasm   requires_cosmwasm_1_1 requires_cosmwasm_1_2 requires_iterator requires_stargate
cw_vesting-staking.wasm      requires_cosmwasm_1_1 requires_cosmwasm_1_2 requires_iterator requires_staking requires_stargate
```

### cw-vesting ships in two builds, and the choice is load-bearing

`cw-vesting` is **not** in cw-plus. It is a DAO DAO contract, and it ships as two artifacts
differing by exactly one capability: `cw_vesting-staking` declares `requires_staking`,
`cw_vesting-no_staking` does not.

The brief says only "cw-vesting". That is not specific enough to deploy from:

- **Foundation Treasury (504M locked)** must use **`-staking`**. The design delegates this tranche
  to consortium validators while locked, and the entire 1% inflation rationale is computed against
  ~504M of bonded stake. Deploy `-no_staking` here and the 504M can never be bonded — bonded stake
  at launch collapses to roughly the genesis validator's 1,000 QDN self-bond, staker APR becomes
  nonsense, and chain security with it.
- **Long-Term Reserve (600M)** should use **`-no_staking`**. `allocations.csv` marks it
  `stakes: no`, so the smaller surface is correct.

## CSV arithmetic

`allocations.csv` satisfies brief assertions 1–4 as delivered:

```
rows: 11 | distinct buckets: 10 | pct sum: 100
total tokens_qdn: 4,000,000,000  == 4e9
total aqdn: 4000000000000000000000000000
per bucket: row sum == 4_000_000_000 * pct // 100   -- all OK
```

`bucket_id` 08 and 11 are intentionally absent. Ten buckets, not twelve.

---

## 12. Traps this chain sets for a test harness

Eight harness bugs were found while getting these eight verdicts. Recorded because **every one
produced plausible-but-wrong output rather than an obvious failure** — which is the dangerous kind,
and the next person writing against this chain will meet the same ones.

| trap | how it lies to you |
|---|---|
| **The legacy amino account shape.** `query auth account` answers with `.account.type` and nests the payload under `.account.value`, not the proto `.account."@type"` | Cost two false FAILs (A2, A4 reported failures on transactions that had *succeeded*) and later a false NOT-EXERCISED, when a null account-number made `tx sign` write nothing |
| **`2>&1` on any `--gas auto` command.** The CLI writes `gas estimate: N` to stderr; folding it into stdout makes `jq` fail, and under `set -e` the suite dies **silently mid-run**, losing verdicts already gathered | Documented in `test_bank_restriction.sh`'s header — and it still bit this file. Use `2>/dev/null` |
| **`--generate-only` with `--gas auto`.** Auto needs a simulation, which needs a signer; for a multisig there is none yet | The CLI writes *nothing* and exits cleanly. Reads as "no tx to sign". Use an explicit `--gas` |
| **`status` is read-only in zsh** (it mirrors `$?`) | `local ... status` aborts the function; the caller then spins to its timeout |
| **`setup_env.sh` sets `SCRIPT_DIR` itself** | Sourcing it silently repoints your own `SCRIPT_DIR` at `scripts/`. Use `$qadenatestscripts` |
| **`pgrep -f <script>` matches the waiting shell** | A `until ! pgrep -f foo.sh` loop matches its own command line and never exits. Wait on a captured PID |
| **Discarding stderr on the failure path** | A `BROADCAST_REJECTED` with the reason thrown away is undiagnosable — and CLI-side rejection is exactly where the reason lives |
| **The AML scan is skipped in CheckTx and simulation** | A refused transaction broadcasts cleanly, gets a hash, and fails *inside the block* while the CLI exits 0. **Never trust an exit status here** — read the on-chain result code |

The last one is the chain's own documented convention and the reason `tx_result` exists in the
harness. The rest are avoidable once known.

---

## 13. Follow-up: what 1159 actually is, and whether an all-native design avoids it

### 13.1 Code 1159 is `ErrBankSendNotScannable`, and it is about IDENTITY, not CosmWasm

`x/qadena/types/errors.go:120`:

```go
ErrBankSendNotScannable = sdkerrors.Register(ModuleName, 1159,
    "This transfer cannot be AML-scanned; each party must be a wallet with eKYC data "+
    "or on the scanned-contract whitelist")
```

It is raised in the enclave, `cmd/qadenad_enclave/enclave_scan_bank_send.go`. A2 hit the
**sender-side** branch, whose own comment names the case exactly:

```go
// A sender that is not a qadena wallet at all -- a plain key, an unlisted contract, an EVM
// account -- reports "wallet does not exist" ... Unlike the recipient above, there is no default
// to fall back to: letting an unidentifiable SENDER through under the chain default would make
// "hold no credential" the cheapest way to pick your own threshold.
```

So the rule is: **a sender must be identifiable, or governance-approved.** A native multisig is a
*plain key* — it never ran `create-wallet`, so it is not a qadena wallet and holds no credential —
and `senderJurisdictions` fails with `ErrWalletNotExists`, which becomes 1159.

There is deliberately no fallback threshold for an unknown sender, because that would make holding
no credential the cheapest way to get the most permissive AML limit. This is a designed property,
not a defect.

**A2 involved no CosmWasm whatsoever.** It was a stock Cosmos SDK `keys add --multisig` account.
The name "scanned-**contract** whitelist" is misleading here: the list takes any address, and
treasury — a plain account — is seeded into it at genesis precisely so the chain can be
bootstrapped.

**Therefore 1159 is orthogonal to the native-vs-CosmWasm choice.** Every bucket, either way, must be
whitelisted or be a credentialed wallet. Going native does not avoid it, and adopting contracts does
not cause it.

### 13.2 No cw-plus release would have worked

Checked rather than assumed. cw-plus has exactly two current releases:

| release | cosmwasm-std pin | features |
|---|---|---|
| v2.0.0 (Mar 2024, newest) | `"2.0.0"` | **none** |
| v1.1.2 | `{ version = "1.4.0" }` | **none** |

Neither enables `staking` or `stargate`/`cosmwasm_2_0`. A1 and A3 were **not** caused by picking the
wrong version — no published cw-plus artifact can emit those messages.

### 13.3 DAO DAO's contracts DO carry stargate — correcting §3's remediation

§3 said the remediation was a custom build. That was too narrow. DAO DAO publishes audited
contracts built **with** the feature:

```
dao_proposal_single.wasm   requires_cosmwasm_1_1 requires_cosmwasm_1_2 requires_iterator requires_stargate
dao_voting_cw4.wasm        requires_cosmwasm_1_1 requires_cosmwasm_1_2 requires_iterator requires_stargate
cw_admin_factory.wasm      requires_cosmwasm_1_1 requires_cosmwasm_1_2 requires_iterator requires_stargate
cw_vesting-staking.wasm    ... requires_staking requires_stargate
```

So **A1 is solvable off the shelf** by using `dao-proposal-single` + `dao-voting-cw4` instead of
cw3-flex/cw4-group — audited by Oak Security, no custom build.

Note what is still missing: `dao_proposal_single` declares `requires_stargate` but **not**
`requires_staking`, so a DAO-DAO-governed bucket still could not emit `StakingMsg::Delegate`
directly. Only `cw_vesting-staking` carries staking.

### 13.4 A native multisig CAN stake — tested

The question A3 really asks is whether bucket funds can be bonded. Tested directly on the same
native 2-of-3 multisig used in A2, which is a `PeriodicVestingAccount`:

```
tx staking delegate 1000000000000000000000aqdn, 2-of-3 signed
-> code 0, height 7433
   query staking delegations -> delegated: 1000000000000000000000 aqdn
```

**Locked principal, held by a native multisig, delegated successfully.** Staking has no feature
gates and module-account transfers are exempt from the AML scan, so the whole A3 problem disappears
in a native design.

### 13.5 Where an all-native design stands

| capability | native | evidence |
|---|---|---|
| n-of-m threshold custody | yes | A2 — signatures produced and accepted |
| receive a vesting grant | yes | A2, A4 |
| spend, once whitelisted | yes | height 3732, code 0 |
| **delegate locked principal** | **yes** | §13.4, height 7433 |
| enforce a vesting schedule | yes | `x/auth/vesting`; locks hold vs the EVM (`evm-vesting-handoff.md`) |
| pay fees for others | yes | A6 |

What is genuinely lost without cw3:

1. **No on-chain proposal record.** cw3 records who proposed, who voted, and when it expires. Native
   multisig signature collection happens **off chain** — the chain sees only a finished transaction.
   For a foundation-controlled treasury that must be publicly accountable, that is a real
   transparency loss.
2. **Membership changes move the address.** A native multisig address is derived from its pubkey set
   and threshold, so changing a signer or a threshold **produces a different address** — every
   affected bucket must be transferred to the new one, re-whitelisted, and will emit an AML report.
   cw3+cw4 `update_members` keeps the same address. The brief's Phase C step 10 plans exactly such a
   reseating, so this is on the roadmap, not hypothetical.
3. Weighted votes and executor restrictions have no native equivalent.

Neither loss is fatal, and both are governance-process questions rather than capability gaps.
**This is a design decision for the human**, but the technical blockers that made CosmWasm look
mandatory (A1, A3) do not exist in a native design, and the one that looked like a CosmWasm problem
(A2/1159) is not one.

---

## 14. x/group — works, but is LICENCE-BLOCKED for production

> **Read this header before the results below.** Everything in this section is a valid measurement
> of what the chain can do, and `x/group` is **not usable for mainnet custody**. In Cosmos SDK
> **v0.54.0 it moved to `enterprise/`** under a **Source Available Evaluation License** —
> evaluation, testing and education only; production requires a paid Cosmos Enterprise licence. It
> is also out of the SDK Bug Bounty programme.
>
> This chain runs v0.53.5, where `x/group` is still core and Apache-2.0, which is exactly the trap
> `config/launch-config.yml:437` already describes for `x/crisis`: shipping a module you have
> already decided to remove buys you a live-chain migration later — here, of accounts holding
> 4,000,000,000 QDN, some of it locked.
>
> The design therefore uses native multisigs. See `qadena-native-brief.md` §"x/group is EXCLUDED".
> v0.54 moves for the record: **enterprise/** `x/group`, `x/poa`; **contrib/** `x/circuit`, `x/nft`,
> `x/crisis`. `x/authz`, `x/feegrant`, `x/auth`, `x/bank`, `x/staking`, `x/gov`, `x/distribution`
> remain core.

### What was measured anyway

§13.5 claimed an all-native design loses on-chain proposal records and address-stable membership.
**Both claims were wrong.** `x/group` is wired into this app (`app/app_config.go`, `GroupKeeper` in
`app/app.go`) and provides exactly what cw3-flex + cw4-group provide, natively.

| test | result |
|---|---|
| `create-group-with-policy`, 3 members, threshold 2 | policy `qadena1afk9zr2hn2…gej48j`, code 0 |
| whitelist the policy address via `x/gov`, `codeID: 0` | proposal 20 PASSED |
| fund the policy | code 0, 50,000 QDN |
| proposal → 2 votes → `exec`, carrying `MsgSend` **and** `MsgDelegate` | **code 0 @ 7862**; recipient +1,000 QDN; policy delegated 5,000 QDN |
| proposal → `exec` carrying `MsgCreatePeriodicVestingAccount` | **code 0 @ 7882**; recipient is a `PeriodicVestingAccount` |
| `update-group-members`: add carlo, remove treasury (weight 0) | members changed; **policy address byte-identical** |

The last row is the one that matters: **membership changed without the address changing**, so no
fund transfer, no re-whitelisting, no AML report. cw3 cannot even change its *threshold* after
instantiate; `x/group` can (`update-group-policy-decision-policy`).

So the A1 and A3 failures are **not** properties of this chain. They are properties of the cw-plus
artifacts — the same operations succeed through core-SDK message types. That conclusion survives the
licence problem: it is the *module wrapper* that is unusable, not the underlying capability, and the
native-multisig design in `qadena-native-brief.md` reaches the same operations without it.

### The one hard limit

A group policy **cannot hold a chain-enforced vesting lock**:

```
account qadena1dlszg2sst9r69my4f84l3mj66zxcf3umcgujys30t84srg95dgvs6y40lr already exists:
invalid request [cosmos/cosmos-sdk@v0.53.5/x/auth/vesting/msg_server.go:192]
```

`MsgCreatePeriodicVestingAccount` refuses any address that already has an account, and a policy
account exists from the moment the policy is created. A lock must therefore be created at a
**fresh** address — which can be a native multisig (A2), giving threshold custody plus a real lock,
at the cost of frozen membership for the schedule's duration.

That trade-off is the subject of `qadena-native-brief.md`.

---

## 15. Native custody follow-ups (N1–N6) — all core-SDK, all passing

Harness: `testscripts/test_native_custody.sh`. Evidence: `logs/native-custody/`. Run 1787846034 on
`qadena_4828-1`. **5 PASS, 1 NOT-EXERCISED, 0 failures.**

The subject is a 2-of-3 native multisig holding a `PeriodicVestingAccount` whose second period —
8,000 QDN — is **genuinely still locked** for a year. That matters: an earlier account used a
backdated single period that had already fully elapsed, so its "delegation of locked principal" was
really a delegation of free tokens (`delegated_free` set, `delegated_vesting` empty). Every
assertion below reads `delegated_vesting`, or the locked balance, rather than trusting a total.

| # | Question | Verdict |
|---|---|---|
| N1 | Can a multisig delegate genuinely LOCKED principal? | **PASS** |
| N2 | Are rewards on locked stake liquid, and can the multisig take them? | **PASS** |
| N3 | Does undelegate return the principal LOCKED? | **PASS** |
| N4 | Can the multisig THRESHOLD sign an authz `MsgGrant`? | **PASS** |
| N5 | Can a `StakeAuthorization` holder delegate but not spend? | **PASS** |
| N6 | Can a multisig hold an eKYC credential? | **NOT-EXERCISED** (first verdict retracted — see below) |

### N1 — locked principal, delegated from a multisig

`delegated_vesting = 8000000000000000000000`, `delegated_free = 0`. The zero on the second field is
the proof: the bonded tokens came from the locked tranche, not from anything already vested. This is
the mechanism the foundation's 504M delegation programme and the entire 1% inflation rationale rest
on, and it now has direct evidence on a *multisig* rather than a single-key account.

### N2 — a locked bucket earns liquid income

Rewards accrued on locked stake, were withdrawn by the multisig, and landed **immediately
spendable** (spendable rose ~199.9999 → ~200.0929 QDN). So a bucket that is provably locked still
produces a liquid income stream throughout its own lock. Expected under vanilla vesting; it should
be **disclosed on purpose** rather than discovered, since it is exactly the sort of thing a
"fully locked" claim in public materials would contradict.

### N3 — the follow-up the prior report called its most valuable, now closed

`evm-vesting-handoff.md` §6.4: *"whether unbonding returns those tokens as locked was not verified …
the one remaining path by which locked principal could plausibly become spendable early."*

Tested by shortening the devnet's `unbonding_time` from 504h to 120s by governance (proposal 21,
PASSED) so the unbonding could actually complete:

```
delegated_vesting  8000000000000000000000 -> 0        (bond released)
locked after       8000000000000000000000 aqdn        (the whole un-elapsed tranche)
```

**Unbonding returns the principal still locked.** delegate → undelegate → spend does **not** unwind
a vesting lock. The design's ~700M QDN of intended locks are real against this path too.

> **A false alarm worth recording.** The first version of this test asserted on the *spendable
> delta* across the unbonding wait, saw it rise by 2,000 QDN, and reported that every lock in the
> design was breakable. It was wrong: the 60-second first period vested naturally during the
> 2-minute wait. Scheduled vesting elapses while you test, so **assert on what remains LOCKED, never
> on a spendable delta.** Verified independently against the account before reporting.

### N4 — threshold-signed authz grant

The multisig's 2-of-3 signed a `MsgGrant`, and a brand-new operator key — no eKYC, no whitelist
entry of its own — then spent 100 QDN **out of the multisig**. So operator authority can be added
and revoked without changing the custody address or its whitelist entry, while the n-of-m still
governs who may grant. This is the mechanism the brief's membership answer (Q2 mechanism 2) rests
on, now proven from a multisig granter rather than only a single key.

### N5 — a delegation manager with no spending power

A `StakeAuthorization` holder delegated on the granter's behalf (code 0) and could **not** move
funds. The foundation's validator programme can therefore be run day-to-day by a key that cannot
touch the principal — the role separation a 504M delegated tranche needs.

### N6 — CORRECTED: not settled, and the first verdict was worthless

**The originally reported "CONFIRMED-NO" was invalid.** The test called `create-wallet` with one
argument and got `accepts 3 arg(s), received 1` — a CLI usage error that never reached the chain. A
verdict was published off an argument-count mistake. Recorded here because the failure mode is
instructive: an expected-negative result is the easiest kind to accept without checking.

What the code actually says (`x/qadena/client/cli/tx_create_wallet.go`):

`create-wallet` does not attach a credential to an account you name. It **mints** one:

1. generates (or accepts) a BIP39 mnemonic;
2. `CreatePublicKey()` derives the **transaction** key from it, and a second call derives the
   **credential** key from the *same* mnemonic at a different HD index — `config/config.yml` states
   this too: *"create-wallet derives BOTH the transaction key (account index 0) and the
   `<name>-credential` key (index 1 …) from the one provider mnemonic"*;
3. it then **overrides the signer** — `ctx.WithFrom(from).WithFromAddress(fromAddr)` — so whatever
   `--from` you passed is discarded and the transaction is signed by the newly derived key.

And `msg_server_create_wallet.go` sets `walletID := msg.Creator`, the Creator being that fresh key.

So through the CLI the wallet address is **necessarily** the mnemonic-derived address, and a
multisig address is derived from a pubkey set plus threshold — no mnemonic produces it. Confirmed by
attempting it: the command panicked inside its sponsor-feegrant step rather than producing anything
targeting the multisig.

**What is genuinely unsettled.** `walletID := msg.Creator` is just the signer, so a *hand-crafted*
`MsgCreateWallet` signed by a multisig is not obviously refused by the message server. Constructing
one means reproducing the pubK/pubKID material and sponsor feegrant the CLI assembles; that was not
attempted. **Status: NOT-EXERCISED, not "impossible".**

**A separate obstacle that may be decisive before the technical one.** An eKYC credential encodes a
*person's* residency and citizenship — that is precisely what the AML scan decrypts to select a
jurisdiction threshold (`senderJurisdictions`). Attaching one to an n-of-m account asserts that a
group has a nationality, and a report naming that party names no one. So even a successful technical
registration may be the wrong thing to want.

**Consequence for the design: unchanged, but for a better-stated reason.** Plan on threshold custody
requiring a governance whitelist entry to spend. Not because it is proven impossible otherwise, but
because the supported path does not offer it and the alternative is semantically doubtful. If
someone wants to overturn this, the experiment is a hand-built `MsgCreateWallet` — worth doing
before the consortium agreement fixes founder custody terms.

### A new hard constraint, found by a failing test

The first N1 run produced **no delegation at all**, silently. The account was fully locked, so
`spendable = 0`, and it could not pay the gas to submit its own delegation. Delegating locked
principal is permitted; *paying for the transaction* is not.

**Consequence:** the foundation's locked 504M cannot join the delegation programme, and no locked
founder multisig can stake during its cliff, without either a liquid gas float or a standing
feegrant. Phase C step 4 of the original brief says "delegate the locked 504M" with no mention of
how that account pays for it. Coins sent from outside are not part of `original_vesting`, so they
land fully spendable — which is why the gas float must arrive **after** the grant, and why it must
arrive at all.
